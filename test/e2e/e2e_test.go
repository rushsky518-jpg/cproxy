package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cproxy/internal/agent"
	"cproxy/internal/cert"
	"cproxy/internal/config"
	"cproxy/internal/server"
)

const testToken = "test-token-9f8e7d6c5b4a3210"

// backend records what the web application actually received.
type backend struct {
	mu    sync.Mutex
	last  backendRequest
	calls int
}

type backendRequest struct {
	Method string
	Path   string
	Query  string
	Host   string
	Prefix string
	Proto  string
	FwdFor string
}

func newBackend(t *testing.T) (*backend, *httptest.Server) {
	t.Helper()
	b := &backend{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.last = backendRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Host:   r.Host,
			Prefix: r.Header.Get("X-Forwarded-Prefix"),
			Proto:  r.Header.Get("X-Forwarded-Proto"),
			FwdFor: r.Header.Get("X-Forwarded-For"),
		}
		b.calls++
		b.mu.Unlock()
		w.Header().Set("X-Backend", "fake")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello from backend")
	}))
	t.Cleanup(srv.Close)
	return b, srv
}

func (b *backend) snapshot() backendRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

type runningServer struct {
	srv      *server.Server
	addr     string
	certFile string
	keyFile  string
	stop     func()
}

func startServer(t *testing.T, token string, tlsOn bool) *runningServer {
	t.Helper()
	dir := t.TempDir()
	rs := &runningServer{
		certFile: filepath.Join(dir, "tunnel.crt"),
		keyFile:  filepath.Join(dir, "tunnel.key"),
	}
	cfgPath := filepath.Join(dir, "server.json")
	cfg := map[string]any{
		"public_listen": "127.0.0.1:0",
		"admin_listen":  "127.0.0.1:0",
		"token":         token,
		"log_level":     "error",
		"log_format":    "text",
		"tunnel_tls": map[string]any{
			"enabled":       tlsOn,
			"cert_file":     rs.certFile,
			"key_file":      rs.keyFile,
			"auto_generate": true,
			"public_host":   "127.0.0.1",
		},
	}
	writeJSON(t, cfgPath, cfg)
	loaded, err := config.LoadServer(cfgPath)
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	srv, err := server.New(loaded, discardLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("server did not become ready")
	}
	rs.srv = srv
	rs.addr = srv.Addr()
	var once sync.Once
	rs.stop = func() {
		once.Do(cancel)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("server did not stop")
		}
	}
	t.Cleanup(rs.stop)
	return rs
}

// fingerprint returns the SHA-256 pin of the server's self-signed certificate.
func (rs *runningServer) fingerprint(t *testing.T) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(rs.certFile, rs.keyFile)
	if err != nil {
		t.Fatalf("load generated tunnel certificate: %v", err)
	}
	return cert.Fingerprint(pair)
}

func startAgent(t *testing.T, rs *runningServer, token, target, prefix string, strip bool) func() {
	t.Helper()
	return startAgentOpts(t, rs, token, target, prefix, strip, false)
}

func startAgentOpts(t *testing.T, rs *runningServer, token, target, prefix string, strip, tlsOff bool) func() {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	tunnel := map[string]any{"enabled": false}
	if !tlsOff {
		tunnel = map[string]any{"fingerprint": rs.fingerprint(t)}
	}
	cfg := map[string]any{
		"server":     rs.addr,
		"agent_id":   "test-agent",
		"token":      token,
		"ui_listen":  "off",
		"log_level":  "error",
		"log_format": "text",
		"tunnel_tls": tunnel,
		"services": []map[string]any{{
			"name":         "web",
			"path_prefix":  prefix,
			"target":       target,
			"strip_prefix": strip,
		}},
	}
	writeJSON(t, cfgPath, cfg)
	return runAgent(t, cfgPath)
}

// runAgent loads cfgPath, starts the agent, and returns an idempotent stop.
func runAgent(t *testing.T, cfgPath string) func() {
	t.Helper()
	loaded, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatalf("load agent config: %v", err)
	}
	ag, err := agent.New(loaded, cfgPath, discardLogger())
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = ag.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop := func() {
		once.Do(cancel)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

// agentHandle is an agent with its local UI enabled.
type agentHandle struct {
	stop    func()
	uiURL   string
	cfgPath string
	agent   *agent.Agent
}

func startAgentWithUI(t *testing.T, rs *runningServer, token string, services []map[string]any) *agentHandle {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	cfg := map[string]any{
		"server":     rs.addr,
		"agent_id":   "test-agent",
		"token":      token,
		"ui_listen":  "127.0.0.1:0",
		"log_level":  "error",
		"log_format": "text",
		"tunnel_tls": map[string]any{"fingerprint": rs.fingerprint(t)},
		"services":   services,
	}
	writeJSON(t, cfgPath, cfg)

	loaded, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatalf("load agent config: %v", err)
	}
	ag, err := agent.New(loaded, cfgPath, discardLogger())
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = ag.Run(ctx)
		close(done)
	}()
	select {
	case <-ag.UIReady():
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("agent UI did not start")
	}
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	}
	t.Cleanup(stop)
	return &agentHandle{
		stop:    stop,
		uiURL:   "http://" + ag.UIAddr(),
		cfgPath: cfgPath,
		agent:   ag,
	}
}

// uiPutServices applies a routing table through the agent UI.
func uiPutServices(t *testing.T, uiURL string, services []map[string]any) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatalf("marshal services: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, uiURL+"/api/services", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("PUT services: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return resp.StatusCode, out
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func waitForStatus(t *testing.T, url string, want ...int) *http.Response {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(url)
		if err == nil {
			last = resp.StatusCode
			for _, w := range want {
				if resp.StatusCode == w {
					return resp
				}
			}
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("GET %s never reached %v (last status %d)", url, want, last)
	return nil
}

func TestBasePathRouting(t *testing.T) {
	b, backendSrv := newBackend(t)
	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, backendSrv.Listener.Addr().String(), "/higobase-admin", false)

	base := "http://" + rs.addr
	resp := waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)
	resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got == "" {
		t.Error("X-Request-ID is missing from the public response")
	}

	resp, body := get(t, base+"/higobase-admin/higobase/ajax/list?page=2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "hello from backend" {
		t.Errorf("body = %q", body)
	}
	got := b.snapshot()
	if got.Path != "/higobase-admin/higobase/ajax/list" {
		t.Errorf("backend path = %q, want the prefix preserved", got.Path)
	}
	if got.Query != "page=2" {
		t.Errorf("backend query = %q", got.Query)
	}
	if got.Prefix != "/higobase-admin" {
		t.Errorf("X-Forwarded-Prefix = %q", got.Prefix)
	}
	if got.Proto != "http" {
		t.Errorf("X-Forwarded-Proto = %q", got.Proto)
	}
	if got.FwdFor == "" {
		t.Error("X-Forwarded-For is missing")
	}
	if got.Host != rs.addr {
		t.Errorf("backend Host = %q, want %q", got.Host, rs.addr)
	}

	if resp, _ := get(t, base+"/higobase-admin"); resp.StatusCode != http.StatusOK {
		t.Errorf("bare prefix status = %d, want 200 in base-path mode", resp.StatusCode)
	}
	if resp, _ := get(t, base+"/not-registered"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", resp.StatusCode)
	}
	if resp, _ := get(t, base+"/higobase-adminx"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("path boundary status = %d, want 404", resp.StatusCode)
	}
	if resp, _ := get(t, base+"/_cproxy/tunnel"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("reserved path status = %d, want 404", resp.StatusCode)
	}
	if resp, _ := get(t, base+"/_cproxy/status"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("reserved path status = %d, want 404", resp.StatusCode)
	}
}

func TestStripPrefixAndRedirect(t *testing.T) {
	b, backendSrv := newBackend(t)
	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, backendSrv.Listener.Addr().String(), "/api", true)

	base := "http://" + rs.addr
	waitForStatus(t, base+"/api/ping", http.StatusOK)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(base + "/api")
	if err != nil {
		t.Fatalf("GET /api: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("GET /api status = %d, want 308", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/api/" {
		t.Errorf("Location = %q, want /api/", loc)
	}

	resp, _ = get(t, base+"/api/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := b.snapshot().Path; got != "/users" {
		t.Errorf("backend path = %q, want /users after stripping", got)
	}
}

func TestAgentDisconnectReturns503AndRecovers(t *testing.T) {
	_, backendSrv := newBackend(t)
	rs := startServer(t, testToken, true)
	stopAgent := startAgent(t, rs, testToken, backendSrv.Listener.Addr().String(), "/higobase-admin", false)

	base := "http://" + rs.addr
	waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)

	stopAgent()
	resp := waitForStatus(t, base+"/higobase-admin/health", http.StatusServiceUnavailable)
	resp.Body.Close()

	startAgent(t, rs, testToken, backendSrv.Listener.Addr().String(), "/higobase-admin", false)
	waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)
}

func TestAdminEndpoints(t *testing.T) {
	_, backendSrv := newBackend(t)
	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, backendSrv.Listener.Addr().String(), "/higobase-admin", false)
	waitForStatus(t, "http://"+rs.addr+"/higobase-admin/health", http.StatusOK)

	admin := "http://" + rs.srv.AdminAddr()
	resp, body := get(t, admin+"/healthz")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "\"ok\"") {
		t.Fatalf("healthz = %d %q", resp.StatusCode, body)
	}

	resp, body = get(t, admin+"/status")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var st struct {
		Services []struct {
			Name       string `json:"name"`
			PathPrefix string `json:"path_prefix"`
			Online     bool   `json:"online"`
			Requests   int64  `json:"requests"`
		} `json:"services"`
		Agents    int  `json:"agents"`
		TunnelTLS bool `json:"tunnel_tls"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v\n%s", err, body)
	}
	if len(st.Services) != 1 || st.Services[0].PathPrefix != "/higobase-admin" || !st.Services[0].Online {
		t.Fatalf("unexpected services: %s", body)
	}
	if st.Agents != 1 || !st.TunnelTLS {
		t.Fatalf("unexpected agent count or TLS flag: %s", body)
	}
}

// startAgentWithConfig writes an agent config with arbitrary services.
func startAgentWithConfig(t *testing.T, rs *runningServer, tlsOff bool, services []map[string]any) func() {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	tunnel := map[string]any{"enabled": false}
	if !tlsOff {
		tunnel = map[string]any{"fingerprint": rs.fingerprint(t)}
	}
	cfg := map[string]any{
		"server":     rs.addr,
		"agent_id":   "test-agent",
		"token":      testToken,
		"ui_listen":  "off",
		"log_level":  "error",
		"log_format": "text",
		"tunnel_tls": tunnel,
		"services":   services,
	}
	writeJSON(t, cfgPath, cfg)
	return runAgent(t, cfgPath)
}

func TestTwoServicesRouteIndependently(t *testing.T) {
	b1, srv1 := newBackend(t)
	b2, srv2 := newBackend(t)
	rs := startServer(t, testToken, true)
	startAgentWithConfig(t, rs, false, []map[string]any{
		{"name": "higobase", "path_prefix": "/higobase-admin", "target": srv1.Listener.Addr().String()},
		{"name": "other", "path_prefix": "/other", "target": srv2.Listener.Addr().String()},
	})

	base := "http://" + rs.addr
	waitForStatus(t, base+"/other/health", http.StatusOK)
	resp, _ := get(t, base+"/higobase-admin/a")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first service status = %d", resp.StatusCode)
	}
	if got := b1.snapshot().Path; got != "/higobase-admin/a" {
		t.Errorf("first backend path = %q", got)
	}
	resp, _ = get(t, base+"/other/b")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second service status = %d", resp.StatusCode)
	}
	if got := b2.snapshot().Path; got != "/other/b" {
		t.Errorf("second backend path = %q", got)
	}
	if b2.snapshot().Prefix != "/other" {
		t.Errorf("second backend prefix = %q", b2.snapshot().Prefix)
	}
}

// TestPlainTunnel mode skips TLS on the tunnel and serves it from the same
// plain HTTP listener.
func TestPlainTunnel(t *testing.T) {
	_, backendSrv := newBackend(t)
	rs := startServer(t, testToken, false)
	startAgentOpts(t, rs, testToken, backendSrv.Listener.Addr().String(), "/higobase-admin", false, true)

	base := "http://" + rs.addr
	resp := waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from backend" {
		t.Errorf("body = %q", body)
	}
}

func TestLargeBodyAndConcurrency(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Body-Len", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(echo.Close)

	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, echo.Listener.Addr().String(), "/higobase-admin", false)
	base := "http://" + rs.addr
	waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i * 31 % 251)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(base+"/higobase-admin/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	const workers, perWorker = 16, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				r, err := client.Get(base + "/higobase-admin/concurrent")
				if err != nil {
					errs <- err
					return
				}
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				if r.StatusCode != http.StatusOK {
					errs <- fmt.Errorf("worker %d status %d", id, r.StatusCode)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestStreamingResponse(t *testing.T) {
	stream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		for i := 0; i < 5; i++ {
			_, _ = io.WriteString(w, fmt.Sprintf("data: chunk-%d\n\n", i))
			fl.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	t.Cleanup(stream.Close)

	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, stream.Listener.Addr().String(), "/higobase-admin", false)
	base := "http://" + rs.addr
	waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)

	resp, err := http.Get(base + "/higobase-admin/events")
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	for i := 0; i < 5; i++ {
		if !strings.Contains(string(body), fmt.Sprintf("chunk-%d", i)) {
			t.Errorf("stream body is missing chunk-%d: %q", i, body)
		}
	}
}

// TestWebSocketUpgradePassThrough proves that protocol upgrades (used by the
// Vite HMR client) survive the tunnel as a raw byte stream.
func TestWebSocketUpgradePassThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		// Echo the first 4 bytes that arrive after the handshake.
		buf := make([]byte, 4)
		if _, err := io.ReadFull(brw, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}))
	t.Cleanup(upstream.Close)

	rs := startServer(t, testToken, true)
	startAgent(t, rs, testToken, upstream.Listener.Addr().String(), "/higobase-admin", false)
	base := "http://" + rs.addr
	waitForStatus(t, base+"/higobase-admin/", http.StatusOK)

	conn, err := net.Dial("tcp", rs.addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET /higobase-admin/ HTTP/1.1\r\nHost: " + rs.addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Protocol: vite-hmr\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, want 101", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
}

func TestAgentUIEditsRoutes(t *testing.T) {
	_, srv1 := newBackend(t)
	_, srv2 := newBackend(t)
	rs := startServer(t, testToken, true)
	h := startAgentWithUI(t, rs, testToken, []map[string]any{
		{"name": "higobase", "path_prefix": "/higobase-admin", "target": srv1.Listener.Addr().String()},
	})
	base := "http://" + rs.addr
	waitForStatus(t, base+"/higobase-admin/health", http.StatusOK)

	resp, body := get(t, h.uiURL+"/api/state")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state status = %d", resp.StatusCode)
	}
	var st struct {
		Connected bool `json:"connected"`
		Services  []struct {
			Name       string `json:"name"`
			PathPrefix string `json:"path_prefix"`
			PublicURL  string `json:"public_url"`
			OK         bool   `json:"ok"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode state: %v\n%s", err, body)
	}
	if !st.Connected || len(st.Services) != 1 || st.Services[0].PathPrefix != "/higobase-admin" || !st.Services[0].OK {
		t.Fatalf("unexpected state: %s", body)
	}
	if !strings.Contains(st.Services[0].PublicURL, "/higobase-admin/") {
		t.Errorf("public_url = %q", st.Services[0].PublicURL)
	}

	// Add a second route through the UI.
	code, out := uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "higobase", "path_prefix": "/higobase-admin", "target": srv1.Listener.Addr().String()},
		{"name": "extra", "path_prefix": "/extra", "target": srv2.Listener.Addr().String()},
	})
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("add route: %d %v", code, out)
	}
	resp2 := waitForStatus(t, base+"/extra/health", http.StatusOK)
	resp2.Body.Close()
	if resp, _ := get(t, base+"/higobase-admin/health"); resp.StatusCode != http.StatusOK {
		t.Errorf("original route broke after adding another one: %d", resp.StatusCode)
	}

	// Remove the second route: it must stop routing instead of lingering as 503.
	code, out = uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "higobase", "path_prefix": "/higobase-admin", "target": srv1.Listener.Addr().String()},
	})
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("remove route: %d %v", code, out)
	}
	resp3 := waitForStatus(t, base+"/extra/health", http.StatusNotFound)
	resp3.Body.Close()
	if resp, _ := get(t, base+"/higobase-admin/health"); resp.StatusCode != http.StatusOK {
		t.Errorf("remaining route broke after delete: %d", resp.StatusCode)
	}

	// The change must be written back to the config file.
	raw, err := os.ReadFile(h.cfgPath)
	if err != nil {
		t.Fatalf("read persisted config: %v", err)
	}
	var persisted config.Agent
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode persisted config: %v", err)
	}
	if len(persisted.Services) != 1 || persisted.Services[0].Name != "higobase" {
		t.Fatalf("persisted services = %+v", persisted.Services)
	}
	if persisted.Token != testToken {
		t.Errorf("persisted token changed: %q", persisted.Token)
	}
}

// newTextBackend serves a fixed body so tests can tell two targets apart.
func newTextBackend(t *testing.T, text string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAgentUIRetargetsImmediately(t *testing.T) {
	srvA := newTextBackend(t, "BACKEND-A")
	srvB := newTextBackend(t, "BACKEND-B")
	rs := startServer(t, testToken, true)
	h := startAgentWithUI(t, rs, testToken, []map[string]any{
		{"name": "web", "path_prefix": "/web", "target": srvA.Listener.Addr().String()},
	})
	base := "http://" + rs.addr
	waitForStatus(t, base+"/web/", http.StatusOK)

	if _, body := get(t, base+"/web/"); body != "BACKEND-A" {
		t.Fatalf("initial body = %q", body)
	}

	code, out := uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "web", "path_prefix": "/web", "target": srvB.Listener.Addr().String()},
	})
	if code != http.StatusOK {
		t.Fatalf("retarget: %d %v", code, out)
	}

	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		_, body = get(t, base+"/web/")
		if body == "BACKEND-B" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("target change did not take effect, last body = %q", body)
}

func TestAgentUIRejectsBadRoutes(t *testing.T) {
	_, srv1 := newBackend(t)
	rs := startServer(t, testToken, true)
	h := startAgentWithUI(t, rs, testToken, []map[string]any{
		{"name": "web", "path_prefix": "/web", "target": srv1.Listener.Addr().String()},
	})
	base := "http://" + rs.addr
	waitForStatus(t, base+"/web/health", http.StatusOK)

	code, out := uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "a", "path_prefix": "/a", "target": srv1.Listener.Addr().String()},
		{"name": "b", "path_prefix": "/a/b", "target": srv1.Listener.Addr().String()},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("overlapping prefixes: code = %d, want 400 (%v)", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "overlap") {
		t.Errorf("error = %q, want an overlap message", msg)
	}
	// The previous routing table must still be in effect.
	if resp, _ := get(t, base+"/web/health"); resp.StatusCode != http.StatusOK {
		t.Errorf("route changed after a rejected update: %d", resp.StatusCode)
	}

	code, out = uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "../etc", "path_prefix": "/ok", "target": srv1.Listener.Addr().String()},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("bad service name: code = %d, want 400 (%v)", code, out)
	}

	code, out = uiPutServices(t, h.uiURL, []map[string]any{
		{"name": "reserved", "path_prefix": "/_cproxy", "target": srv1.Listener.Addr().String()},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("reserved prefix: code = %d, want 400 (%v)", code, out)
	}
}

func TestAgentUIRejectsCrossOriginWrites(t *testing.T) {
	_, srv1 := newBackend(t)
	rs := startServer(t, testToken, true)
	h := startAgentWithUI(t, rs, testToken, []map[string]any{
		{"name": "web", "path_prefix": "/web", "target": srv1.Listener.Addr().String()},
	})
	waitForStatus(t, "http://"+rs.addr+"/web/health", http.StatusOK)

	body, _ := json.Marshal(map[string]any{"services": []map[string]any{{"name": "x", "path_prefix": "/x", "target": srv1.Listener.Addr().String()}}})
	req, err := http.NewRequest(http.MethodPut, h.uiURL+"/api/services", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAgentUIIndexServed(t *testing.T) {
	_, srv1 := newBackend(t)
	rs := startServer(t, testToken, true)
	h := startAgentWithUI(t, rs, testToken, []map[string]any{
		{"name": "web", "path_prefix": "/web", "target": srv1.Listener.Addr().String()},
	})
	resp, body := get(t, h.uiURL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index status = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "本地路由编辑") || !strings.Contains(body, "/api/services") {
		t.Fatalf("unexpected index page")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestBadTokenIsRejected(t *testing.T) {
	rs := startServer(t, testToken, true)
	line := rawTunnelRequest(t, rs.addr,
		"GET /_cproxy/tunnel HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: cproxy/1\r\n"+
			"X-Cproxy-Mode: control\r\nX-Cproxy-Token: wrong-token-0000000000\r\n\r\n")
	if !strings.Contains(line, "401") {
		t.Fatalf("status line = %q, want 401", line)
	}
}

func TestDataTunnelRequiresSessionToken(t *testing.T) {
	rs := startServer(t, testToken, true)
	line := rawTunnelRequest(t, rs.addr,
		"GET /_cproxy/tunnel HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: cproxy/1\r\n"+
			"X-Cproxy-Mode: data\r\nX-Cproxy-Session: deadbeef\r\nX-Cproxy-Session-Token: nope\r\n"+
			"X-Cproxy-Conn: deadbeef\r\n\r\n")
	if !strings.Contains(line, "401") {
		t.Fatalf("status line = %q, want 401", line)
	}
}

func rawTunnelRequest(t *testing.T, addr, req string) string {
	t.Helper()
	// Tunnel traffic is TLS in these tests; the generated certificate is self-signed.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(conn)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return line
}

func readLine(r io.Reader) (string, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for len(buf) < 1024 {
		n, err := r.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if one[0] == '\n' {
				return string(buf), nil
			}
		}
		if err != nil {
			return string(buf), fmt.Errorf("read line: %w", err)
		}
	}
	return string(buf), nil
}

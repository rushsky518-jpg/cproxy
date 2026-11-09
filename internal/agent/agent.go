// Package agent implements the a-side tunnel client and its local editor UI.
package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cproxy/internal/bridge"
	"cproxy/internal/cert"
	"cproxy/internal/config"
	"cproxy/internal/netutil"
	"cproxy/internal/pathutil"
	"cproxy/internal/protocol"
)

const (
	dialTimeout       = 5 * time.Second
	handshakeTimeout  = 10 * time.Second
	pingInterval      = 15 * time.Second
	controlReadIdle   = 60 * time.Second
	registerTimeout   = 15 * time.Second
	maxDataConns      = 256
	reconnectMinDelay = time.Second
	reconnectMaxDelay = 30 * time.Second
)

// Agent maintains one control session with the public server.
type Agent struct {
	cfg     *config.Agent
	cfgPath string
	log     *slog.Logger
	tlsConf *tls.Config
	sem     chan struct{}

	mu       sync.Mutex
	services []config.Service
	sess     *controlSession
	statuses map[string]protocol.ServiceStatus
	lastErr  string

	uiAddr   string
	uiReady  chan struct{}
	uiServer *http.Server
}

// New prepares TLS verification and the service lookup table.
func New(cfg *config.Agent, cfgPath string, logger *slog.Logger) (*Agent, error) {
	a := &Agent{
		cfg:      cfg,
		cfgPath:  cfgPath,
		log:      logger,
		services: append([]config.Service(nil), cfg.Services...),
		statuses: make(map[string]protocol.ServiceStatus, len(cfg.Services)),
		sem:      make(chan struct{}, maxDataConns),
		uiReady:  make(chan struct{}),
	}
	for _, svc := range cfg.Services {
		a.statuses[svc.Name] = protocol.ServiceStatus{Name: svc.Name, PathPrefix: svc.PathPrefix, OK: true}
	}
	if cfg.TunnelTLS.IsEnabled() {
		tc, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		a.tlsConf = tc
	}
	return a, nil
}

func buildTLSConfig(cfg *config.Agent) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.TunnelTLS.ServerName,
	}
	switch {
	case cfg.TunnelTLS.Fingerprint != "":
		want, err := cert.ParseFingerprint(cfg.TunnelTLS.Fingerprint)
		if err != nil {
			return nil, err
		}
		// The certificate is pinned by its SHA-256 digest instead of a CA chain.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificate")
			}
			sum := hashCert(rawCerts[0])
			if !equalBytes(sum, want) {
				return fmt.Errorf("server certificate fingerprint mismatch: got sha256:%s", hex.EncodeToString(sum))
			}
			return nil
		}
	case cfg.TunnelTLS.CAFile != "":
		pem, err := os.ReadFile(cfg.TunnelTLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read tunnel_tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tunnel_tls.ca_file contains no certificates")
		}
		tc.RootCAs = pool
	case cfg.TunnelTLS.InsecureSkipVerify:
		tc.InsecureSkipVerify = true
	default:
		return nil, errors.New("tunnel_tls: fingerprint or ca_file is required")
	}
	return tc, nil
}

// Run starts the local UI and reconnects until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.UIListen != "" {
		if err := a.startUI(ctx); err != nil {
			return err
		}
	}

	delay := reconnectMinDelay
	for {
		started := time.Now()
		err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		a.setLastError(err)
		// A session that stayed up for a while resets the backoff.
		if time.Since(started) > 30*time.Second {
			delay = reconnectMinDelay
		}
		jitter := time.Duration(rand.Int63n(int64(delay) / 5))
		wait := delay + jitter
		a.log.Warn("tunnel disconnected, reconnecting", "error", err, "retry_in", wait.String())
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
		delay *= 2
		if delay > reconnectMaxDelay {
			delay = reconnectMaxDelay
		}
	}
}

// runOnce runs one control session until it fails.
func (a *Agent) runOnce(ctx context.Context) error {
	conn, br, err := a.dialTunnel(ctx)
	if err != nil {
		return err
	}
	sess := &controlSession{
		conn:   conn,
		br:     br,
		agent:  a,
		regCh:  make(chan *protocol.Message, 4),
		closed: make(chan struct{}),
	}
	defer sess.close()

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			sess.close()
		case <-stopWatch:
		}
	}()

	loopErr := make(chan error, 1)
	go func() { loopErr <- sess.readLoop(ctx) }()

	services := a.snapshotServices()
	reply, err := a.registerWith(sess, services)
	if err != nil {
		return err
	}
	if reply.Error != "" {
		return fmt.Errorf("server rejected registration: %s", reply.Error)
	}
	if reply.SessionID == "" || reply.SessionToken == "" {
		return errors.New("server returned an empty session")
	}
	sess.id = reply.SessionID
	sess.token = reply.SessionToken

	a.attach(sess)
	defer a.detach(sess)

	okCount := a.applyRegistered(reply.ServicesStatus)
	a.log.Info("control tunnel established", "server", a.cfg.Server, "agent_id", a.cfg.AgentID,
		"session_id", sess.id, "services", okCount, "offered", len(services))
	if okCount == 0 {
		return errors.New("the server accepted none of the configured services")
	}

	pingCtx, stopPing := context.WithCancel(ctx)
	defer stopPing()
	go sess.pingLoop(pingCtx)

	select {
	case err := <-loopErr:
		return err
	case <-ctx.Done():
		return nil
	}
}

// UpdateServices validates, applies, and persists a new routing table.
// It returns per-service registration statuses from the server.
func (a *Agent) UpdateServices(next []config.Service) ([]protocol.ServiceStatus, error) {
	next = append([]config.Service(nil), next...)
	for i := range next {
		next[i].Name = strings.TrimSpace(next[i].Name)
		next[i].PathPrefix = strings.TrimSpace(next[i].PathPrefix)
		next[i].Target = strings.TrimSpace(next[i].Target)
	}
	if err := config.ValidateServices(next); err != nil {
		return nil, err
	}

	a.mu.Lock()
	sess := a.sess
	prev := append([]config.Service(nil), a.services...)
	a.mu.Unlock()
	if sess == nil || !sess.alive() {
		return nil, errors.New("agent 尚未连接到服务器，请稍后重试")
	}

	reply, err := a.registerWith(sess, next)
	if err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	if msg := statusError(reply.ServicesStatus); msg != "" {
		// The server may have applied part of the change; put the old table back.
		if _, revertErr := a.registerWith(sess, prev); revertErr != nil {
			a.log.Warn("failed to revert routing after a rejected update", "error", revertErr)
		}
		return nil, errors.New(msg)
	}

	a.mu.Lock()
	a.services = next
	a.statuses = indexStatuses(reply.ServicesStatus)
	a.lastErr = ""
	a.mu.Unlock()

	for _, st := range reply.ServicesStatus {
		a.log.Info("service registered", "service", st.Name, "path_prefix", st.PathPrefix)
	}
	if err := a.persistConfig(); err != nil {
		return reply.ServicesStatus, fmt.Errorf("配置已在服务器生效，但写回配置文件失败: %w", err)
	}
	a.log.Info("routing updated from the local UI", "services", len(next), "config", a.cfgPath)
	return reply.ServicesStatus, nil
}

// Reconnect drops the current control session so a fresh one is opened.
func (a *Agent) Reconnect() {
	a.mu.Lock()
	sess := a.sess
	a.mu.Unlock()
	if sess != nil {
		sess.close()
	}
}

// persistConfig writes the routing table back to the agent config file.
func (a *Agent) persistConfig() error {
	if a.cfgPath == "" {
		return nil
	}
	a.mu.Lock()
	cfg := *a.cfg
	cfg.Services = append([]config.Service(nil), a.services...)
	a.mu.Unlock()

	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(a.cfgPath)
	tmp, err := os.CreateTemp(dir, ".agent-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil && !os.IsPermission(err) {
		return err
	}
	if err := os.Rename(tmpName, a.cfgPath); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg.Services = append([]config.Service(nil), a.services...)
	a.mu.Unlock()
	return nil
}

func (a *Agent) snapshotServices() []config.Service {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]config.Service(nil), a.services...)
}

func (a *Agent) serviceByName(name string) (config.Service, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, svc := range a.services {
		if svc.Name == name {
			return svc, true
		}
	}
	return config.Service{}, false
}

func (a *Agent) attach(s *controlSession) {
	a.mu.Lock()
	a.sess = s
	a.lastErr = ""
	a.mu.Unlock()
}

func (a *Agent) detach(s *controlSession) {
	a.mu.Lock()
	if a.sess == s {
		a.sess = nil
	}
	a.mu.Unlock()
}

func (a *Agent) setLastError(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	a.lastErr = err.Error()
	a.mu.Unlock()
}

// applyRegistered records the server's per-service verdicts and logs them.
func (a *Agent) applyRegistered(statuses []protocol.ServiceStatus) int {
	a.mu.Lock()
	a.statuses = indexStatuses(statuses)
	a.mu.Unlock()
	okCount := 0
	for _, st := range statuses {
		if st.OK {
			okCount++
			a.log.Info("service registered", "service", st.Name, "path_prefix", st.PathPrefix,
				"target", a.targetOf(st.Name), "strip_prefix", a.stripOf(st.Name))
			continue
		}
		a.log.Error("service registration rejected", "service", st.Name, "path_prefix", st.PathPrefix, "error", st.Error)
	}
	return okCount
}

func (a *Agent) targetOf(name string) string {
	if svc, ok := a.serviceByName(name); ok {
		return svc.Target
	}
	return ""
}

func (a *Agent) stripOf(name string) bool {
	if svc, ok := a.serviceByName(name); ok {
		return svc.StripPrefix
	}
	return false
}

func indexStatuses(statuses []protocol.ServiceStatus) map[string]protocol.ServiceStatus {
	out := make(map[string]protocol.ServiceStatus, len(statuses))
	for _, st := range statuses {
		out[st.Name] = st
	}
	return out
}

func statusError(statuses []protocol.ServiceStatus) string {
	for _, st := range statuses {
		if !st.OK {
			if st.Error != "" {
				return fmt.Sprintf("服务 %s 注册失败: %s", st.Name, st.Error)
			}
			return fmt.Sprintf("服务 %s 注册失败", st.Name)
		}
	}
	return ""
}

// registerWith sends the register frame and waits for the server's reply.
func (a *Agent) registerWith(sess *controlSession, services []config.Service) (*protocol.Message, error) {
	specs := make([]protocol.ServiceSpec, 0, len(services))
	for _, svc := range services {
		specs = append(specs, protocol.ServiceSpec{
			Name:        svc.Name,
			PathPrefix:  svc.PathPrefix,
			StripPrefix: svc.StripPrefix,
		})
	}
	// Drop replies that arrived after a previous wait timed out.
drain:
	for {
		select {
		case <-sess.regCh:
		default:
			break drain
		}
	}

	if err := sess.send(&protocol.Message{
		Type:     protocol.TypeRegister,
		Version:  protocol.Version,
		AgentID:  a.cfg.AgentID,
		Services: specs,
	}); err != nil {
		return nil, fmt.Errorf("send register: %w", err)
	}

	timer := time.NewTimer(registerTimeout)
	defer timer.Stop()
	select {
	case msg := <-sess.regCh:
		return msg, nil
	case <-sess.closed:
		return nil, errors.New("会话已断开，请稍后重试")
	case <-timer.C:
		return nil, errors.New("等待服务器确认路由超时")
	}
}

// controlSession is one authenticated control connection.
type controlSession struct {
	conn  net.Conn
	br    *bufio.Reader
	agent *Agent
	id    string
	token string

	regCh  chan *protocol.Message
	closed chan struct{}

	writeMu sync.Mutex
	once    sync.Once
}

func (s *controlSession) alive() bool {
	select {
	case <-s.closed:
		return false
	default:
		return true
	}
}

func (s *controlSession) send(m *protocol.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.Write(s.conn, m); err != nil {
		return err
	}
	return s.conn.SetWriteDeadline(time.Time{})
}

func (s *controlSession) close() {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *controlSession) pingLoop(ctx context.Context) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-t.C:
			if err := s.send(&protocol.Message{Type: protocol.TypePing}); err != nil {
				s.close()
				return
			}
		}
	}
}

// readLoop dispatches every frame the server sends.
func (s *controlSession) readLoop(ctx context.Context) error {
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(controlReadIdle))
		msg, err := protocol.Read(s.br)
		if err != nil {
			return err
		}
		switch msg.Type {
		case protocol.TypeRegistered:
			select {
			case s.regCh <- msg:
			case <-s.closed:
				return net.ErrClosed
			default:
				s.agent.log.Warn("dropping an unmatched registration reply")
			}
		case protocol.TypeOpen:
			if msg.Service == "" || msg.ConnID == "" {
				continue
			}
			go s.handleOpen(ctx, msg)
		case protocol.TypePing:
			_ = s.send(&protocol.Message{Type: protocol.TypePong})
		case protocol.TypePong:
			// Liveness only.
		default:
			s.agent.log.Warn("ignoring unexpected control message", "type", msg.Type)
		}
	}
}

// handleOpen connects the local target and bridges one data tunnel into it.
func (s *controlSession) handleOpen(ctx context.Context, m *protocol.Message) {
	a := s.agent
	svc, ok := a.serviceByName(m.Service)
	if !ok {
		s.reportFailure(m, fmt.Sprintf("unknown service %q", m.Service))
		return
	}
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		s.reportFailure(m, "agent reached its connection limit")
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	target, err := (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext(dialCtx, "tcp", svc.Target)
	if err != nil {
		s.reportFailure(m, fmt.Sprintf("connect target %s: %v", svc.Target, err))
		return
	}

	data, err := a.dialData(ctx, s.id, s.token, m.ConnID)
	if err != nil {
		_ = target.Close()
		s.reportFailure(m, fmt.Sprintf("open data tunnel: %v", err))
		return
	}

	start := time.Now()
	res := bridge.Copy(data, target)
	a.log.Info("tunnel closed",
		"service", svc.Name,
		"conn_id", m.ConnID,
		"bytes_out", res.AToB,
		"bytes_in", res.BToA,
		"duration_ms", time.Since(start).Milliseconds())
}

func (s *controlSession) reportFailure(m *protocol.Message, reason string) {
	s.agent.log.Warn("cannot serve request", "service", m.Service, "conn_id", m.ConnID, "error", reason)
	if err := s.send(&protocol.Message{
		Type:    protocol.TypeOpenResult,
		ConnID:  m.ConnID,
		Service: m.Service,
		OK:      false,
		Error:   reason,
	}); err != nil {
		s.close()
	}
}

// dialTunnel opens the control connection and consumes the 101 response.
func (a *Agent) dialTunnel(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	conn, br, err := a.openUpgrade(ctx, map[string]string{
		"X-Cproxy-Mode":  "control",
		"X-Cproxy-Token": a.cfg.TokenValue,
	})
	if err != nil {
		return nil, nil, err
	}
	return conn, br, nil
}

// dialData opens one data connection for connID.
func (a *Agent) dialData(ctx context.Context, sessionID, sessionToken, connID string) (net.Conn, error) {
	conn, _, err := a.openUpgrade(ctx, map[string]string{
		"X-Cproxy-Mode":          "data",
		"X-Cproxy-Session":       sessionID,
		"X-Cproxy-Session-Token": sessionToken,
		"X-Cproxy-Conn":          connID,
	})
	return conn, err
}

// openUpgrade performs the raw HTTP upgrade handshake and returns the stream.
func (a *Agent) openUpgrade(ctx context.Context, headers map[string]string) (net.Conn, *bufio.Reader, error) {
	conn, err := a.dialServer(ctx)
	if err != nil {
		return nil, nil, err
	}
	host := a.cfg.Server
	if h, _, err := net.SplitHostPort(a.cfg.Server); err == nil {
		host = h
	}

	var b strings.Builder
	b.WriteString("GET " + pathutil.TunnelPath + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: cproxy/1\r\n")
	b.WriteString("User-Agent: cproxy-agent/" + protocolVersion() + "\r\n")
	for k, v := range headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if _, err := conn.Write([]byte(b.String())); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("write upgrade request: %w", err)
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read upgrade status: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") && !strings.HasPrefix(statusLine, "HTTP/1.0 101") {
		body, _ := readErrorBody(br)
		_ = conn.Close()
		return nil, nil, fmt.Errorf("tunnel upgrade rejected: %s %s", statusLine, body)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("read upgrade headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})

	var out net.Conn = conn
	if br.Buffered() > 0 {
		out = netutil.NewBufferedConn(conn, br)
	}
	return out, br, nil
}

// dialServer opens TCP and, when enabled, TLS to the server.
func (a *Agent) dialServer(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", a.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("dial server %s: %w", a.cfg.Server, err)
	}
	if a.tlsConf == nil {
		return conn, nil
	}
	tc := tls.Client(conn, a.tlsConf)
	_ = tc.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tc.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel TLS handshake: %w", err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

func readErrorBody(br *bufio.Reader) (string, error) {
	// Read a small bound so a misbehaving server cannot stall the agent.
	buf := make([]byte, 256)
	n, _ := br.Read(buf)
	return strings.TrimSpace(string(buf[:n])), nil
}

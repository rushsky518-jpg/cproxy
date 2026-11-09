// Package agent's local UI: a small single-page editor for the routing table.
package agent

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cproxy/internal/config"
	"cproxy/internal/protocol"
)

//go:embed ui/index.html
var uiIndexHTML []byte

const maxUIBody = 64 << 10

type uiService struct {
	Name        string `json:"name"`
	PathPrefix  string `json:"path_prefix"`
	Target      string `json:"target"`
	StripPrefix bool   `json:"strip_prefix"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	PublicURL   string `json:"public_url,omitempty"`
}

type uiState struct {
	AgentID    string      `json:"agent_id"`
	Server     string      `json:"server"`
	Connected  bool        `json:"connected"`
	SessionID  string      `json:"session_id"`
	ConfigPath string      `json:"config_path"`
	UIListen   string      `json:"ui_listen"`
	LastError  string      `json:"last_error,omitempty"`
	Services   []uiService `json:"services"`
}

// UIReady is closed once the local UI has a listener.
func (a *Agent) UIReady() <-chan struct{} { return a.uiReady }

// UIAddr returns the bound UI address. Valid after UIReady is closed.
func (a *Agent) UIAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.uiAddr
}

func (a *Agent) startUI(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.serveUIIndex)
	mux.HandleFunc("/api/state", a.handleUIState)
	mux.HandleFunc("/api/services", a.handleUISave)
	mux.HandleFunc("/api/reconnect", a.handleUIReconnect)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})

	ln, err := net.Listen("tcp", a.cfg.UIListen)
	if err != nil {
		return fmt.Errorf("listen ui %s: %w", a.cfg.UIListen, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          nil,
	}
	a.mu.Lock()
	a.uiAddr = ln.Addr().String()
	a.uiServer = srv
	a.mu.Unlock()
	close(a.uiReady)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("agent UI stopped", "error", err)
		}
	}()

	a.log.Info("agent UI listening", "url", "http://"+ln.Addr().String()+"/")
	if !isLoopbackListen(a.cfg.UIListen) {
		a.log.Warn("agent UI is not bound to loopback: anyone who can reach it can change the exposed routes")
	}
	return nil
}

func (a *Agent) serveUIIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(uiIndexHTML)
}

func (a *Agent) handleUIState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	writeJSON(w, http.StatusOK, a.uiSnapshot())
}

func (a *Agent) handleUISave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w, "PUT")
		return
	}
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "content-type must be application/json"})
		return
	}

	var req struct {
		Services []config.Service `json:"services"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxUIBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法的 JSON: " + err.Error()})
		return
	}

	statuses, err := a.UpdateServices(req.Services)
	if err != nil {
		code := http.StatusBadRequest
		if statuses != nil {
			code = http.StatusOK
		}
		writeJSON(w, code, map[string]any{
			"ok":       false,
			"error":    err.Error(),
			"services": statuses,
			"state":    a.uiSnapshot(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"services": statuses,
		"state":    a.uiSnapshot(),
	})
}

func (a *Agent) handleUIReconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
		return
	}
	a.Reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": a.uiSnapshot()})
}

func (a *Agent) uiSnapshot() uiState {
	a.mu.Lock()
	defer a.mu.Unlock()

	st := uiState{
		AgentID:    a.cfg.AgentID,
		Server:     a.cfg.Server,
		Connected:  a.sess != nil && a.sess.alive(),
		ConfigPath: a.cfgPath,
		UIListen:   a.cfg.UIListen,
		LastError:  a.lastErr,
	}
	if st.Connected {
		st.SessionID = a.sess.id
	}
	st.Services = make([]uiService, 0, len(a.services))
	for _, svc := range a.services {
		item := uiService{
			Name:        svc.Name,
			PathPrefix:  svc.PathPrefix,
			Target:      svc.Target,
			StripPrefix: svc.StripPrefix,
			OK:          true,
			PublicURL:   "http://" + a.cfg.Server + svc.PathPrefix + "/",
		}
		if status, ok := a.statuses[svc.Name]; ok {
			item.OK = status.OK
			item.Error = status.Error
		}
		st.Services = append(st.Services, item)
	}
	return st
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

// sameOrigin rejects browser cross-origin writes. Non-browser clients usually
// omit Origin and are allowed, since the UI only binds to loopback by default.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// statusByService is a small helper used by tests.
func statusByService(statuses []protocol.ServiceStatus) map[string]protocol.ServiceStatus {
	out := make(map[string]protocol.ServiceStatus, len(statuses))
	for _, st := range statuses {
		out[st.Name] = st
	}
	return out
}

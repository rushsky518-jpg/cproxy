package server

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cproxy/internal/netutil"
	"cproxy/internal/protocol"
	"cproxy/internal/token"
)

const (
	headerToken        = "X-Cproxy-Token"
	headerMode         = "X-Cproxy-Mode"
	headerSession      = "X-Cproxy-Session"
	headerSessionToken = "X-Cproxy-Session-Token"
	headerConn         = "X-Cproxy-Conn"

	modeControl = "control"
	modeData    = "data"

	upgradeProtocol = "cproxy/1"

	controlHandshakeTimeout = 10 * time.Second
	controlIdleTimeout      = 45 * time.Second
)

// isUpgrade reports whether r asks for the cproxy tunnel protocol.
func isUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), upgradeProtocol) {
		return false
	}
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// handleTunnel serves both the control and the data tunnel on the same port.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !isUpgrade(r) {
		http.Error(w, "upgrade required", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remote := remoteIP(r)
	if !s.limiter.allow(remote) {
		s.log.Warn("tunnel auth rate limited", "remote", remote)
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}

	switch r.Header.Get(headerMode) {
	case modeControl:
		if !token.Equal(s.cfg.TokenValue, r.Header.Get(headerToken)) {
			s.limiter.fail(remote)
			s.log.Warn("tunnel rejected: invalid token", "remote", remote)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.limiter.succeed(remote)
		s.serveControl(w, r)
	case modeData:
		s.serveData(w, r)
	default:
		s.limiter.fail(remote)
		http.Error(w, "unknown tunnel mode", http.StatusBadRequest)
	}
}

func (s *Server) serveControl(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := hijack(w)
	if err != nil {
		s.log.Error("control hijack failed", "error", err)
		return
	}
	defer conn.Close()
	if err := writeUpgrade(conn, brw); err != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(controlHandshakeTimeout))
	msg, err := protocol.Read(brw.Reader)
	if err != nil {
		s.log.Warn("control handshake failed", "remote", conn.RemoteAddr().String(), "error", err)
		return
	}
	if msg.Type != protocol.TypeRegister {
		s.log.Warn("control handshake failed: expected register", "remote", conn.RemoteAddr().String(), "type", msg.Type)
		return
	}
	if msg.Version != protocol.Version {
		_ = protocol.Write(conn, &protocol.Message{
			Type:  protocol.TypeRegistered,
			Error: fmt.Sprintf("unsupported protocol version %d", msg.Version),
		})
		return
	}
	if err := validateAgentID(msg.AgentID); err != nil {
		_ = protocol.Write(conn, &protocol.Message{Type: protocol.TypeRegistered, Error: err.Error()})
		return
	}

	// Validate the offered services before creating the session.
	specs, rejected := normalizeSpecs(msg.Services)
	for _, st := range rejected {
		s.log.Warn("agent offered an invalid service", "agent_id", msg.AgentID, "service", st.Name, "error", st.Error)
	}

	if len(specs) == 0 {
		s.log.Warn("agent offered no usable services", "agent_id", msg.AgentID)
		_ = protocol.Write(conn, &protocol.Message{Type: protocol.TypeRegistered, Error: "no valid services were offered"})
		return
	}
	if len(specs) > 128 {
		_ = protocol.Write(conn, &protocol.Message{Type: protocol.TypeRegistered, Error: "too many services (max 128)"})
		return
	}

	id, err := randomID()
	if err != nil {
		return
	}
	sessToken, err := token.Generate()
	if err != nil {
		return
	}
	sess := newSession(id, sessToken, msg.AgentID, conn, s.reg)

	statuses := append(rejected, s.reg.apply(sess, specs)...)
	sess.reg = s.reg
	s.reg.addSession(sess)

	if err := sess.send(&protocol.Message{
		Type:           protocol.TypeRegistered,
		SessionID:      sess.id,
		SessionToken:   sess.token,
		ServicesStatus: statuses,
	}); err != nil {
		sess.close(err)
		return
	}

	okCount := 0
	for _, st := range statuses {
		if st.OK {
			okCount++
		}
	}
	attrs := []any{"agent_id", msg.AgentID, "session_id", sess.id, "remote", conn.RemoteAddr().String(), "services", okCount}
	attrs = append(attrs, "offered", len(specs))
	s.log.Info("agent registered", attrs...)
	for _, st := range statuses {
		if !st.OK {
			s.log.Warn("service registration rejected", "agent_id", msg.AgentID, "service", st.Name, "path", st.PathPrefix, "error", st.Error)
		}
	}

	defer func() {
		sess.close(nil)
		s.log.Info("agent disconnected", "agent_id", sess.agentID, "session_id", sess.id)
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(controlIdleTimeout))
		msg, err := protocol.Read(brw.Reader)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Debug("control connection closed", "agent_id", sess.agentID, "error", err)
			}
			return
		}
		if err := sess.handleMessage(msg); err != nil {
			s.log.Warn("control protocol error", "agent_id", sess.agentID, "error", err)
			return
		}
	}
}

func (s *Server) serveData(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(headerSession)
	connID := r.Header.Get(headerConn)
	remote := remoteIP(r)
	if sessionID == "" || connID == "" {
		http.Error(w, "missing tunnel headers", http.StatusBadRequest)
		return
	}
	sess := s.reg.session(sessionID)
	if sess == nil || !sess.alive() {
		http.Error(w, "unknown session", http.StatusUnauthorized)
		return
	}
	if !token.Equal(sess.token, r.Header.Get(headerSessionToken)) {
		s.limiter.fail(remote)
		s.log.Warn("data tunnel rejected: invalid session token", "session_id", sessionID, "remote", remote)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	svc := sess.pendingService(connID)
	if svc == nil {
		s.log.Warn("data tunnel rejected: unknown pending connection", "session_id", sessionID, "conn_id", connID)
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}

	conn, brw, err := hijack(w)
	if err != nil {
		s.log.Error("data hijack failed", "error", err)
		return
	}
	if err := writeUpgrade(conn, brw); err != nil {
		_ = conn.Close()
		return
	}

	// Preserve bytes the HTTP parser may have buffered before the upgrade.
	var dataConn net.Conn = conn
	if n := brw.Reader.Buffered(); n > 0 {
		dataConn = netutil.NewBufferedConn(conn, brw.Reader)
	}
	if !svc.deliver(connID, dataConn) {
		s.log.Warn("data tunnel arrived after timeout", "session_id", sessionID, "conn_id", connID)
		_ = dataConn.Close()
		return
	}
	s.log.Debug("data tunnel established", "agent_id", sess.agentID, "service", svc.Name, "conn_id", connID)
}

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hj.Hijack()
}

func writeUpgrade(conn net.Conn, brw *bufio.ReadWriter) error {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + upgradeProtocol + "\r\n\r\n")
	if err != nil {
		return err
	}
	if err := brw.Flush(); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// normalizeSpecs separates well-formed service names from the rest.
func normalizeSpecs(in []protocol.ServiceSpec) ([]protocol.ServiceSpec, []protocol.ServiceStatus) {
	valid := make([]protocol.ServiceSpec, 0, len(in))
	var rejected []protocol.ServiceStatus
	for _, raw := range in {
		spec := protocol.ServiceSpec{
			Name:        strings.TrimSpace(raw.Name),
			PathPrefix:  raw.PathPrefix,
			StripPrefix: raw.StripPrefix,
		}
		if err := validateServiceName(spec.Name); err != nil {
			rejected = append(rejected, protocol.ServiceStatus{
				Name: raw.Name, PathPrefix: raw.PathPrefix, Error: err.Error(),
			})
			continue
		}
		valid = append(valid, spec)
	}
	return valid, rejected
}

func validateAgentID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("agent_id is required")
	}
	if len(id) > 128 {
		return errors.New("agent_id is too long")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("agent_id contains unsupported character %q", r)
		}
	}
	return nil
}

func validateServiceName(name string) error {
	if name == "" {
		return errors.New("service name is required")
	}
	if len(name) > 64 {
		return errors.New("service name is too long")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("service name contains unsupported character %q", r)
		}
	}
	return nil
}

// pendingService finds the service waiting for connID on sess.
func (s *session) pendingService(connID string) *Service {
	if connID == "" {
		return nil
	}
	for _, svc := range s.reg.all() {
		if svc.owner() != s {
			continue
		}
		if svc.hasPending(connID) {
			return svc
		}
	}
	return nil
}

func (s *Service) owner() *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

func (s *Service) hasPending(connID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pending[connID]
	return ok
}

// authLimiter throttles failed tunnel authentications per source IP.
type authLimiter struct {
	mu    sync.Mutex
	fails map[string]*failBucket
}

type failBucket struct {
	count int
	reset time.Time
}

const (
	failWindow = time.Minute
	failLimit  = 20
)

func newAuthLimiter() *authLimiter {
	return &authLimiter{fails: make(map[string]*failBucket)}
}

func (l *authLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.fails[key]
	if b == nil {
		return true
	}
	if time.Now().After(b.reset) {
		delete(l.fails, key)
		return true
	}
	return b.count < failLimit
}

func (l *authLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.fails[key]
	if b == nil || time.Now().After(b.reset) {
		l.fails[key] = &failBucket{count: 1, reset: time.Now().Add(failWindow)}
		return
	}
	b.count++
	if len(l.fails) > 10000 {
		for k, v := range l.fails {
			if time.Now().After(v.reset) {
				delete(l.fails, k)
			}
		}
	}
}

func (l *authLimiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

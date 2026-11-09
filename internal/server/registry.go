package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"cproxy/internal/pathutil"
	"cproxy/internal/protocol"
)

var (
	// ErrOffline means no agent session currently serves the route.
	ErrOffline = errors.New("service is offline")
	// ErrBusy means the service reached its connection limit.
	ErrBusy = errors.New("service connection limit reached")
	// ErrTunnelTimeout means the agent did not open a data channel in time.
	ErrTunnelTimeout = errors.New("timed out waiting for the agent data channel")
)

// dataResult is delivered to a pending dial when the agent opens a data
// channel or reports a failure.
type dataResult struct {
	conn net.Conn
	err  error
}

// Service is one public path prefix backed by one agent.
type Service struct {
	Name        string
	PathPrefix  string
	StripPrefix bool
	AgentID     string

	mu        sync.Mutex
	session   *session
	online    bool
	pending   map[string]chan dataResult
	transport *http.Transport
	proxy     *httputil.ReverseProxy

	sem chan struct{}

	requests atomic.Int64
	errors   atomic.Int64
	bytesOut atomic.Int64
	bytesIn  atomic.Int64
}

// route returns the current path prefix and strip setting atomically.
func (s *Service) route() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.PathPrefix, s.StripPrefix
}

// Online reports whether an agent session currently owns the service.
func (s *Service) Online() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online && s.session != nil && s.session.alive()
}

// Stats is a snapshot for the admin endpoint.
type Stats struct {
	Name       string `json:"name"`
	PathPrefix string `json:"path_prefix"`
	AgentID    string `json:"agent_id"`
	Online     bool   `json:"online"`
	Requests   int64  `json:"requests"`
	Errors     int64  `json:"errors"`
	BytesOut   int64  `json:"bytes_out"`
	BytesIn    int64  `json:"bytes_in"`
}

// registry owns the routing table and the active tunnel sessions.
type registry struct {
	mu       sync.RWMutex
	services map[string]*Service
	ordered  []*Service
	sessions map[string]*session
	byAgent  map[string]*session

	maxConns      int
	idle          time.Duration
	headerTimeout time.Duration
}

func newRegistry(maxConns int, idle, headerTimeout time.Duration) *registry {
	return &registry{
		services:      make(map[string]*Service),
		sessions:      make(map[string]*session),
		byAgent:       make(map[string]*session),
		maxConns:      maxConns,
		idle:          idle,
		headerTimeout: headerTimeout,
	}
}

// match returns the longest prefix that contains p.
func (r *registry) match(p string) *Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.ordered {
		if pathutil.MatchPrefix(p, s.PathPrefix) {
			return s
		}
	}
	return nil
}

func (r *registry) all() []*Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Service, len(r.ordered))
	copy(out, r.ordered)
	return out
}

// apply attaches specs to sess, prunes the routes this session no longer
// offers, and returns one status per spec. Re-running it on an existing session
// is how agent-side routing edits take effect without reconnecting.
func (r *registry) apply(sess *session, specs []protocol.ServiceSpec) []protocol.ServiceStatus {
	statuses := make([]protocol.ServiceStatus, 0, len(specs))
	offered := make(map[string]bool, len(specs))

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, spec := range specs {
		offered[spec.Name] = true
		st := protocol.ServiceStatus{Name: spec.Name, PathPrefix: spec.PathPrefix}
		prefix, err := pathutil.NormalizePrefix(spec.PathPrefix)
		if err != nil {
			st.Error = err.Error()
			statuses = append(statuses, st)
			continue
		}
		if other := r.conflictLocked(spec.Name, prefix); other != "" {
			st.Error = fmt.Sprintf("path %s is already used by service %q", prefix, other)
			statuses = append(statuses, st)
			continue
		}
		if existing := r.services[spec.Name]; existing != nil {
			existing.mu.Lock()
			owner := existing.session
			claimed := owner != nil && owner != sess && owner.alive()
			existing.mu.Unlock()
			if claimed {
				st.Error = fmt.Sprintf("service %q is already registered by agent %q", spec.Name, owner.agentID)
				statuses = append(statuses, st)
				continue
			}
		}

		svc := r.services[spec.Name]
		if svc == nil {
			svc = &Service{
				Name:    spec.Name,
				pending: make(map[string]chan dataResult),
				sem:     make(chan struct{}, r.maxConns),
			}
			svc.transport = newTransport(svc.dialContext, r.maxConns, r.idle, r.headerTimeout)
			svc.proxy = newProxy(svc)
			r.services[spec.Name] = svc
		}
		svc.mu.Lock()
		svc.PathPrefix = prefix
		svc.StripPrefix = spec.StripPrefix
		svc.AgentID = sess.agentID
		svc.session = sess
		svc.online = true
		svc.mu.Unlock()

		// A re-registration usually means the agent changed the target. Drop
		// pooled tunnels so the next request dials the new target instead of
		// reusing a connection bridged to the previous one.
		svc.transport.CloseIdleConnections()

		r.reindexLocked()
		st.OK = true
		st.PathPrefix = prefix
		statuses = append(statuses, st)
	}

	// Remove routes the agent dropped, otherwise they would linger as 503.
	for name, svc := range r.services {
		if offered[name] {
			continue
		}
		svc.mu.Lock()
		owned := svc.session == sess
		svc.mu.Unlock()
		if owned {
			delete(r.services, name)
		}
	}
	r.reindexLocked()

	return statuses
}

// conflictLocked returns the name of another service using prefix.
func (r *registry) conflictLocked(name, prefix string) string {
	for otherName, s := range r.services {
		if otherName == name {
			continue
		}
		if pathutil.Overlap(s.PathPrefix, prefix) {
			return otherName
		}
	}
	return ""
}

func (r *registry) reindexLocked() {
	services := r.services
	r.ordered = r.ordered[:0]
	for _, s := range services {
		r.ordered = append(r.ordered, s)
	}
	sort.Slice(r.ordered, func(i, j int) bool {
		if len(r.ordered[i].PathPrefix) != len(r.ordered[j].PathPrefix) {
			return len(r.ordered[i].PathPrefix) > len(r.ordered[j].PathPrefix)
		}
		return r.ordered[i].Name < r.ordered[j].Name
	})
}

func (r *registry) addSession(s *session) {
	var old *session
	r.mu.Lock()
	old = r.byAgent[s.agentID]
	if old != nil && old != s {
		delete(r.sessions, old.id)
	}
	r.sessions[s.id] = s
	r.byAgent[s.agentID] = s
	r.mu.Unlock()

	// Closing takes the registry lock, so it must happen outside the critical
	// section above.
	if old != nil && old != s {
		old.close(fmt.Errorf("replaced by a new session from agent %s", s.agentID))
	}
}

// removeSession detaches sess and marks the services it still owns offline.
func (r *registry) removeSession(sess *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sess.id)
	if r.byAgent[sess.agentID] == sess {
		delete(r.byAgent, sess.agentID)
	}
	for _, svc := range r.services {
		if svc.session == sess {
			svc.mu.Lock()
			svc.online = false
			svc.session = nil
			svc.failPendingLocked(ErrOffline)
			svc.mu.Unlock()
		}
	}
}

func (r *registry) session(id string) *session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

func (r *registry) stats() []Stats {
	services := r.all()
	out := make([]Stats, 0, len(services))
	for _, s := range services {
		s.mu.Lock()
		path, agentID, online := s.PathPrefix, s.AgentID, s.online && s.session != nil && s.session.alive()
		s.mu.Unlock()
		out = append(out, Stats{
			Name:       s.Name,
			PathPrefix: path,
			AgentID:    agentID,
			Online:     online,
			Requests:   s.requests.Load(),
			Errors:     s.errors.Load(),
			BytesOut:   s.bytesOut.Load(),
			BytesIn:    s.bytesIn.Load(),
		})
	}
	return out
}

// failPendingLocked resolves every waiting dial with err.
func (s *Service) failPendingLocked(err error) {
	for id, ch := range s.pending {
		select {
		case ch <- dataResult{err: err}:
		default:
		}
		delete(s.pending, id)
	}
}

// deliver hands an agent data connection to the dialer waiting for connID.
func (s *Service) deliver(connID string, conn net.Conn) bool {
	s.mu.Lock()
	ch, ok := s.pending[connID]
	if ok {
		delete(s.pending, connID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- dataResult{conn: conn}:
		return true
	default:
		return false
	}
}

// failConn reports an agent-side failure for connID.
func (s *Service) failConn(connID string, err error) {
	s.mu.Lock()
	ch, ok := s.pending[connID]
	if ok {
		delete(s.pending, connID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- dataResult{err: err}:
	default:
	}
}

// dialContext is the transport hook: it asks the agent for a fresh data channel.
func (s *Service) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, ErrBusy
	}
	release := func() { <-s.sem }

	s.mu.Lock()
	sess := s.session
	online := s.online && sess != nil && sess.alive()
	s.mu.Unlock()
	if !online {
		release()
		return nil, ErrOffline
	}

	connID, err := randomID()
	if err != nil {
		release()
		return nil, err
	}
	ch := make(chan dataResult, 1)
	s.mu.Lock()
	s.pending[connID] = ch
	s.mu.Unlock()

	cleanup := func() {
		s.mu.Lock()
		delete(s.pending, connID)
		s.mu.Unlock()
	}
	defer cleanup()

	if err := sess.send(&protocol.Message{Type: protocol.TypeOpen, ConnID: connID, Service: s.Name}); err != nil {
		release()
		return nil, fmt.Errorf("%w: %v", ErrOffline, err)
	}

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case res := <-ch:
		if res.err != nil {
			release()
			return nil, res.err
		}
		if res.conn == nil {
			release()
			return nil, ErrTunnelTimeout
		}
		return &trackedConn{Conn: res.conn, release: release, bytesOut: &s.bytesOut, bytesIn: &s.bytesIn}, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	case <-timer.C:
		release()
		return nil, ErrTunnelTimeout
	case <-sess.doneCh():
		release()
		return nil, ErrOffline
	}
}

// trackedConn returns a connection slot and counts bytes when closed.
type trackedConn struct {
	net.Conn
	release  func()
	once     sync.Once
	bytesOut *atomic.Int64
	bytesIn  *atomic.Int64
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytesIn.Add(int64(n))
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.bytesOut.Add(int64(n))
	return n, err
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func newTransport(dial func(context.Context, string, string) (net.Conn, error), maxConns int, idle, headerTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		MaxIdleConns:          maxConns,
		MaxIdleConnsPerHost:   maxConns,
		IdleConnTimeout:       idle,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: time.Second,
		// Keep the body byte-for-byte: the agent target may already compress.
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
}

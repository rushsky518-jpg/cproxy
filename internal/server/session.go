package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"cproxy/internal/protocol"
)

// session is one authenticated agent control connection.
type session struct {
	id      string
	token   string
	agentID string
	reg     *registry

	conn net.Conn

	mu     sync.Mutex
	closed bool

	done      chan struct{}
	closeOnce sync.Once
}

func newSession(id, token, agentID string, conn net.Conn, reg *registry) *session {
	return &session{
		id:      id,
		token:   token,
		agentID: agentID,
		reg:     reg,
		conn:    conn,
		done:    make(chan struct{}),
	}
}

func (s *session) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *session) doneCh() <-chan struct{} { return s.done }

// send writes one control frame. Writes are serialized because the reader
// goroutine and dialers both produce frames.
func (s *session) send(m *protocol.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session is closed")
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.Write(s.conn, m); err != nil {
		return fmt.Errorf("write control frame: %w", err)
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
	return nil
}

func (s *session) close(cause error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = s.conn.Close()
		close(s.done)
		if s.reg != nil {
			s.reg.removeSession(s)
		}
	})
}

// handleMessage processes one frame from the agent control connection.
func (s *session) handleMessage(m *protocol.Message) error {
	switch m.Type {
	case protocol.TypePing:
		return s.send(&protocol.Message{Type: protocol.TypePong})
	case protocol.TypePong:
		return nil
	case protocol.TypeOpenResult:
		if m.ConnID == "" {
			return nil
		}
		svc := s.serviceByName(m.Service)
		if svc == nil {
			return nil
		}
		if m.OK {
			// The data channel itself resolves the pending dial.
			return nil
		}
		msg := m.Error
		if msg == "" {
			msg = "agent failed to open the service"
		}
		svc.failConn(m.ConnID, errors.New(msg))
		return nil
	case protocol.TypeRegister:
		// The agent edited its routes and is re-registering on the live session.
		if m.Version != protocol.Version {
			return s.send(&protocol.Message{Type: protocol.TypeRegistered, Error: "unsupported protocol version"})
		}
		valid, rejected := normalizeSpecs(m.Services)
		if len(valid) == 0 {
			return s.send(&protocol.Message{Type: protocol.TypeRegistered, Error: "no valid services were offered"})
		}
		statuses := append(rejected, s.reg.apply(s, valid)...)
		return s.send(&protocol.Message{
			Type:           protocol.TypeRegistered,
			SessionID:      s.id,
			SessionToken:   s.token,
			ServicesStatus: statuses,
		})
	default:
		return fmt.Errorf("unexpected control message %q", m.Type)
	}
}

func (s *session) serviceByName(name string) *Service {
	if name == "" {
		return nil
	}
	s.reg.mu.RLock()
	defer s.reg.mu.RUnlock()
	svc := s.reg.services[name]
	if svc == nil || svc.session != s {
		return nil
	}
	return svc
}

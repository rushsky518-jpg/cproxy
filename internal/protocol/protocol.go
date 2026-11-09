// Package protocol defines the framed control messages used by the tunnel.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	Version      = 1
	MaxFrameSize = 64 << 10

	TypeRegister   = "register"
	TypeRegistered = "registered"
	TypeOpen       = "open"
	TypeOpenResult = "open_result"
	TypePing       = "ping"
	TypePong       = "pong"
)

// Message is the common control frame. Fields that do not apply are omitted.
type Message struct {
	Type           string          `json:"type"`
	Version        int             `json:"version,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	Services       []ServiceSpec   `json:"services,omitempty"`
	ServicesStatus []ServiceStatus `json:"services_status,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	SessionToken   string          `json:"session_token,omitempty"`
	ConnID         string          `json:"conn_id,omitempty"`
	Service        string          `json:"service,omitempty"`
	OK             bool            `json:"ok,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// ServiceSpec is what an agent asks the server to expose.
type ServiceSpec struct {
	Name        string `json:"name"`
	PathPrefix  string `json:"path_prefix"`
	StripPrefix bool   `json:"strip_prefix,omitempty"`
}

// ServiceStatus is the per-service result of a registration.
type ServiceStatus struct {
	Name       string `json:"name"`
	PathPrefix string `json:"path_prefix,omitempty"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// Read reads one length-prefixed JSON frame.
func Read(r io.Reader) (*Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("invalid frame size %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var m Message
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	if m.Type == "" {
		return nil, fmt.Errorf("frame has no type")
	}
	return &m, nil
}

// Write writes one length-prefixed JSON frame.
func Write(w io.Writer, m *Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}
	if len(b) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	return writeFull(w, b)
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

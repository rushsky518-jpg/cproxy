package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := &Message{
		Type:      TypeRegister,
		Version:   Version,
		AgentID:   "a-01",
		Services:  []ServiceSpec{{Name: "web", PathPrefix: "/higobase-admin"}},
		SessionID: "abc",
	}
	if err := Write(&buf, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Type != in.Type || out.AgentID != in.AgentID || out.Version != in.Version {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if len(out.Services) != 1 || out.Services[0].PathPrefix != "/higobase-admin" {
		t.Fatalf("services mismatch: %+v", out.Services)
	}
}

func TestReadRejectsBadFrames(t *testing.T) {
	// Zero length.
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0))
	if _, err := Read(&buf); err == nil {
		t.Error("zero-length frame was accepted")
	}

	// Oversized length.
	buf.Reset()
	binary.Write(&buf, binary.BigEndian, uint32(MaxFrameSize+1))
	if _, err := Read(&buf); err == nil {
		t.Error("oversized frame was accepted")
	}

	// Invalid JSON.
	buf.Reset()
	payload := []byte("{not json}")
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	if _, err := Read(&buf); err == nil {
		t.Error("invalid JSON was accepted")
	}

	// Missing type.
	buf.Reset()
	payload = []byte(`{"agent_id":"x"}`)
	binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	if _, err := Read(&buf); err == nil {
		t.Error("frame without type was accepted")
	}
}

func TestWriteRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, &Message{Type: TypeRegister, AgentID: strings.Repeat("x", MaxFrameSize)})
	if err == nil {
		t.Error("oversized message was accepted")
	}
}

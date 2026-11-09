package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"cproxy/internal/protocol"
)

func protocolVersion() string {
	return fmt.Sprintf("%d", protocol.Version)
}

func hashCert(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

func equalBytes(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

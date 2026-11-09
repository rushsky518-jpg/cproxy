// Package token loads and compares the shared agent token.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Load resolves the token from CPROXY_TOKEN, inline config, or a file.
func Load(inline, file string) (string, error) {
	if v := strings.TrimSpace(os.Getenv("CPROXY_TOKEN")); v != "" {
		return Validate(v)
	}
	if v := strings.TrimSpace(inline); v != "" {
		return Validate(v)
	}
	if file == "" {
		return "", fmt.Errorf("token or token_file is required")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read token_file %s: %w", file, err)
	}
	return Validate(strings.TrimSpace(string(b)))
}

// Validate checks that a token is present and safe to put in a header.
func Validate(s string) (string, error) {
	if len(s) < 16 {
		return "", fmt.Errorf("token must be at least 16 bytes")
	}
	if len(s) > 512 {
		return "", fmt.Errorf("token is too long")
	}
	for _, r := range s {
		// Tokens travel in an HTTP header; keep them to visible ASCII.
		if r < 0x21 || r > 0x7e {
			return "", fmt.Errorf("token must contain only printable ASCII characters")
		}
	}
	return s, nil
}

// Generate returns a new 256-bit URL-safe token.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Equal compares two tokens without leaking their contents through timing.
func Equal(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

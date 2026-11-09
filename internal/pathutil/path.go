// Package pathutil contains the path rules shared by the server and agent.
package pathutil

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// TunnelPath is the reserved HTTP path used by the agent tunnel.
	TunnelPath = "/_cproxy/tunnel"
	// ReservedRoot is the reserved path prefix. Services may not use it.
	ReservedRoot = "/_cproxy"
)

// NormalizePrefix validates and normalizes a public path prefix.
// The returned prefix never has a trailing slash.
func NormalizePrefix(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("path_prefix is required")
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("path_prefix must be valid UTF-8")
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path_prefix must start with /")
	}
	if strings.ContainsAny(p, "\\?#%") {
		return "", fmt.Errorf("path_prefix contains an unsupported character")
	}
	if strings.Contains(p, "//") {
		return "", fmt.Errorf("path_prefix must not contain //")
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "", fmt.Errorf("path_prefix cannot be /")
	}
	if len(p) > 200 {
		return "", fmt.Errorf("path_prefix is too long")
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("path_prefix contains an invalid segment")
		}
		for _, r := range seg {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return "", fmt.Errorf("path_prefix contains whitespace or a control character")
			}
		}
	}
	if IsReserved(p) {
		return "", fmt.Errorf("path_prefix %s is reserved", p)
	}
	return p, nil
}

// IsReserved reports whether p is the tunnel path or below it.
func IsReserved(p string) bool {
	return p == ReservedRoot || strings.HasPrefix(p, ReservedRoot+"/")
}

// ValidRequestPath performs conservative validation before routing.
func ValidRequestPath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || len(p) > 8192 {
		return false
	}
	if !utf8.ValidString(p) {
		return false
	}
	if strings.Contains(p, "\\") || strings.Contains(p, "//") {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// MatchPrefix reports whether p is prefix itself or a child of prefix.
// It matches on path-segment boundaries, so /app1x does not match /app1.
func MatchPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// StripPrefix removes prefix from p and always returns a rooted path.
func StripPrefix(p, prefix string) string {
	if p == prefix {
		return "/"
	}
	p = strings.TrimPrefix(p, prefix)
	if p == "" || !strings.HasPrefix(p, "/") {
		return "/" + strings.TrimPrefix(p, "/")
	}
	return p
}

// Overlap reports whether two prefixes would make routing ambiguous.
func Overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

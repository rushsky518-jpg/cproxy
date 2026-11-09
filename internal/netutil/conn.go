// Package netutil contains the connection helpers used by the HTTP tunnel.
package netutil

import (
	"bufio"
	"net"
)

// BufferedConn is a net.Conn whose reads first drain a bufio.Reader. This is
// required after an HTTP response because ReadResponse may have buffered bytes
// that belong to the upgraded stream.
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// NewBufferedConn wraps c. If r is nil, reads go straight to c.
func NewBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: c, r: r}
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

// CloseWrite propagates a half-close when the underlying connection supports it.
func (c *BufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PrefixConn replays bytes read during protocol detection.
type PrefixConn struct {
	net.Conn
	prefix []byte
}

// NewPrefixConn returns a connection that yields prefix before reading Conn.
func NewPrefixConn(c net.Conn, prefix []byte) *PrefixConn {
	cp := make([]byte, len(prefix))
	copy(cp, prefix)
	return &PrefixConn{Conn: c, prefix: cp}
}

func (c *PrefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite propagates a half-close when the underlying connection supports it.
func (c *PrefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

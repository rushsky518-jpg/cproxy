package netutil

import (
	"net"
	"sync"
)

// ChanListener is a net.Listener fed by another goroutine. It lets the
// protocol-detecting listener hand connections to one of two http.Servers.
type ChanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

// NewChanListener creates a listener with a buffered handoff channel.
func NewChanListener(addr net.Addr, buffer int) *ChanListener {
	if buffer < 0 {
		buffer = 0
	}
	return &ChanListener{
		addr: addr,
		ch:   make(chan net.Conn, buffer),
		done: make(chan struct{}),
	}
}

// Accept implements net.Listener.
func (l *ChanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		if c == nil {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener and drains queued connections.
func (l *ChanListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		for {
			select {
			case c := <-l.ch:
				if c != nil {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

// Addr implements net.Listener.
func (l *ChanListener) Addr() net.Addr {
	return l.addr
}

// Push hands a connection to the HTTP server. It returns false when the
// listener is closed; the caller must close the connection in that case.
func (l *ChanListener) Push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

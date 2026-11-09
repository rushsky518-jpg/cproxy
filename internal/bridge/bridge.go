// Package bridge copies bytes in both directions and preserves TCP half-close.
package bridge

import (
	"io"
	"net"
	"sync"
	"time"
)

// Result reports the bytes copied in each direction.
type Result struct {
	AToB     int64
	BToA     int64
	Duration time.Duration
}

// Copy bridges a and b until both directions finish. A normal EOF half-closes
// the peer; an error closes both connections to avoid a stuck copy.
func Copy(a, b net.Conn) Result {
	start := time.Now()
	var res Result
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(a, b)
		res.AToB = n
		if err != nil {
			_ = a.Close()
			_ = b.Close()
			return
		}
		closeWrite(a)
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(b, a)
		res.BToA = n
		if err != nil {
			_ = a.Close()
			_ = b.Close()
			return
		}
		closeWrite(b)
	}()

	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	res.Duration = time.Since(start)
	return res
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

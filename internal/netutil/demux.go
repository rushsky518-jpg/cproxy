package netutil

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Demux accepts on one TCP port and separates TLS from plain HTTP by looking
// at the first byte. The agent tunnel uses TLS; browsers use plain HTTP.
type Demux struct {
	base       net.Listener
	tlsConfig  *tls.Config
	plain      *ChanListener
	tls        *ChanListener
	log        *slog.Logger
	timeout    time.Duration
	handshakes chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
}

// NewDemux starts accepting. tlsConfig may be nil to reject TLS connections.
func NewDemux(base net.Listener, tlsConfig *tls.Config, logger *slog.Logger) *Demux {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Demux{
		base:       base,
		tlsConfig:  tlsConfig,
		plain:      NewChanListener(base.Addr(), 256),
		log:        logger,
		timeout:    5 * time.Second,
		handshakes: make(chan struct{}, 128),
		done:       make(chan struct{}),
	}
	if tlsConfig != nil {
		d.tls = NewChanListener(base.Addr(), 128)
	}
	d.wg.Add(1)
	go d.acceptLoop()
	return d
}

// Plain returns the plain HTTP listener.
func (d *Demux) Plain() net.Listener { return d.plain }

// TLS returns the TLS listener, or nil when TLS is disabled.
func (d *Demux) TLS() net.Listener {
	if d.tls == nil {
		return nil
	}
	return d.tls
}

func (d *Demux) acceptLoop() {
	defer d.wg.Done()
	for {
		c, err := d.base.Accept()
		if err != nil {
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handle(c)
		}()
	}
}

func (d *Demux) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(d.timeout))
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := NewPrefixConn(c, first[:])

	if first[0] == 0x16 {
		if d.tlsConfig == nil {
			_ = c.Close()
			return
		}
		select {
		case d.handshakes <- struct{}{}:
		case <-d.done:
			_ = c.Close()
			return
		}
		defer func() { <-d.handshakes }()

		tc := tls.Server(pc, d.tlsConfig)
		_ = tc.SetDeadline(time.Now().Add(d.timeout))
		if err := tc.Handshake(); err != nil {
			d.log.Debug("tunnel TLS handshake failed", "remote", c.RemoteAddr().String(), "error", err)
			_ = tc.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		if !d.tls.Push(tc) {
			_ = tc.Close()
		}
		return
	}

	if !d.plain.Push(pc) {
		_ = pc.Close()
	}
}

// Close stops accepting and drains the handoff queues.
func (d *Demux) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		_ = d.base.Close()
		_ = d.plain.Close()
		if d.tls != nil {
			_ = d.tls.Close()
		}
	})
	d.wg.Wait()
	return nil
}

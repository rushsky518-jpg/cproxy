// Package server implements the public HTTP endpoint and the agent tunnel.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"cproxy/internal/cert"
	"cproxy/internal/config"
	"cproxy/internal/netutil"
	"cproxy/internal/pathutil"
)

// Server is the c-side process.
type Server struct {
	cfg  *config.Server
	log  *slog.Logger
	reg  *registry
	cert tls.Certificate

	limiter *authLimiter
	started time.Time

	addr      string
	adminAddr string
	ready     chan struct{}
	readyOnce sync.Once

	demux     *netutil.Demux
	publicSrv *http.Server
	tunnelSrv *http.Server
	adminSrv  *http.Server

	wg       sync.WaitGroup
	stopOnce sync.Once
}

// New validates the tunnel certificate and prepares the server.
func New(cfg *config.Server, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg: cfg,
		log: logger,
		reg: newRegistry(cfg.MaxConnsPerService,
			time.Duration(cfg.IdleConnTimeoutSeconds)*time.Second,
			time.Duration(cfg.ResponseHeaderTimeoutSecond)*time.Second),
		limiter: newAuthLimiter(),
		started: time.Now(),
		ready:   make(chan struct{}),
	}
	if cfg.TunnelTLS.IsEnabled() {
		c, fp, err := cert.LoadOrGenerate(cfg.TunnelTLS.CertFile, cfg.TunnelTLS.KeyFile,
			cfg.TunnelTLS.ShouldAutoGenerate(), cfg.TunnelTLS.PublicHost)
		if err != nil {
			return nil, fmt.Errorf("tunnel TLS: %w", err)
		}
		s.cert = c
		s.log.Info("tunnel TLS enabled", "fingerprint", fp, "cert_file", cfg.TunnelTLS.CertFile)
	} else {
		s.log.Warn("tunnel TLS is disabled: the agent token and tunnel traffic are sent in clear text")
	}
	return s, nil
}

// Run starts the listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	base, err := net.Listen("tcp", s.cfg.PublicListen)
	if err != nil {
		return fmt.Errorf("listen public %s: %w", s.cfg.PublicListen, err)
	}

	var tlsConfig *tls.Config
	if s.cfg.TunnelTLS.IsEnabled() {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{s.cert},
			MinVersion:   tls.VersionTLS12,
			// The tunnel speaks HTTP/1.1 only; HTTP/2 cannot be hijacked.
			NextProtos: []string{"http/1.1"},
		}
	}
	s.demux = netutil.NewDemux(base, tlsConfig, s.log)
	s.addr = base.Addr().String()

	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/", s.handlePublic)
	if tlsConfig == nil {
		// Single plain listener: the tunnel shares the public path space.
		publicMux.HandleFunc(pathutil.TunnelPath, s.handleTunnel)
	}

	tunnelMux := http.NewServeMux()
	tunnelMux.HandleFunc(pathutil.TunnelPath, s.handleTunnel)
	tunnelMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	s.publicSrv = &http.Server{
		Handler:           publicMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	s.tunnelSrv = &http.Server{
		Handler:           tunnelMux,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}

	s.serve(s.publicSrv, s.demux.Plain())
	if l := s.demux.TLS(); l != nil {
		s.serve(s.tunnelSrv, l)
	}

	if s.cfg.AdminListen != "" {
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/healthz", s.handleHealthz)
		adminMux.HandleFunc("/status", s.handleStatus)
		s.adminSrv = &http.Server{
			Handler:           adminMux,
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		}
		adminLn, err := net.Listen("tcp", s.cfg.AdminListen)
		if err != nil {
			_ = s.demux.Close()
			return fmt.Errorf("listen admin %s: %w", s.cfg.AdminListen, err)
		}
		s.adminAddr = adminLn.Addr().String()
		s.log.Info("admin listening", "addr", s.adminAddr)
		s.serve(s.adminSrv, adminLn)
	}

	s.log.Info("server listening",
		"addr", base.Addr().String(),
		"admin", s.adminAddr,
		"tunnel_tls", s.cfg.TunnelTLS.IsEnabled(),
		"max_conns_per_service", s.cfg.MaxConnsPerService)

	// All listeners are bound; callers may now use Addr and AdminAddr.
	s.readyOnce.Do(func() { close(s.ready) })

	<-ctx.Done()
	s.log.Info("shutting down")
	return s.Shutdown()
}

func (s *Server) serve(srv *http.Server, l net.Listener) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.log.Error("listener stopped", "addr", l.Addr().String(), "error", err)
		}
	}()
}

// Shutdown stops accepting and waits briefly for in-flight requests.
func (s *Server) Shutdown() error {
	timeout := time.Duration(s.cfg.ShutdownTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	s.stopOnce.Do(func() {
		s.reg.closeSessions()
		if s.demux != nil {
			_ = s.demux.Close()
		}
		for _, srv := range []*http.Server{s.publicSrv, s.tunnelSrv, s.adminSrv} {
			if srv != nil {
				_ = srv.Shutdown(ctx)
			}
		}
	})
	s.wg.Wait()
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	type status struct {
		UptimeSeconds int64     `json:"uptime_seconds"`
		Services      []Stats   `json:"services"`
		Agents        int       `json:"agents"`
		TunnelTLS     bool      `json:"tunnel_tls"`
		Listen        string    `json:"listen"`
		Tunnel        string    `json:"tunnel_path"`
		GeneratedAt   time.Time `json:"generated_at"`
	}
	st := status{
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		Services:      s.reg.stats(),
		Agents:        s.reg.agentCount(),
		TunnelTLS:     s.cfg.TunnelTLS.IsEnabled(),
		Listen:        s.cfg.PublicListen,
		Tunnel:        pathutil.TunnelPath,
		GeneratedAt:   time.Now().UTC(),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(st)
}

func (r *registry) agentCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byAgent)
}

// closeSessions tears down every control connection (used during shutdown).
func (r *registry) closeSessions() {
	r.mu.RLock()
	list := make([]*session, 0, len(r.sessions))
	for _, s := range r.sessions {
		list = append(list, s)
	}
	r.mu.RUnlock()
	for _, s := range list {
		s.close(errors.New("server is shutting down"))
	}
}

// Addr returns the bound public address. Valid after Ready is closed.
func (s *Server) Addr() string { return s.addr }

// AdminAddr returns the bound admin address ("" when admin is disabled).
func (s *Server) AdminAddr() string { return s.adminAddr }

// Ready is closed once the public listener is bound.
func (s *Server) Ready() <-chan struct{} { return s.ready }

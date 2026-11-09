package server

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"cproxy/internal/pathutil"
)

// newProxy builds the per-service reverse proxy. It talks to the agent over a
// private Transport whose dialer opens a fresh tunnel data channel.
func newProxy(svc *Service) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: svc.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			for k := range pr.In.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-cproxy-") {
					pr.Out.Header.Del(k)
				}
			}
			prefix, strip := svc.route()
			p := pr.In.URL.Path
			if strip {
				p = pathutil.StripPrefix(p, prefix)
			}
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = svc.Name + ".cproxy.internal"
			pr.Out.URL.Path = p
			pr.Out.URL.RawPath = ""
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			// The proxy is the edge: never trust a client-supplied chain.
			pr.Out.Header.Set("X-Forwarded-For", remoteIP(pr.In))
			pr.Out.Header.Set("X-Forwarded-Prefix", prefix)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", "http")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Best effort for strip mode; base-path deployments need no rewrite.
			prefix, strip := svc.route()
			if !strip {
				return nil
			}
			loc := resp.Header.Get("Location")
			if strings.HasPrefix(loc, "/") && !pathutil.MatchPrefix(loc, prefix) {
				resp.Header.Set("Location", prefix+loc)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			svc.errors.Add(1)
			code, msg := classifyProxyError(err)
			if code == 0 {
				// Client went away; nothing sensible to send.
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Proxy-Service", svc.Name)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(msg + "\n"))
		},
		// Flush promptly so SSE and streamed pages are not held in a buffer.
		FlushInterval: -1,
	}
}

func classifyProxyError(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusBadGateway, "bad gateway"
	case errors.Is(err, context.Canceled):
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return http.StatusGatewayTimeout, "gateway timeout"
		}
		return 0, ""
	case errors.Is(err, ErrOffline):
		return http.StatusServiceUnavailable, "service is offline: the agent is not connected"
	case errors.Is(err, ErrBusy):
		return http.StatusServiceUnavailable, "service is busy: connection limit reached"
	case errors.Is(err, ErrTunnelTimeout):
		return http.StatusGatewayTimeout, "gateway timeout: the agent did not open a data channel"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "gateway timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout, "gateway timeout"
	}
	return http.StatusBadGateway, "bad gateway: " + err.Error()
}

// handlePublic is the entry point for browser traffic.
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	reqID := s.requestID(r)
	rec.Header().Set("X-Request-ID", reqID)
	// Also expose it to the backend so application logs can correlate.
	r.Header.Set("X-Request-ID", reqID)

	p := r.URL.Path
	if !pathutil.ValidRequestPath(p) {
		http.Error(rec, "bad request path", http.StatusBadRequest)
		s.logAccess(r, reqID, nil, rec, start)
		return
	}
	if pathutil.IsReserved(p) {
		http.NotFound(rec, r)
		s.logAccess(r, reqID, nil, rec, start)
		return
	}

	svc := s.reg.match(p)
	if svc == nil {
		rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rec.WriteHeader(http.StatusNotFound)
		_, _ = rec.Write([]byte("no service is registered for this path\n"))
		s.logAccess(r, reqID, nil, rec, start)
		return
	}
	if r.Method == http.MethodConnect {
		http.Error(rec, "CONNECT is not supported", http.StatusMethodNotAllowed)
		s.logAccess(r, reqID, svc, rec, start)
		return
	}
	if !svc.Online() {
		rec.Header().Set("Retry-After", "5")
		rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rec.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rec.Write([]byte("service is offline: the agent is not connected\n"))
		s.logAccess(r, reqID, svc, rec, start)
		return
	}
	// Browsers resolve relative URLs against the current directory, so a bare
	// prefix must end in a slash when we strip it.
	prefix, strip := svc.route()
	if strip && p == prefix && !strings.HasSuffix(r.URL.Path, "/") {
		target := prefix + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(rec, r, target, http.StatusPermanentRedirect)
		s.logAccess(r, reqID, svc, rec, start)
		return
	}

	svc.requests.Add(1)
	svc.proxy.ServeHTTP(rec, r)
	s.logAccess(r, reqID, svc, rec, start)
}

// statusRecorder captures the status code and body size for access logs.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(p)
	r.written += int64(n)
	return n, err
}

// Flush supports streaming responses through the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards protocol upgrades (for example Vite HMR WebSockets).
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	conn, brw, err := hj.Hijack()
	if err == nil {
		r.status = http.StatusSwitchingProtocols
		r.wrote = true
	}
	return conn, brw, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) logAccess(r *http.Request, reqID string, svc *Service, rec *statusRecorder, start time.Time) {
	level := slog.LevelInfo
	if rec.status >= 500 {
		level = slog.LevelWarn
	}
	attrs := []any{
		"request_id", reqID,
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"bytes", rec.written,
		"duration_ms", time.Since(start).Milliseconds(),
		"remote", remoteIP(r),
	}
	if svc != nil {
		attrs = append(attrs, "service", svc.Name)
	}
	s.log.Log(context.Background(), level, "http request", attrs...)
}

func (s *Server) requestID(r *http.Request) string {
	// Keep a sane client-supplied id so b can correlate its own traces.
	if in := strings.TrimSpace(r.Header.Get("X-Request-ID")); in != "" && len(in) <= 64 && isTokenText(in) {
		return in
	}
	id, err := randomID()
	if err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return id[:16]
}

func isTokenText(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

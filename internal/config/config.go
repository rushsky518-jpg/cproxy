// Package config loads and validates the server and agent JSON files.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cproxy/internal/cert"
	"cproxy/internal/pathutil"
	"cproxy/internal/token"
)

// Server is the c-side configuration.
type Server struct {
	PublicListen                string    `json:"public_listen,omitempty"`
	Token                       string    `json:"token,omitempty"`
	TokenFile                   string    `json:"token_file,omitempty"`
	AdminListen                 string    `json:"admin_listen,omitempty"`
	TunnelTLS                   TunnelTLS `json:"tunnel_tls"`
	MaxConnsPerService          int       `json:"max_conns_per_service,omitempty"`
	IdleConnTimeoutSeconds      int       `json:"idle_conn_timeout_seconds,omitempty"`
	ResponseHeaderTimeoutSecond int       `json:"response_header_timeout_seconds,omitempty"`
	ShutdownTimeoutSeconds      int       `json:"shutdown_timeout_seconds,omitempty"`
	LogLevel                    string    `json:"log_level,omitempty"`
	LogFormat                   string    `json:"log_format,omitempty"`

	TokenValue string `json:"-"`
}

// TunnelTLS configures the TLS layer used only by the agent tunnel. The
// public HTTP listener remains plain HTTP.
type TunnelTLS struct {
	Enabled      *bool  `json:"enabled,omitempty"`
	CertFile     string `json:"cert_file,omitempty"`
	KeyFile      string `json:"key_file,omitempty"`
	AutoGenerate *bool  `json:"auto_generate,omitempty"`
	PublicHost   string `json:"public_host,omitempty"`
}

// IsEnabled defaults to true.
func (t TunnelTLS) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

// ShouldAutoGenerate defaults to true.
func (t TunnelTLS) ShouldAutoGenerate() bool {
	return t.AutoGenerate == nil || *t.AutoGenerate
}

// Agent is the a-side configuration.
type Agent struct {
	Server     string         `json:"server"`
	AgentID    string         `json:"agent_id,omitempty"`
	Token      string         `json:"token,omitempty"`
	TokenFile  string         `json:"token_file,omitempty"`
	UIListen   string         `json:"ui_listen,omitempty"`
	TunnelTLS  AgentTunnelTLS `json:"tunnel_tls"`
	Services   []Service      `json:"services"`
	LogLevel   string         `json:"log_level,omitempty"`
	LogFormat  string         `json:"log_format,omitempty"`
	TokenValue string         `json:"-"`
}

// AgentTunnelTLS configures how the agent verifies the server certificate.
type AgentTunnelTLS struct {
	Enabled            *bool  `json:"enabled,omitempty"`
	Fingerprint        string `json:"fingerprint,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// IsEnabled defaults to true.
func (t AgentTunnelTLS) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

// Service is one local target exposed under a public path prefix.
type Service struct {
	Name        string `json:"name"`
	PathPrefix  string `json:"path_prefix"`
	Target      string `json:"target"`
	StripPrefix bool   `json:"strip_prefix,omitempty"`
}

// LoadServer reads, defaults, validates, and resolves the token.
func LoadServer(path string) (*Server, error) {
	var cfg Server
	if err := decode(path, &cfg); err != nil {
		return nil, err
	}
	setServerDefaults(&cfg)
	if err := validateServer(&cfg); err != nil {
		return nil, err
	}
	tok, err := token.Load(cfg.Token, cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	cfg.TokenValue = tok
	return &cfg, nil
}

// LoadAgent reads, defaults, validates, and resolves the token.
func LoadAgent(path string) (*Agent, error) {
	var cfg Agent
	if err := decode(path, &cfg); err != nil {
		return nil, err
	}
	if err := setAgentDefaults(&cfg); err != nil {
		return nil, err
	}
	if err := validateAgent(&cfg); err != nil {
		return nil, err
	}
	tok, err := token.Load(cfg.Token, cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	cfg.TokenValue = tok
	return &cfg, nil
}

func setServerDefaults(cfg *Server) {
	if cfg.PublicListen == "" {
		cfg.PublicListen = "0.0.0.0:8080"
	}
	if cfg.AdminListen == "" {
		cfg.AdminListen = "127.0.0.1:7002"
	}
	if cfg.MaxConnsPerService == 0 {
		cfg.MaxConnsPerService = 64
	}
	if cfg.IdleConnTimeoutSeconds == 0 {
		cfg.IdleConnTimeoutSeconds = 90
	}
	if cfg.ResponseHeaderTimeoutSecond == 0 {
		cfg.ResponseHeaderTimeoutSecond = 60
	}
	if cfg.ShutdownTimeoutSeconds == 0 {
		cfg.ShutdownTimeoutSeconds = 10
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}
	if cfg.TunnelTLS.IsEnabled() {
		if cfg.TunnelTLS.CertFile == "" && cfg.TunnelTLS.KeyFile == "" {
			cfg.TunnelTLS.CertFile = filepath.Join("certs", "tunnel.crt")
			cfg.TunnelTLS.KeyFile = filepath.Join("certs", "tunnel.key")
		}
	}
}

func setAgentDefaults(cfg *Agent) error {
	if cfg.AgentID == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("resolve hostname for agent_id: %w", err)
		}
		cfg.AgentID = h
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}
	switch strings.ToLower(strings.TrimSpace(cfg.UIListen)) {
	case "":
		cfg.UIListen = "127.0.0.1:7100"
	case "off", "none", "false", "disabled":
		cfg.UIListen = ""
	}
	if cfg.TunnelTLS.IsEnabled() && cfg.TunnelTLS.ServerName == "" {
		if host, _, err := net.SplitHostPort(cfg.Server); err == nil {
			cfg.TunnelTLS.ServerName = host
		}
	}
	return nil
}

func validateServer(cfg *Server) error {
	if err := validateListen(cfg.PublicListen); err != nil {
		return fmt.Errorf("public_listen: %w", err)
	}
	if cfg.AdminListen != "" {
		if err := validateListen(cfg.AdminListen); err != nil {
			return fmt.Errorf("admin_listen: %w", err)
		}
		if cfg.AdminListen == cfg.PublicListen && !strings.HasSuffix(cfg.AdminListen, ":0") {
			return fmt.Errorf("admin_listen must not equal public_listen")
		}
	}
	if cfg.MaxConnsPerService < 1 || cfg.MaxConnsPerService > 10000 {
		return fmt.Errorf("max_conns_per_service must be between 1 and 10000")
	}
	if cfg.IdleConnTimeoutSeconds < 1 || cfg.IdleConnTimeoutSeconds > 86400 {
		return fmt.Errorf("idle_conn_timeout_seconds is out of range")
	}
	if cfg.ResponseHeaderTimeoutSecond < 1 || cfg.ResponseHeaderTimeoutSecond > 86400 {
		return fmt.Errorf("response_header_timeout_seconds is out of range")
	}
	if cfg.ShutdownTimeoutSeconds < 1 || cfg.ShutdownTimeoutSeconds > 300 {
		return fmt.Errorf("shutdown_timeout_seconds is out of range")
	}
	if cfg.TunnelTLS.IsEnabled() {
		if cfg.TunnelTLS.CertFile == "" || cfg.TunnelTLS.KeyFile == "" {
			return fmt.Errorf("tunnel_tls.cert_file and tunnel_tls.key_file are required when TLS is enabled")
		}
	}
	if err := validateLog(cfg.LogLevel, cfg.LogFormat); err != nil {
		return err
	}
	return nil
}

func validateAgent(cfg *Agent) error {
	if err := validateHostPort(cfg.Server); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if err := validateName(cfg.AgentID, 128); err != nil {
		return fmt.Errorf("agent_id: %w", err)
	}
	if cfg.TunnelTLS.IsEnabled() {
		if cfg.TunnelTLS.Fingerprint != "" && cfg.TunnelTLS.CAFile != "" {
			return fmt.Errorf("tunnel_tls: set either fingerprint or ca_file, not both")
		}
		if cfg.TunnelTLS.Fingerprint == "" && cfg.TunnelTLS.CAFile == "" && !cfg.TunnelTLS.InsecureSkipVerify {
			return fmt.Errorf("tunnel_tls: fingerprint or ca_file is required (insecure_skip_verify is for development only)")
		}
		if cfg.TunnelTLS.Fingerprint != "" {
			if _, err := cert.ParseFingerprint(cfg.TunnelTLS.Fingerprint); err != nil {
				return fmt.Errorf("tunnel_tls.fingerprint: %w", err)
			}
		}
	}
	if err := validateLog(cfg.LogLevel, cfg.LogFormat); err != nil {
		return err
	}
	if cfg.UIListen != "" {
		if err := validateListen(cfg.UIListen); err != nil {
			return fmt.Errorf("ui_listen: %w", err)
		}
	}
	return ValidateServices(cfg.Services)
}

// ValidateServices normalizes path prefixes and rejects unsafe or overlapping
// routes. It mutates services in place and is shared by config loading and the
// local editor UI.
func ValidateServices(services []Service) error {
	if len(services) == 0 {
		return fmt.Errorf("at least one service is required")
	}
	if len(services) > 128 {
		return fmt.Errorf("too many services (max 128)")
	}
	names := make(map[string]bool, len(services))
	prefixes := make([]string, 0, len(services))
	for i := range services {
		s := &services[i]
		if err := validateName(s.Name, 64); err != nil {
			return fmt.Errorf("services[%d].name: %w", i, err)
		}
		if names[s.Name] {
			return fmt.Errorf("duplicate service name %q", s.Name)
		}
		names[s.Name] = true
		p, err := pathutil.NormalizePrefix(s.PathPrefix)
		if err != nil {
			return fmt.Errorf("services[%d].path_prefix: %w", i, err)
		}
		s.PathPrefix = p
		for _, other := range prefixes {
			if pathutil.Overlap(p, other) {
				return fmt.Errorf("path_prefix %q overlaps with %q", p, other)
			}
		}
		prefixes = append(prefixes, p)
		if err := validateHostPort(s.Target); err != nil {
			return fmt.Errorf("services[%d].target: %w", i, err)
		}
	}
	return nil
}

func validateLog(level, format string) error {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("log_level: unsupported value %q", level)
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text", "json":
	default:
		return fmt.Errorf("log_format: unsupported value %q", format)
	}
	return nil
}

func validateHostPort(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("must be host:port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateListen(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("must be host:port: %w", err)
	}
	_ = host
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	return nil
}

func validateName(s string, max int) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > max {
		return fmt.Errorf("is too long (max %d)", max)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("contains unsupported character %q", r)
		}
	}
	return nil
}

func decode(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("decode config %s: unexpected trailing data", path)
	}
	return nil
}

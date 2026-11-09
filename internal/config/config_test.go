package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadServerDefaults(t *testing.T) {
	path := writeTemp(t, "server.json", `{"token":"0123456789abcdef"}`)
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.PublicListen != "0.0.0.0:8080" {
		t.Errorf("public_listen = %q", cfg.PublicListen)
	}
	if cfg.AdminListen != "127.0.0.1:7002" {
		t.Errorf("admin_listen = %q", cfg.AdminListen)
	}
	if !cfg.TunnelTLS.IsEnabled() {
		t.Error("tunnel TLS should default to enabled")
	}
	if cfg.MaxConnsPerService != 64 {
		t.Errorf("max_conns_per_service = %d", cfg.MaxConnsPerService)
	}
	if cfg.TokenValue != "0123456789abcdef" {
		t.Errorf("token = %q", cfg.TokenValue)
	}
}

func TestLoadServerRejectsBadConfig(t *testing.T) {
	cases := map[string]string{
		"short token":   `{"token":"short"}`,
		"bad listen":    `{"token":"0123456789abcdef","public_listen":"nonsense"}`,
		"same admin":    `{"token":"0123456789abcdef","public_listen":"127.0.0.1:8080","admin_listen":"127.0.0.1:8080"}`,
		"unknown field": `{"token":"0123456789abcdef","nope":true}`,
		"bad log level": `{"token":"0123456789abcdef","log_level":"verbose"}`,
		"missing token": `{}`,
	}
	for name, body := range cases {
		path := writeTemp(t, "server.json", body)
		if _, err := LoadServer(path); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadAgentDefaultsAndValidation(t *testing.T) {
	body := `{
	  "server": "c.example.com:8080",
	  "token": "0123456789abcdef",
	  "tunnel_tls": {"fingerprint": "sha256:` + strings.Repeat("a", 64) + `"},
	  "services": [
	    {"name": "higobase", "path_prefix": "/higobase-admin/", "target": "127.0.0.1:8080"}
	  ]
	}`
	path := writeTemp(t, "agent.json", body)
	cfg, err := LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if cfg.AgentID == "" {
		t.Error("agent_id should default to the hostname")
	}
	if cfg.Services[0].PathPrefix != "/higobase-admin" {
		t.Errorf("path_prefix = %q", cfg.Services[0].PathPrefix)
	}
	if cfg.TunnelTLS.ServerName != "c.example.com" {
		t.Errorf("server_name = %q", cfg.TunnelTLS.ServerName)
	}
}

func TestLoadAgentRejectsBadConfig(t *testing.T) {
	base := `"server":"c.example.com:8080","token":"0123456789abcdef",
		"tunnel_tls":{"fingerprint":"sha256:` + strings.Repeat("a", 64) + `"}`
	cases := map[string]string{
		"no services":     `{` + base + `,"services":[]}`,
		"overlap":         `{` + base + `,"services":[{"name":"a","path_prefix":"/a","target":"127.0.0.1:1"},{"name":"b","path_prefix":"/a/b","target":"127.0.0.1:2"}]}`,
		"reserved prefix": `{` + base + `,"services":[{"name":"a","path_prefix":"/_cproxy","target":"127.0.0.1:1"}]}`,
		"bad target":      `{` + base + `,"services":[{"name":"a","path_prefix":"/a","target":"nope"}]}`,
		"duplicate name":  `{` + base + `,"services":[{"name":"a","path_prefix":"/a","target":"127.0.0.1:1"},{"name":"a","path_prefix":"/b","target":"127.0.0.1:2"}]}`,
		"no tls pin":      `{"server":"c.example.com:8080","token":"0123456789abcdef","services":[{"name":"a","path_prefix":"/a","target":"127.0.0.1:1"}]}`,
		"bad fingerprint": `{"server":"c.example.com:8080","token":"0123456789abcdef","tunnel_tls":{"fingerprint":"xyz"},"services":[{"name":"a","path_prefix":"/a","target":"127.0.0.1:1"}]}`,
	}
	for name, body := range cases {
		path := writeTemp(t, "agent.json", body)
		if _, err := LoadAgent(path); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAgentUIListen(t *testing.T) {
	base := `"server":"c.example.com:8080","token":"0123456789abcdef",
		"tunnel_tls":{"fingerprint":"sha256:` + strings.Repeat("a", 64) + `"},
		"services":[{"name":"a","path_prefix":"/a","target":"127.0.0.1:1"}]`

	path := writeTemp(t, "agent.json", `{`+base+`}`)
	cfg, err := LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if cfg.UIListen != "127.0.0.1:7100" {
		t.Errorf("ui_listen default = %q", cfg.UIListen)
	}

	path = writeTemp(t, "agent.json", `{"ui_listen":"off",`+base+`}`)
	cfg, err = LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent(off): %v", err)
	}
	if cfg.UIListen != "" {
		t.Errorf("ui_listen = %q, want empty", cfg.UIListen)
	}

	path = writeTemp(t, "agent.json", `{"ui_listen":"nonsense",`+base+`}`)
	if _, err := LoadAgent(path); err == nil {
		t.Error("invalid ui_listen was accepted")
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("file-token-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, "server.json", `{"token_file":"`+strings.ReplaceAll(tokFile, `\`, `\\`)+`"}`)
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.TokenValue != "file-token-0123456789" {
		t.Errorf("token = %q", cfg.TokenValue)
	}
}

func TestEnvTokenOverrides(t *testing.T) {
	t.Setenv("CPROXY_TOKEN", "env-token-0123456789")
	path := writeTemp(t, "server.json", `{"token":"file-token-0123456789"}`)
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.TokenValue != "env-token-0123456789" {
		t.Errorf("token = %q, want the environment value", cfg.TokenValue)
	}
}

// Command cproxy is a single-port HTTP reverse tunnel.
//
//	cproxy server   -f server.json    run the public proxy (host c)
//	cproxy agent    -f agent.json     run the tunnel client (host a)
//	cproxy gen-token                  print a new 256-bit agent token
//	cproxy check    -f config.json    validate a configuration file
//	cproxy version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"cproxy/internal/agent"
	"cproxy/internal/cert"
	"cproxy/internal/config"
	"cproxy/internal/logging"
	"cproxy/internal/server"
	"cproxy/internal/token"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "gen-token":
		err = runGenToken()
	case "check":
		err = runCheck(os.Args[2:])
	case "fingerprint":
		err = runFingerprint(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("cproxy", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cproxy %s - single-port HTTP reverse tunnel

Usage:
  cproxy server -f server.json     run the public proxy
  cproxy agent  -f agent.json      run the tunnel client
  cproxy check  -f config.json     validate a configuration file
  cproxy fingerprint -c tunnel.crt print a certificate pin for agent.json
  cproxy gen-token                 print a new agent token
  cproxy version
`, version)
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	cfgPath := fs.String("f", "server.json", "server configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return err
	}
	logger, err := logging.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	cfgPath := fs.String("f", "agent.json", "agent configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadAgent(*cfgPath)
	if err != nil {
		return err
	}
	logger, err := logging.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	ag, err := agent.New(cfg, *cfgPath, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return ag.Run(ctx)
}

func runFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	certPath := fs.String("c", "", "PEM certificate file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return errors.New("fingerprint requires -c <certificate.pem>")
	}
	fp, err := cert.FingerprintFile(*certPath)
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

func runGenToken() error {
	t, err := token.Generate()
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("f", "", "configuration file")
	kind := fs.String("type", "auto", "config type: server, agent, or auto")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("check requires -f <config.json>")
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if *kind == "auto" {
		if _, ok := probe["services"]; ok {
			*kind = "agent"
		} else {
			*kind = "server"
		}
	}
	switch *kind {
	case "server":
		cfg, err := config.LoadServer(*cfgPath)
		if err != nil {
			return err
		}
		fmt.Println("server configuration is valid")
		fmt.Printf("  public_listen: %s\n  admin_listen: %s\n  tunnel_tls: %v\n",
			cfg.PublicListen, cfg.AdminListen, cfg.TunnelTLS.IsEnabled())
	case "agent":
		cfg, err := config.LoadAgent(*cfgPath)
		if err != nil {
			return err
		}
		fmt.Println("agent configuration is valid")
		fmt.Printf("  server: %s\n  agent_id: %s\n", cfg.Server, cfg.AgentID)
		for _, svc := range cfg.Services {
			fmt.Printf("  service %s: %s -> %s (strip_prefix=%v)\n",
				svc.Name, svc.PathPrefix, svc.Target, svc.StripPrefix)
		}
	default:
		return fmt.Errorf("unknown config type %q", *kind)
	}
	return nil
}

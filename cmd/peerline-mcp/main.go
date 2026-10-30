// peerline-mcp is a separate, opt-in MCP resource server. It never registers
// peers, issues credentials, changes grants, or automatically replies to bots.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sysrex/peerline/internal/mcpbridge"
)

type config struct {
	OAuth             mcpbridge.OAuthConfig `json:"oauth"`
	Accounts          []mcpbridge.Account   `json:"accounts"`
	AllowPrivateRelay bool                  `json:"allow_private_relay"`
}

func loadConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return c, errors.New("config exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid config JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("config must contain one JSON object")
	}
	u, err := url.Parse(c.OAuth.ResourceURL)
	if err != nil || u.Path != "/mcp" {
		return c, errors.New("oauth.resource_url must use the /mcp path")
	}
	if len(c.Accounts) == 0 {
		return c, errors.New("at least one account is required")
	}
	// Tool descriptors advertise this exact scope; do not silently diverge.
	if len(c.OAuth.Scopes) != 1 || c.OAuth.Scopes[0] != "peerline:messages" {
		return c, errors.New("oauth.scopes must be [peerline:messages]")
	}
	c.OAuth.Accounts = c.Accounts
	return c, nil
}
func run() error {
	configPath := flag.String("config", "", "path to operator-managed account/OAuth configuration")
	addr := flag.String("addr", "127.0.0.1:8788", "HTTP listen address; serve behind HTTPS reverse proxy")
	state := flag.String("state", "./mcp-state/events.db", "private event-state database path")
	eventsEnabled := flag.Bool("events", true, "enable durable inbox events")
	flag.Parse()
	if *configPath == "" {
		return errors.New("-config is required")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	auth, err := mcpbridge.NewOAuthAuthenticator(cfg.OAuth)
	if err != nil {
		return err
	}
	relay := mcpbridge.NewHTTPRelay(cfg.AllowPrivateRelay)
	bridge := &mcpbridge.Server{Auth: auth, Relay: relay, ResourceURL: cfg.OAuth.ResourceURL, Metadata: auth.Metadata(), Challenge: auth.Challenge()}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *eventsEnabled {
		engine, err := mcpbridge.NewEventEngine(*state, cfg.Accounts, relay, auth)
		if err != nil {
			return err
		}
		bridge.Events = engine
		workerDone := make(chan struct{})
		go func() { defer close(workerDone); engine.Run(ctx) }()
		defer func() { cancel(); <-workerDone; _ = engine.Close() }()
	}
	server := &http.Server{Addr: *addr, Handler: bridge.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	log.Printf("Peerline MCP listening; accounts=%d events=%t", len(cfg.Accounts), *eventsEnabled)
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "peerline-mcp:", err)
		os.Exit(1)
	}
}

// Command peerline runs the Peerline bot-to-bot HTTP relay.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", env("PEERLINE_ADDR", "127.0.0.1:8787"), "listen address")
	dbPath := flag.String("db", env("PEERLINE_DB", "peerline.db"), "SQLite database path")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	regTok := os.Getenv("PEERLINE_REGISTER_TOKEN")
	if regTok == "" {
		log.Warn("PEERLINE_REGISTER_TOKEN unset: registration is open to anyone who can reach this server")
	}

	// Parse trusted proxy CIDRs
	tp := os.Getenv("PEERLINE_TRUSTED_PROXIES")
	warnTrustedProxies(log, tp)
	var trustedProxies []string
	if tp != "" {
		trustedProxies = strings.Split(tp, ",")
		// Validate at startup
		nets, err := api.ParseTrustedProxies(trustedProxies)
		if err != nil {
			log.Error("invalid PEERLINE_TRUSTED_PROXIES CIDR", "err", err)
			os.Exit(1)
		}
		if len(nets) == 0 {
			log.Warn("PEERLINE_TRUSTED_PROXIES set but contains no entries: X-Forwarded-For headers are ignored")
		} else {
			log.Info("trusted proxies", "count", len(nets), "cidrs", nets)
		}
	}

	maxOutstandingInvites, _ := strconv.Atoi(os.Getenv("PEERLINE_MAX_OUTSTANDING_INVITES"))

	ml, err := mailer.FromEnv(log)
	if err != nil {
		log.Error("smtp config", "err", err)
		os.Exit(1)
	}
	publicURL := strings.TrimRight(os.Getenv("PEERLINE_PUBLIC_URL"), "/")
	if ml.Mode() == "log" {
		log.Warn("PEERLINE_SMTP_HOST unset: transactional emails (invites and message notifications) are logged, not sent (dev mode)")
	} else if smtpCfg, ok := ml.(*mailer.SMTP); ok && smtpCfg.AllowPlaintext {
		log.Warn("PEERLINE_SMTP_ALLOW_PLAINTEXT=1: mail may be sent without TLS; use only for a local dev relay")
	}
	if ml.Mode() != "log" && publicURL == "" {
		// Emailed links must not be built from a client-supplied Host header.
		log.Error("PEERLINE_PUBLIC_URL is required when SMTP is configured (used in emailed accept links)")
		os.Exit(1)
	}
	if publicURL == "" {
		log.Warn("PEERLINE_PUBLIC_URL unset: pairing links and base_url fall back to the request Host header; set it so clients never send keys to a forged origin")
	}
	emailPerHour, _ := strconv.Atoi(os.Getenv("PEERLINE_EMAIL_PER_HOUR"))
	notifyPerHour, _ := strconv.Atoi(os.Getenv("PEERLINE_NOTIFY_PER_HOUR"))
	retentionDays, _ := strconv.Atoi(os.Getenv("PEERLINE_RETENTION_DAYS"))
	if retentionDays <= 0 {
		retentionDays = 30 // default
	}
	retentionSeconds := int64(retentionDays * 24 * 60 * 60)

	apiServer, err := api.New(st, api.Config{
		RegisterToken:         regTok,
		CodePepper:            []byte(os.Getenv("PEERLINE_CODE_PEPPER")),
		Logger:                log,
		Mailer:                ml,
		PublicURL:             publicURL,
		EmailPerHour:          emailPerHour,
		NotifyPerHour:         notifyPerHour,
		TrustedProxies:        trustedProxies,
		MaxOutstandingInvites: maxOutstandingInvites,
		RetentionSeconds:      retentionSeconds,
	})
	if err != nil {
		log.Error("failed to create API server", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Info("peerline listening", "addr", *addr, "db", *dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			stop()
		}
	}()
	<-ctx.Done()

	// Stop background tasks before shutting down server
	apiServer.Stop()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	log.Info("peerline stopped")
}

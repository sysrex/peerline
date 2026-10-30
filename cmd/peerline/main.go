// Command peerline runs the Peerline bot-to-bot HTTP relay.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
	"github.com/sysrex/peerline/internal/version"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseInt parses an env var as int, returning an error if set but non-numeric.
// Returns (0, nil) if unset (caller provides default).
func parseInt(val, name string) (int, error) {
	if val == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, errors.New(name + " must be numeric, got: " + val)
	}
	return n, nil
}

// parseVersionDetail validates and normalizes PEERLINE_VERSION_DETAIL.
// Accepts "minimal", "full", or "off" (case-insensitive, whitespace-trimmed).
// Returns an error for any other value to fail-closed on typos.
func parseVersionDetail(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "minimal", "full", "off":
		return normalized, nil
	default:
		return "", fmt.Errorf("must be 'minimal', 'full', or 'off', got: %q", raw)
	}
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	addr := flag.String("addr", env("PEERLINE_ADDR", "127.0.0.1:8787"), "listen address")
	dbPath := flag.String("db", env("PEERLINE_DB", "peerline.db"), "SQLite database path")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("peerline starting", "version", version.String())
	if version.NeedsAttention() {
		log.Warn("version information incomplete", "commit", version.Info()["commit"])
	}

	// Validate PEERLINE_VERSION_DETAIL at startup (fail closed on typos)
	versionDetail, err := parseVersionDetail(env("PEERLINE_VERSION_DETAIL", "minimal"))
	if err != nil {
		log.Error("invalid PEERLINE_VERSION_DETAIL value; must be 'minimal', 'full', or 'off'", "value", env("PEERLINE_VERSION_DETAIL", ""))
		os.Exit(1)
	}

	// Parse backup environment variables
	skipBackup := os.Getenv("PEERLINE_SKIP_MIGRATION_BACKUP") == "1"
	backupDir := os.Getenv("PEERLINE_BACKUP_DIR")
	backupKeep := 3

	if keepEnv := os.Getenv("PEERLINE_BACKUP_KEEP"); keepEnv != "" {
		if n, err := strconv.Atoi(keepEnv); err == nil {
			if n >= 1 {
				backupKeep = n
			} else {
				log.Warn("PEERLINE_BACKUP_KEEP must be >= 1, using default", "invalid_value", keepEnv, "default", 3)
			}
		} else {
			log.Warn("PEERLINE_BACKUP_KEEP must be a number, using default", "invalid_value", keepEnv, "default", 3)
		}
	}

	if skipBackup {
		log.Warn("PEERLINE_SKIP_MIGRATION_BACKUP is enabled, pre-migration backups are disabled")
	}

	// Open database with explicit options
	opts := store.OpenOptions{
		SkipMigrationBackup:  skipBackup,
		BackupDir:            backupDir,
		BackupRetentionCount: backupKeep,
		Logger:               log,
	}

	st, err := store.OpenWithOptions(*dbPath, opts)
	if err != nil {
		// Check for schema-too-new error and exit with distinct code
		var tooNewErr *store.ErrSchemaTooNew
		if errors.As(err, &tooNewErr) {
			log.Error("database schema version is too new for this binary", "err", err)
			os.Exit(2)
		}
		// Check for schema-invalid error
		var invalidErr *store.ErrSchemaInvalid
		if errors.As(err, &invalidErr) {
			log.Error("database schema version is invalid", "err", err)
			os.Exit(1)
		}
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Log schema version, max supported, and backup info on startup
	backupInfo := "none needed"
	if bp := st.LastBackupPath(); bp != "" {
		if st.BackupReused() {
			backupInfo = "reused " + bp
		} else {
			backupInfo = bp
		}
	} else if skipBackup {
		backupInfo = "skipped (opt-out)"
	}
	dbBase := filepath.Base(*dbPath)
	log.Info("database opened",
		"db", dbBase,
		"schema_version", st.SchemaVersionInUse(),
		"max_supported", store.SchemaVersion(),
		"backup", backupInfo)

	// Load key index at startup (#112)
	keyIndexWarn, _ := strconv.Atoi(os.Getenv("PEERLINE_KEY_INDEX_WARN"))
	if keyIndexWarn <= 0 {
		keyIndexWarn = 1_000_000
	}
	n, dur, err := st.LoadKeyIndex(context.Background())
	if err != nil {
		log.Error("load key index", "err", err)
		os.Exit(1)
	}
	log.Info("key index loaded", "keys", n, "duration_ms", dur.Milliseconds())
	if n >= keyIndexWarn {
		log.Warn("key index size exceeds PEERLINE_KEY_INDEX_WARN", "keys", n, "warn_threshold", keyIndexWarn)
	}

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
	} else if smtp, ok := ml.(*mailer.SMTP); ok {
		// Probe SMTP server at startup to fail fast if TLS is misconfigured.
		// Network errors (connection refused, timeout) only warn; Send retries at runtime.
		if err := smtp.Probe(context.Background(), log); err != nil {
			if errors.Is(err, mailer.ErrRelayUnreachable) {
				log.Warn("smtp relay unreachable at startup (will retry on send)", "host", smtp.Host, "port", smtp.Port, "err", err)
			} else {
				log.Error("smtp probe failed: TLS misconfiguration", "err", err)
				os.Exit(1)
			}
		}
		// Log TLS mode at startup
		var tlsMode string
		if smtp.ImplicitTLS {
			tlsMode = "implicit TLS (port 465)"
		} else if smtp.AllowPlaintext {
			tlsMode = "STARTTLS optional (plaintext allowed)"
			if !mailer.IsLoopback(smtp.Host) {
				log.Warn("SMTP configured with plaintext allowed to non-loopback relay; invite codes and message previews are not protected in transit", "host", smtp.Host, "port", smtp.Port)
			}
		} else {
			tlsMode = "STARTTLS required"
		}
		log.Info("SMTP configured", "host", smtp.Host, "port", smtp.Port, "tls", tlsMode, "authenticated", smtp.User != "")
	}
	if publicURL == "" {
		log.Warn("PEERLINE_PUBLIC_URL unset: pairing links and base_url fall back to the request Host header; set it so clients never send keys to a forged origin")
	}
	emailPerHour, _ := strconv.Atoi(os.Getenv("PEERLINE_EMAIL_PER_HOUR"))
	notifyPerHour, _ := strconv.Atoi(os.Getenv("PEERLINE_NOTIFY_PER_HOUR"))

	maxBagsPerPeer, maxBagBytesPerPeer, err := parseBagLimits(
		os.Getenv("PEERLINE_MAX_BAGS_PER_PEER"),
		os.Getenv("PEERLINE_MAX_BAG_BYTES_PER_PEER"),
	)
	if err != nil {
		log.Error("invalid bag limit configuration", "err", err)
		os.Exit(1)
	}

	retentionDays, _ := strconv.Atoi(os.Getenv("PEERLINE_RETENTION_DAYS"))
	if retentionDays <= 0 {
		retentionDays = 30 // default
	}
	retentionSeconds := int64(retentionDays * 24 * 60 * 60)

	keyIndexRebuildHours, _ := strconv.Atoi(os.Getenv("PEERLINE_KEY_INDEX_REBUILD_HOURS"))
	if keyIndexRebuildHours <= 0 {
		keyIndexRebuildHours = 6 // default
	}

	// Parse rate limiter config (#96: validate at startup)
	authFailPerMinute, err := parseInt(os.Getenv("PEERLINE_AUTH_FAIL_PER_MINUTE"), "PEERLINE_AUTH_FAIL_PER_MINUTE")
	if err != nil {
		log.Error("invalid rate limiter config", "err", err)
		os.Exit(1)
	}
	authFailBurst, err := parseInt(os.Getenv("PEERLINE_AUTH_FAIL_BURST"), "PEERLINE_AUTH_FAIL_BURST")
	if err != nil {
		log.Error("invalid rate limiter config", "err", err)
		os.Exit(1)
	}
	writePerMinute, err := parseInt(os.Getenv("PEERLINE_WRITE_PER_MINUTE"), "PEERLINE_WRITE_PER_MINUTE")
	if err != nil {
		log.Error("invalid rate limiter config", "err", err)
		os.Exit(1)
	}
	writeBurst, err := parseInt(os.Getenv("PEERLINE_WRITE_BURST"), "PEERLINE_WRITE_BURST")
	if err != nil {
		log.Error("invalid rate limiter config", "err", err)
		os.Exit(1)
	}

	log.Info("rate limiter config",
		"auth_fail_per_minute", authFailPerMinute,
		"auth_fail_burst", authFailBurst,
		"write_per_minute", writePerMinute,
		"write_burst", writeBurst)

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
		AuthFailPerMinute:     authFailPerMinute,
		AuthFailBurst:         authFailBurst,
		WritePerMinute:        writePerMinute,
		WriteBurst:            writeBurst,
		KeyIndexRebuildHours:  keyIndexRebuildHours,
		VersionDetail:         versionDetail,
		MaxBagsPerPeer:        maxBagsPerPeer,
		MaxBagBytesPerPeer:    maxBagBytesPerPeer,
	})
	if err != nil {
		log.Error("failed to create API server", "err", err)
		os.Exit(1)
	}

	maxBags, maxBytes := apiServer.BagLimits()
	log.Info("bag storage caps", "max_bags_per_peer", maxBags, "max_bag_bytes_per_peer", maxBytes)

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

func parseBagLimits(bagsStr, bytesStr string) (int, int64, error) {
	maxBags, err := parseNonNegativeInt(bagsStr)
	if err != nil {
		return 0, 0, fmt.Errorf("PEERLINE_MAX_BAGS_PER_PEER: %w", err)
	}
	maxBytes, err := parseNonNegativeInt64(bytesStr)
	if err != nil {
		return 0, 0, fmt.Errorf("PEERLINE_MAX_BAG_BYTES_PER_PEER: %w", err)
	}
	return maxBags, maxBytes, nil
}

func parseNonNegativeInt(s string) (int, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if v < 0 {
		return 0, errors.New("must be non-negative")
	}
	return v, nil
}

func parseNonNegativeInt64(s string) (int64, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if v < 0 {
		return 0, errors.New("must be non-negative")
	}
	return v, nil
}

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
	"github.com/sysrex/peerline/internal/clock"
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

// parseNonNegativeInt parses an env var as a non-negative int (>= 0), returning an error if set but non-numeric or negative.
// Returns (0, nil) if unset or "0" (caller applies default downstream).
// Upper bound is checked if max > 0.
func parseNonNegativeInt(val, name string, max int) (int, error) {
	if val == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("%s is out of range: %s", name, val)
		}
		return 0, fmt.Errorf("%s must be numeric, got: %s", name, val)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must be non-negative, got: %d", name, n)
	}
	if max > 0 && n > max {
		return 0, fmt.Errorf("%s must be <= %d, got: %d", name, max, n)
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

// parseBoolStrict validates boolean environment variables strictly.
// Accepts: "", "0", "false" (false) or "1", "true" (true), case-insensitive, whitespace-trimmed.
// Returns an error for any other value to fail-closed on typos.
func parseBoolStrict(raw string) (bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("must be '0', '1', 'false', or 'true', got: %q", raw)
	}
}

// describeTLSMode returns a human-readable description of the SMTP TLS mode.
func describeTLSMode(smtp *mailer.SMTP) string {
	if smtp.ImplicitTLS {
		return "implicit TLS (port 465)"
	} else if smtp.AllowPlaintext {
		return "STARTTLS optional (plaintext allowed)"
	}
	return "STARTTLS required"
}

// buildTrustedProxySettings extracts and validates trusted proxy configuration from environment.
// It parses PEERLINE_TRUSTED_PROXIES and PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD exactly once,
// validates CIDRs (rejecting malformed entries and entries that are too broad for the opt-in setting),
// emits startup warnings, and returns the values. Called from main before mailer.FromEnv.
func buildTrustedProxySettings(getenv func(string) string, log *slog.Logger) (proxies []string, allowBroad bool, err error) {
	tp := getenv("PEERLINE_TRUSTED_PROXIES")
	allowBroad, err = parseBoolStrict(getenv("PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD"))
	if err != nil {
		return nil, false, fmt.Errorf("invalid PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD value: %w", err)
	}

	// Warn if opt-in is enabled but no proxies configured
	if allowBroad && tp == "" {
		log.Warn("PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled but PEERLINE_TRUSTED_PROXIES is unset; the opt-in has no effect")
	}

	if tp != "" {
		proxies = strings.Split(tp, ",")
		// Validate CIDRs before mailer and SMTP probe to fail fast on typos or broad ranges
		_, _, err = api.ParseTrustedProxiesWithOpts(proxies, allowBroad)
		if err != nil {
			return nil, false, fmt.Errorf("invalid PEERLINE_TRUSTED_PROXIES: %w", err)
		}
	}
	return proxies, allowBroad, nil
}

// parseStartupLimits parses KEY_INDEX_WARN and RETENTION_DAYS from environment.
// Returns (0, 0, nil) for unset/zero values (caller applies defaults).
func parseStartupLimits(getenv func(string) string) (keyIndexWarn, retentionDays int, err error) {
	keyIndexWarn, err = parseNonNegativeInt(getenv("PEERLINE_KEY_INDEX_WARN"), "PEERLINE_KEY_INDEX_WARN", 0)
	if err != nil {
		return 0, 0, err
	}
	retentionDays, err = parseNonNegativeInt(getenv("PEERLINE_RETENTION_DAYS"), "PEERLINE_RETENTION_DAYS", 36500)
	if err != nil {
		return 0, 0, err
	}
	return keyIndexWarn, retentionDays, nil
}

// buildAPIConfig constructs the api.Config that main() passes to api.New.
// It parses all environment variables, validates them, and returns the exact config.
// Called once from main(); the returned config is passed verbatim to api.New with no field assignments in between.
func buildAPIConfig(getenv func(string) string, clk clock.Clock, ml mailer.Sender, versionDetail, publicURL string, maxBagsPerPeer int, maxBagBytesPerPeer, retentionSeconds int64, trustedProxies []string, allowBroadIPv6 bool, logger *slog.Logger) (api.Config, error) {

	regTok := getenv("PEERLINE_REGISTER_TOKEN")
	maxOutstandingInvites, err := parseNonNegativeInt(getenv("PEERLINE_MAX_OUTSTANDING_INVITES"), "PEERLINE_MAX_OUTSTANDING_INVITES", 0)
	if err != nil {
		return api.Config{}, err
	}
	emailPerHour, err := parseNonNegativeInt(getenv("PEERLINE_EMAIL_PER_HOUR"), "PEERLINE_EMAIL_PER_HOUR", 0)
	if err != nil {
		return api.Config{}, err
	}
	notifyPerHour, err := parseNonNegativeInt(getenv("PEERLINE_NOTIFY_PER_HOUR"), "PEERLINE_NOTIFY_PER_HOUR", 0)
	if err != nil {
		return api.Config{}, err
	}
	keyIndexRebuildHours, err := parseNonNegativeInt(getenv("PEERLINE_KEY_INDEX_REBUILD_HOURS"), "PEERLINE_KEY_INDEX_REBUILD_HOURS", 8760)
	if err != nil {
		return api.Config{}, err
	}
	if keyIndexRebuildHours <= 0 {
		keyIndexRebuildHours = 6 // default
	}

	// Parse rate limiter config
	authFailPerMinute, err := parseInt(getenv("PEERLINE_AUTH_FAIL_PER_MINUTE"), "PEERLINE_AUTH_FAIL_PER_MINUTE")
	if err != nil {
		return api.Config{}, err
	}
	authFailBurst, err := parseInt(getenv("PEERLINE_AUTH_FAIL_BURST"), "PEERLINE_AUTH_FAIL_BURST")
	if err != nil {
		return api.Config{}, err
	}
	writePerMinute, err := parseInt(getenv("PEERLINE_WRITE_PER_MINUTE"), "PEERLINE_WRITE_PER_MINUTE")
	if err != nil {
		return api.Config{}, err
	}
	writeBurst, err := parseInt(getenv("PEERLINE_WRITE_BURST"), "PEERLINE_WRITE_BURST")
	if err != nil {
		return api.Config{}, err
	}

	return api.Config{
		RegisterToken:         regTok,
		CodePepper:            []byte(getenv("PEERLINE_CODE_PEPPER")),
		Logger:                logger,
		Mailer:                ml,
		PublicURL:             publicURL,
		EmailPerHour:          emailPerHour,
		NotifyPerHour:         notifyPerHour,
		TrustedProxies:        trustedProxies,
		AllowBroadIPv6:        allowBroadIPv6,
		Clock:                 clk,
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
	}, nil
}

// describeSMTPMode returns the log level and message for SMTP startup logging.
// Returns WARN for non-loopback non-implicit-TLS relays with plaintext allowed (invite codes unprotected in transit),
// INFO otherwise.
func describeSMTPMode(smtp *mailer.SMTP) (slog.Level, string) {
	if !smtp.ImplicitTLS && smtp.AllowPlaintext && !mailer.IsLoopback(smtp.Host) {
		return slog.LevelWarn, "SMTP configured with plaintext allowed to non-loopback relay; invite codes and message previews are not protected in transit"
	}
	return slog.LevelInfo, "SMTP configured"
}

// smtpProbeAction decides whether a probe error should be fatal (exit 1) or a warning.
// Returns (fatal=true, level, message) for config errors; (fatal=false, level, message) for transient errors.
func smtpProbeAction(err error) (fatal bool, level slog.Level, message string) {
	if err == nil {
		return false, slog.LevelInfo, ""
	}
	if errors.Is(err, mailer.ErrRelayUnreachable) {
		return false, slog.LevelWarn, "smtp relay unreachable at startup (will retry on send)"
	}
	return true, slog.LevelError, "smtp probe failed: configuration error"
}

func main() {
	// Set restrictive umask on Unix platforms (0600 for files, 0700 for directories)
	setRestrictiveUmask()

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
	backupTimeout := 5 * time.Minute // Default: 5 minutes

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

	if timeoutEnv := os.Getenv("PEERLINE_BACKUP_TIMEOUT"); timeoutEnv != "" {
		if n, err := strconv.Atoi(timeoutEnv); err == nil {
			if n > 0 {
				backupTimeout = time.Duration(n) * time.Second
			} else {
				log.Warn("PEERLINE_BACKUP_TIMEOUT must be > 0, using default", "invalid_value", timeoutEnv, "default_seconds", 300)
			}
		} else {
			log.Warn("PEERLINE_BACKUP_TIMEOUT must be a number (seconds), using default", "invalid_value", timeoutEnv, "default_seconds", 300)
		}
	}

	if skipBackup {
		log.Warn("PEERLINE_SKIP_MIGRATION_BACKUP is enabled, pre-migration backups are disabled")
	}

	// Open database with explicit options
	clk := clock.Real{}
	opts := store.OpenOptions{
		SkipMigrationBackup:  skipBackup,
		BackupDir:            backupDir,
		BackupRetentionCount: backupKeep,
		BackupTimeout:        backupTimeout,
		Logger:               log,
		Clock:                clk,
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

	// Parse startup limits (KEY_INDEX_WARN, RETENTION_DAYS)
	keyIndexWarn, retentionDays, err := parseStartupLimits(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if keyIndexWarn <= 0 {
		keyIndexWarn = 1_000_000
	}
	if retentionDays <= 0 {
		retentionDays = 30 // default
	}
	retentionSeconds := int64(retentionDays * 24 * 60 * 60)

	// Load key index at startup (#112)
	n, dur, err := st.LoadKeyIndex(context.Background())
	if err != nil {
		log.Error("load key index", "err", err)
		os.Exit(1)
	}
	log.Info("key index loaded", "keys", n, "duration_ms", dur.Milliseconds())
	if n >= keyIndexWarn {
		log.Warn("key index size exceeds PEERLINE_KEY_INDEX_WARN", "keys", n, "warn_threshold", keyIndexWarn)
	}

	// Parse trusted proxy config before SMTP probe (fail-fast on typos)
	trustedProxies, allowBroadIPv6, err := buildTrustedProxySettings(os.Getenv, log)
	if err != nil {
		log.Error("trusted proxy config", "err", err)
		os.Exit(1)
	}

	regTok := os.Getenv("PEERLINE_REGISTER_TOKEN")
	if regTok == "" {
		log.Warn("PEERLINE_REGISTER_TOKEN unset: registration is open to anyone who can reach this server")
	}

	ml, err := mailer.FromEnv(log)
	if err != nil {
		log.Error("smtp config", "err", err)
		os.Exit(1)
	}
	if err := checkLogBody(log, ml, *addr); err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	publicURL := strings.TrimRight(os.Getenv("PEERLINE_PUBLIC_URL"), "/")
	if ml.Mode() == "log" {
		log.Warn("PEERLINE_SMTP_HOST unset: transactional emails (invites and message notifications) are logged, not sent (dev mode)")
	}
	if ml.Mode() != "log" && publicURL == "" {
		// Emailed links must not be built from a client-supplied Host header.
		log.Error("PEERLINE_PUBLIC_URL is required when SMTP is configured (used in emailed accept links)")
		os.Exit(1)
	} else if smtp, ok := ml.(*mailer.SMTP); ok {
		// Probe SMTP server at startup to fail fast if TLS is misconfigured.
		// Network errors (connection refused, timeout) only warn; Send retries at runtime.
		probeErr := smtp.Probe(context.Background())
		fatal, probeLevel, probeMsg := smtpProbeAction(probeErr)
		if probeErr != nil {
			log.Log(context.Background(), probeLevel, probeMsg, "host", smtp.Host, "port", smtp.Port, "err", probeErr)
			if fatal {
				os.Exit(1)
			}
		}
		level, msg := describeSMTPMode(smtp)
		log.Log(context.Background(), level, msg, "host", smtp.Host, "port", smtp.Port, "tls", describeTLSMode(smtp), "authenticated", smtp.User != "")
	}
	if publicURL == "" {
		log.Warn("PEERLINE_PUBLIC_URL unset: pairing links and base_url fall back to the request Host header; set it so clients never send keys to a forged origin")
	}

	maxBagsPerPeer, maxBagBytesPerPeer, err := parseBagLimits(
		os.Getenv("PEERLINE_MAX_BAGS_PER_PEER"),
		os.Getenv("PEERLINE_MAX_BAG_BYTES_PER_PEER"),
	)
	if err != nil {
		log.Error("invalid bag limit configuration", "err", err)
		os.Exit(1)
	}


	if os.Getenv("PEERLINE_CODE_PEPPER") == "" {
		log.Warn("PEERLINE_CODE_PEPPER unset: confirm-mode short codes use a per-process secret, so pending claims cannot be confirmed across a restart")
	}

	// Build api.Config with all parsed environment variables
	cfg, err := buildAPIConfig(os.Getenv, clk, ml, versionDetail, publicURL, maxBagsPerPeer, maxBagBytesPerPeer, retentionSeconds, trustedProxies, allowBroadIPv6, log)
	if err != nil {
		log.Error("api config", "err", err)
		os.Exit(1)
	}

	log.Info("rate limiter config",
		"auth_fail_per_minute", cfg.AuthFailPerMinute,
		"auth_fail_burst", cfg.AuthFailBurst,
		"write_per_minute", cfg.WritePerMinute,
		"write_burst", cfg.WriteBurst)

	apiServer, err := api.New(st, cfg)
	if err != nil {
		log.Error("failed to create API server", "err", err)
		os.Exit(1)
	}

	apiServer.SetClaimStore(st)

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
	maxBags, err := parseNonNegativeInt(bagsStr, "PEERLINE_MAX_BAGS_PER_PEER", 0)
	if err != nil {
		return 0, 0, err
	}
	maxBytes, err := parseNonNegativeInt64(bytesStr)
	if err != nil {
		return 0, 0, fmt.Errorf("PEERLINE_MAX_BAG_BYTES_PER_PEER: %w", err)
	}
	return maxBags, maxBytes, nil
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

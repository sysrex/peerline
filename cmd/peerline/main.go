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
	"path/filepath"
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
		if _, err := api.ParseTrustedProxies(trustedProxies); err != nil {
			log.Error("invalid PEERLINE_TRUSTED_PROXIES CIDR", "err", err)
			os.Exit(1)
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
	} else if publicURL == "" {
		// Emailed links must not be built from a client-supplied Host header.
		log.Error("PEERLINE_PUBLIC_URL is required when SMTP is configured (used in emailed accept links)")
		os.Exit(1)
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

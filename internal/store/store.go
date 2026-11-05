// Package store is the SQLite persistence layer (modernc.org/sqlite, no CGO).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sysrex/peerline/internal/clock"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrSelfPairing = errors.New("cannot pair with self")
var ErrTooManyInvites = errors.New("too many outstanding invites")
var ErrBagLimitExceeded = errors.New("bag limit exceeded")
var ErrStorageQuotaExceeded = errors.New("storage quota exceeded")

// ErrSchemaTooNew is returned when the database schema version is newer than this binary supports.
type ErrSchemaTooNew struct {
	Have int
	Max  int
}

func (e *ErrSchemaTooNew) Error() string {
	return fmt.Sprintf("database schema version %d is newer than this binary supports (max %d); upgrade the peerline binary or restore from backup", e.Have, e.Max)
}

// ErrSchemaInvalid is returned when the database schema version is negative or otherwise invalid.
type ErrSchemaInvalid struct {
	Have int
}

func (e *ErrSchemaInvalid) Error() string {
	return fmt.Sprintf("database schema version %d is invalid (must be >= 0)", e.Have)
}

var memDBCounter uint64

type Store struct {
	db                 *sql.DB
	clk                clock.Clock
	schemaVersionInUse int
	lastBackupPath     string
	backupReused       bool
	keyIndex           *keyIndex
	keyIndexLoaded     bool
}

// nowUnix returns the current Unix timestamp from the store's clock.
func (s *Store) nowUnix() int64 {
	return s.clk.Now().Unix()
}

// migrations is the ordered list of schema migration functions.
// SchemaVersion() returns len(migrations).
var migrations = []func(*sql.Tx) error{
	migrateV1NotifyEmail,
	migrateV2PairingTokenHash,
	migrateV3InvitePublicID,
	migrateV4EmailVerification,
	migrateV5InviteClaimState,
	migrateV6ClaimOffer,
}

// SchemaVersion returns the maximum schema version this binary supports.
func SchemaVersion() int {
	return len(migrations)
}

// SchemaVersionInUse returns the schema version this Store is using.
func (s *Store) SchemaVersionInUse() int {
	return s.schemaVersionInUse
}

// LastBackupPath returns the base name of the last backup created or reused, or "" if none.
func (s *Store) LastBackupPath() string {
	if s.lastBackupPath == "" {
		return ""
	}
	return filepath.Base(s.lastBackupPath)
}

// BackupReused returns true if the last backup was reused from a previous attempt.
func (s *Store) BackupReused() bool {
	return s.backupReused
}

// OpenOptions configures Open behavior.
type OpenOptions struct {
	// SkipMigrationBackup skips the pre-migration VACUUM INTO backup when true.
	// Set via PEERLINE_SKIP_MIGRATION_BACKUP=1 or pass explicitly for tests.
	SkipMigrationBackup bool

	// BackupDir overrides the directory where migration backups are written.
	// Defaults to the database's directory.
	BackupDir string

	// BackupRetentionCount limits the number of migration backups to keep (oldest are deleted).
	// Minimum 1, defaults to 3. Invalid values log a warning and use 3.
	BackupRetentionCount int

	// BackupTimeout is the maximum duration for the VACUUM INTO operation.
	// Defaults to 5 minutes. Set via PEERLINE_BACKUP_TIMEOUT (in seconds).
	BackupTimeout time.Duration

	// Logger for warnings and info messages. Defaults to slog.Default().
	Logger *slog.Logger

	// Clock is an injectable time source for testing. If nil, uses clock.Real{}.
	// Used for invite expiry checks, backup timestamps, and other time-based operations.
	Clock clock.Clock

	// vacuumInto is an injectable hook for testing. If nil, uses db.Exec("VACUUM INTO ?", path).
	vacuumInto func(db *sql.DB, backupPath string) error

	// migrationStepHook is an injectable hook for testing migration step failures.
	// Called before each migration step with (targetVersion, currentVersion). If it returns
	// an error, the step is skipped and the error is returned.
	migrationStepHook func(target, current int) error
}

const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS peers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  notify_email TEXT NOT NULL DEFAULT '',
  notify_email_verified INTEGER NOT NULL DEFAULT 0,
  notify_email_token TEXT
);
CREATE TABLE IF NOT EXISTS invites (
  code_hash TEXT PRIMARY KEY,
  from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  bags TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_by TEXT,
  pairing_token_hash TEXT,
  public_id TEXT
);
-- grants are directional: grantee may act on owner's resources within scopes/bags.
CREATE TABLE IF NOT EXISTS grants (
  owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  bags TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner, grantee)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  body TEXT NOT NULL,
  reply_to INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages(recipient, id);
CREATE TABLE IF NOT EXISTS bags (
  owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  content BLOB NOT NULL,
  version INTEGER NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner, name)
);
CREATE INDEX IF NOT EXISTS invites_expires_at ON invites(expires_at);
`

// dbFilePath extracts the actual file path from a database DSN (data source name).
// It matches the DSN parsing done by modernc.org/sqlite v1.61.0 driver's newConn function
// (conn.go lines 73-91).
//
// Returns:
//   - path: the file system path SQLite will actually open, empty for memory databases
//   - isMemory: true for ":memory:", "file::memory:", or file: URIs with "mode=memory" query parameter
//   - err: parsing errors for invalid URIs
//
// The driver behavior (from modernc.org/sqlite@v1.61.0/conn.go:73-91):
//   - Query string (after '?') is extracted
//   - If DSN does NOT start with "file:", the query is stripped: dsn = dsn[:pos]
//   - If DSN starts with "file:", the full DSN (including query) is passed to sqlite3_open_v2
//     with SQLITE_OPEN_URI flag, and SQLite decodes the URI and interprets mode=memory
//
// Memory databases:
//   - ":memory:" (plain path)
//   - "file::memory:" or "file::memory:?params" (file: URI)
//   - file: URIs with "mode=memory" query parameter (exact key match, last value wins, case-insensitive value)
func dbFilePath(dsn string) (path string, isMemory bool, err error) {
	// Plain :memory:
	if dsn == ":memory:" {
		return "", true, nil
	}

	// Extract query string position for plain file paths
	queryStart := strings.IndexRune(dsn, '?')

	// Handle file: URIs (prefix check is case-sensitive in modernc.org/sqlite v1.61.0)
	if strings.HasPrefix(dsn, "file:") {
		// Strip "file:" prefix
		uriPath := dsn[5:]

		// Check for file::memory: (with or without query/fragment)
		if strings.HasPrefix(uriPath, ":memory:") {
			return "", true, nil
		}

		// Refuse fragments in file: URIs
		// Fragments create ambiguity in URI parsing where SQLite and validation code
		// can disagree about the file path and parameters. Use %23 to encode a literal # in the filename.
		if strings.ContainsRune(uriPath, '#') {
			return "", false, fmt.Errorf("file: URI contains a fragment (#), which is not supported; use %%23 to encode a literal # in the filename")
		}

		// Extract query string
		uriQueryStart := strings.IndexRune(uriPath, '?')

		// Determine the actual path part (before any query)
		pathPart := uriPath
		var query string

		if uriQueryStart >= 0 {
			// Extract query
			query = uriPath[uriQueryStart+1:]
			pathPart = uriPath[:uriQueryStart]
		}

		// Check for mode=memory in query (file: URIs only)
		if query != "" {
			// Check for mode=memory: exact key match "mode", last value wins, case-sensitive value
			// SQLite only accepts lowercase "memory" - uppercase values like "MEMORY" cause errors
			var lastModeValue string
			for _, param := range strings.Split(query, "&") {
				if kv := strings.SplitN(param, "=", 2); len(kv) == 2 {
					if kv[0] == "mode" {
						lastModeValue = kv[1]
					}
				}
			}
			if lastModeValue == "memory" {
				return "", true, nil
			}
		}

		// Now decode the path part
		uriPath = pathPart

		// Decode URI: handle file:/// (3 slashes), file://host/ (authority), file:/ (1 slash), file:rel
		if strings.HasPrefix(uriPath, "//") {
			// file://authority/path
			// Extract authority (host)
			rest := uriPath[2:]
			slashIdx := strings.IndexRune(rest, '/')
			var authority, pathPart string
			if slashIdx >= 0 {
				authority = rest[:slashIdx]
				pathPart = rest[slashIdx:] // Includes leading /
			} else {
				authority = rest
				pathPart = ""
			}

			// Accept empty authority or "localhost", reject others
			if authority != "" && authority != "localhost" {
				return "", false, fmt.Errorf("file: URI with non-local host %q not supported", authority)
			}

			// Use the path part (already has leading / if non-empty)
			if pathPart == "" {
				return "", false, fmt.Errorf("file: URI with authority but no path")
			}
			uriPath = pathPart
		} else if strings.HasPrefix(uriPath, "/") {
			// file:/absolute/path -> /absolute/path (already correct)
		}
		// else: file:relative/path -> relative/path (already correct)

		// Percent-decode the path
		decoded, decodeErr := url.PathUnescape(uriPath)
		if decodeErr != nil {
			return "", false, fmt.Errorf("invalid percent encoding in file: URI: %w", decodeErr)
		}

		return decoded, false, nil
	}

	// Plain file path: strip query if present (modernc strips it before opening)
	if queryStart >= 0 {
		return dsn[:queryStart], false, nil
	}

	return dsn, false, nil
}

// checkDatabasePath refuses non-regular database files (FIFO, socket, device, directory).
// Symlinks are allowed if their target is a regular file or doesn't exist (dangling).
// Symlinks to non-regular files (FIFO, socket, device, directory) are refused.
// ":memory:" and SQLite URI paths are skipped.
// A missing path is acceptable (will be created).
func checkDatabasePath(dsn string) error {
	// Parse the DSN to get the actual file path
	path, isMemory, err := dbFilePath(dsn)
	if err != nil {
		return err
	}

	// Memory databases are always OK
	if isMemory {
		return nil
	}

	// Empty path from URI parsing is an error
	if path == "" {
		return fmt.Errorf("database path is empty after parsing DSN")
	}

	// Lstat to detect symlinks
	info, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		if os.IsNotExist(lstatErr) {
			// Missing path is OK, it will be created
			return nil
		}
		return pathless(lstatErr)
	}

	// If it's a symlink, check the target
	if info.Mode()&os.ModeSymlink != 0 {
		// Stat the target (follows the symlink)
		targetInfo, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				// Dangling symlink: resolve the full chain (up to 40 hops) and check
				// every directory crossed for group/world-writable permissions.
				const maxHops = 40

				currentPath := path
				resolved := false
				for hop := 0; hop < maxHops; hop++ {
					// Check the current link's parent directory
					linkDir := filepath.Dir(currentPath)
					linkDirInfo, linkDirErr := os.Stat(linkDir)
					if linkDirErr != nil {
						if os.IsNotExist(linkDirErr) {
							return fmt.Errorf("database symlink %s is dangling and intermediate directory %s does not exist", filepath.Base(path), filepath.Base(linkDir))
						}
						return pathless(linkDirErr)
					}
					if linkDirInfo.Mode().Perm()&0o022 != 0 {
						return fmt.Errorf("database symlink %s is dangling and directory %s is group- or world-writable", filepath.Base(path), filepath.Base(linkDir))
					}

					// Read the symlink target
					targetPath, resolveErr := os.Readlink(currentPath)
					if resolveErr != nil {
						return pathless(resolveErr)
					}

					// Make it absolute if relative
					if !filepath.IsAbs(targetPath) {
						targetPath = filepath.Join(linkDir, targetPath)
					}

					// Check if this target exists
					targetInfo, targetStatErr := os.Lstat(targetPath)
					if targetStatErr != nil {
						if os.IsNotExist(targetStatErr) {
							// Final target doesn't exist: check its parent directory
							targetDir := filepath.Dir(targetPath)
							targetDirInfo, targetDirErr := os.Stat(targetDir)
							if targetDirErr != nil {
								if os.IsNotExist(targetDirErr) {
									return fmt.Errorf("database symlink %s is dangling and target's parent directory %s does not exist", filepath.Base(path), filepath.Base(targetDir))
								}
								return pathless(targetDirErr)
							}
							if targetDirInfo.Mode().Perm()&0o022 != 0 {
								return fmt.Errorf("database symlink %s is dangling and target's parent directory is group- or world-writable", filepath.Base(path))
							}

							// Dangling symlink with all safe directories is OK
							return nil
						}
						return pathless(targetStatErr)
					}

					// Target exists: check if it's another symlink
					if targetInfo.Mode()&os.ModeSymlink != 0 {
						// Continue following the chain
						currentPath = targetPath
						continue
					}

					// Target exists and is not a symlink: we've reached the end
					// This means it's not actually dangling; fall through to regular check
					info = targetInfo
					resolved = true
					break
				}

				// If we exhausted maxHops without resolving, the chain is too long
				if !resolved {
					return fmt.Errorf("database symlink %s chain exceeds maximum depth of %d", filepath.Base(path), maxHops)
				}
			} else {
				return pathless(statErr)
			}
		} else {
			// Symlink target exists and is accessible
			info = targetInfo
		}
	}

	// Refuse non-regular files (FIFO, socket, device, directory)
	if !info.Mode().IsRegular() {
		fileType := "non-regular file"
		switch {
		case info.IsDir():
			fileType = "directory"
		case info.Mode()&os.ModeCharDevice != 0:
			fileType = "character device"
		case info.Mode()&os.ModeDevice != 0:
			fileType = "device"
		case info.Mode()&os.ModeNamedPipe != 0:
			fileType = "named pipe (FIFO)"
		case info.Mode()&os.ModeSocket != 0:
			fileType = "socket"
		}
		return fmt.Errorf("database file %s is a %s; must be a regular file", filepath.Base(path), fileType)
	}

	return nil
}

// Open opens the database at path, applies migrations, and returns a Store.
// Use ":memory:" for tests. It is the only Store constructor; a zero-value Store{} has a nil clock and must not be used directly.
func Open(path string) (*Store, error) {
	keepEnv := os.Getenv("PEERLINE_BACKUP_KEEP")
	var keep int
	if keepEnv != "" {
		fmt.Sscanf(keepEnv, "%d", &keep)
	}
	if keep < 1 {
		if keepEnv != "" && keep != 0 {
			slog.Default().Warn("PEERLINE_BACKUP_KEEP invalid or zero, using default 3", "value", keepEnv)
		}
		keep = 3
	}

	opts := OpenOptions{
		SkipMigrationBackup:  os.Getenv("PEERLINE_SKIP_MIGRATION_BACKUP") == "1",
		BackupDir:            os.Getenv("PEERLINE_BACKUP_DIR"),
		BackupRetentionCount: keep,
		Logger:               slog.Default(),
	}
	return OpenWithOptions(path, opts)
}

// OpenWithOptions opens the database with custom options.
func OpenWithOptions(path string, opts OpenOptions) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.BackupRetentionCount < 1 {
		opts.Logger.Warn("BackupRetentionCount < 1, using 3", "value", opts.BackupRetentionCount)
		opts.BackupRetentionCount = 3
	}

	// Refuse non-regular DB files before opening
	if err := checkDatabasePath(path); err != nil {
		return nil, err
	}

	dsn := buildDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Tighten permissions on existing database files if needed (Unix only)
	// Called early so files are secured before migration/backup
	tightenDatabaseFilePermissions(path, opts.Logger)

	// Guard: check version BEFORE executing schema
	currentVersion, err := checkSchemaVersion(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Check if database is empty BEFORE executing schema
	isEmpty, err := isDatabaseEmpty(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("check if database is empty: %w", err)
	}

	if !isEmpty && currentVersion < SchemaVersion() && opts.SkipMigrationBackup {
		opts.Logger.Warn("PEERLINE_SKIP_MIGRATION_BACKUP is set: migrating without a backup")
	}

	var backupPath string
	var reused bool
	if currentVersion < SchemaVersion() && !opts.SkipMigrationBackup && !isEmpty {
		backupPath, reused, err = backupBeforeMigration(db, path, currentVersion, SchemaVersion(), opts)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}

	if !isEmpty {
		var ok string
		if err := db.QueryRow(`PRAGMA quick_check`).Scan(&ok); err != nil {
			db.Close()
			return nil, fmt.Errorf("quick_check: %w", err)
		}
		if ok != "ok" {
			db.Close()
			return nil, fmt.Errorf("database failed integrity check: quick_check returned %q", ok)
		}
	}

	// Re-read right before the schema script so a newer binary that migrated meanwhile is not downgraded over.
	if _, err := checkSchemaVersion(db); err != nil {
		db.Close()
		return nil, err
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}

	schemaInUse, err := runMigrations(db, currentVersion, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := checkSchemaShape(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := backfillNullPublicIDs(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("backfill invite public_id: %w", err)
	}

	// Tighten permissions on database files (main, WAL, SHM) if needed (Unix only)
	// Called after schema setup so all files exist
	tightenDatabaseFilePermissions(path, opts.Logger)

	return &Store{
		db:                 db,
		clk:                clock.Or(opts.Clock),
		schemaVersionInUse: schemaInUse,
		lastBackupPath:     backupPath,
		backupReused:       reused,
		keyIndex:           newKeyIndex(),
	}, nil
}

func buildDSN(path string) string {
	pragmas := "_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		// Use file-based shared-cache for :memory: so pragmas apply.
		// Generate unique name per Open to prevent test bleed.
		id := atomic.AddUint64(&memDBCounter, 1)
		return fmt.Sprintf("file:memdb-%d?mode=memory&cache=shared&%s", id, pragmas)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + pragmas
}

func backfillNullPublicIDs(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := backfillInvitePublicIDs(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// expectedColumns and expectedIndexes are what the code reads and relies on; a database at the
// current user_version that lacks any of them (partial restore, hand edit) is refused.
var expectedColumns = map[string][]string{
	"peers": {"id", "name", "key_hash", "created_at", "notify_email", "notify_email_verified", "notify_email_token", "created_via_invite"},
	"invites": {"code_hash", "from_peer", "scopes", "bags", "expires_at", "used_by", "pairing_token_hash", "public_id",
		"require_confirm", "claimed_by", "confirm_by", "declined_at", "nonce", "back_scopes", "back_bags", "code_fails"},
	"grants": {"owner", "grantee", "scopes", "bags", "created_at"},
}

var expectedIndexes = []string{"invites_pairing_token_hash", "invites_public_id"}

func checkSchemaShape(db *sql.DB) error {
	for table, cols := range expectedColumns {
		for _, c := range cols {
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, c).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("database schema is damaged: %s.%s is missing", table, c)
			}
		}
	}
	for _, ix := range expectedIndexes {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('invites') WHERE name=? AND "unique"=1`, ix).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("database schema is damaged: unique index %s is missing", ix)
		}
	}
	return nil
}

// migrate applies ordered, idempotent schema upgrades tracked by PRAGMA user_version.
// checkSchemaVersion reads user_version and validates it's not too new or invalid.
func checkSchemaVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read user_version: %w", err)
	}
	if version < 0 {
		return 0, &ErrSchemaInvalid{Have: version}
	}
	maxKnown := SchemaVersion()
	if version > maxKnown {
		return 0, &ErrSchemaTooNew{Have: version, Max: maxKnown}
	}
	return version, nil
}

// isDatabaseEmpty checks if the database has no user tables (schema not yet applied).
func isDatabaseEmpty(db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// pathless strips the directory from *fs.PathError / *os.LinkError so errors and logs do not leak the filesystem layout.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s %s: %w", pe.Op, filepath.Base(pe.Path), pe.Err)
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return fmt.Errorf("%s %s: %w", le.Op, filepath.Base(le.Old), le.Err)
	}
	return err
}

// setupBackupDir ensures the backup directory exists with 0700 permissions and refuses symlinks,
// directories owned by another user, and any group or world write access.
// For explicitly configured PEERLINE_BACKUP_DIR, enforces strict 0700 (no group/world access).
// For the default DB directory, only refuses group/world writable (0022).
func setupBackupDir(dir string, explicitlyConfigured bool, logger *slog.Logger) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup directory: %w", pathless(err))
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat backup directory: %w", pathless(err))
	}
	dirBase := filepath.Base(dir)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("backup directory %q must be a real directory, not a symlink", dirBase)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("backup directory %q is not owned by the user running peerline", dirBase)
	}

	perm := info.Mode().Perm()
	if explicitlyConfigured {
		// Strict check for PEERLINE_BACKUP_DIR: no group/world access at all
		if perm&0077 != 0 {
			badBits := perm & 0077
			return fmt.Errorf("backup directory %q allows group or world access (mode %04o, bad bits: %03o); fix permissions to 0700", dirBase, perm, badBits)
		}
	} else {
		// Lenient check for default DB directory: only refuse writable
		if perm&0022 != 0 {
			badBits := perm & 0022
			return fmt.Errorf("backup directory %q is group or world writable (mode %04o, bad bits: %03o); database directory must not be writable by others", dirBase, perm, badBits)
		}
	}

	return nil
}

// runMigrations applies pending migrations and returns the resulting schema version.
func runMigrations(db *sql.DB, currentVersion int, opts OpenOptions) (int, error) {
	maxKnownVersion := SchemaVersion()
	if currentVersion >= maxKnownVersion {
		return currentVersion, nil
	}
	for i, mig := range migrations {
		if err := runMigrationStep(db, i+1, mig, maxKnownVersion, opts); err != nil {
			return 0, err
		}
	}
	return checkSchemaVersion(db)
}

// backupSuffixRE matches the timestamp suffix of backups we create.
// Matches: .YYYYMMDD-HHMMSS.microseconds with optional .hexhexhexhexhexhexhexhex suffix (8 hex chars)
// or legacy .decimal_pid suffix (for compatibility with pre-random-suffix backups).
const backupSuffixRE = `\.\d{8}-\d{6}\.\d{6}(\.[0-9a-f]{8}|\.\d+)?$`

// backupBeforeMigration creates a VACUUM INTO backup of the database before applying migrations.
// For :memory: databases or brand-new databases, no backup is taken.
// Returns (backupPath, reused, error).
func backupBeforeMigration(db *sql.DB, explicitPath string, currentVersion, targetVersion int, opts OpenOptions) (string, bool, error) {
	var dbPath string
	err := db.QueryRow(`SELECT file FROM pragma_database_list() WHERE name='main'`).Scan(&dbPath)
	if err != nil {
		return "", false, fmt.Errorf("get database path: %w", err)
	}

	// Skip backup for in-memory databases
	if dbPath == "" {
		return "", false, nil
	}

	// Use explicit path if provided, otherwise use discovered path
	if explicitPath != "" && explicitPath != ":memory:" {
		dbPath = explicitPath
	}

	// Determine backup directory
	backupDir := opts.BackupDir
	explicitlyConfigured := backupDir != ""
	if backupDir == "" {
		backupDir = filepath.Dir(dbPath)
	}

	if err := setupBackupDir(backupDir, explicitlyConfigured, opts.Logger); err != nil {
		return "", false, err
	}

	dbBase := filepath.Base(dbPath)

	// Check for existing backup matching this migration
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(dbBase) + `\.pre-v` + fmt.Sprintf("%d", targetVersion) + `-from-v` + fmt.Sprintf("%d", currentVersion) + backupSuffixRE)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return "", false, fmt.Errorf("read backup directory: %w", pathless(err))
	}

	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) && entry.Type().IsRegular() {
			existingBackup := filepath.Join(backupDir, entry.Name())

			// Check if backup is newer than both DB and WAL
			backupInfo, err := os.Stat(existingBackup)
			if err != nil {
				continue
			}

			dbInfo, err := os.Stat(dbPath)
			if err != nil {
				continue
			}

			walPath := dbPath + "-wal"
			walInfo, err := os.Stat(walPath)
			walExists := err == nil

			backupNewer := backupInfo.ModTime().After(dbInfo.ModTime())
			if walExists {
				backupNewer = backupNewer && backupInfo.ModTime().After(walInfo.ModTime())
			}

			if backupNewer {
				// Verify backup integrity
				if err := verifyBackup(existingBackup, currentVersion); err != nil {
					opts.Logger.Warn("existing backup failed verification, creating new backup", "backup", filepath.Base(existingBackup), "error", pathless(err).Error())
					continue
				}

				opts.Logger.Info("reusing existing pre-migration backup", "backup", filepath.Base(existingBackup))
				return existingBackup, true, nil
			}
		}
	}

	// Create new backup
	clk := clock.Or(opts.Clock)
	timestamp := clk.Now().UTC().Format("20060102-150405.000000")

	// Sweep stale .partial files from previous interrupted backups (older than 2 minutes)
	sweepPartialBackups(backupDir, dbBase, opts.Logger)

	backupName := fmt.Sprintf("%s.pre-v%d-from-v%d.%s", dbBase, targetVersion, currentVersion, timestamp)

	// Check available disk space before creating the backup
	if err := checkDiskSpace(db, backupDir, opts.Logger); err != nil {
		return "", false, err
	}

	// Retry loop: try up to 10 times with random suffixes on collision
	var finalPath string
	var backupSize int64
	var backupDuration time.Duration
	var linked bool

	for attempts := 0; attempts < 10; attempts++ {
		tryName := backupName
		if attempts > 0 {
			// Generate random suffix: 4 random bytes as hex
			randomBytes := make([]byte, 4)
			if _, err := rand.Read(randomBytes); err != nil {
				return "", false, fmt.Errorf("generate random suffix: %w", err)
			}
			tryName = fmt.Sprintf("%s.%x", backupName, randomBytes)
		}

		finalPath = filepath.Join(backupDir, tryName)

		// Check if final name already exists (collision)
		if _, err := os.Lstat(finalPath); err == nil {
			// Final name exists, try next random suffix
			continue
		} else if !os.IsNotExist(err) {
			return "", false, fmt.Errorf("check backup file: %w", pathless(err))
		}

		partialPath := finalPath + ".partial"

		// Create .partial file with O_EXCL|O_NOFOLLOW at 0600
		f, err := openBackupFileExclusive(partialPath)
		if err != nil {
			if os.IsExist(err) {
				// Partial file exists (stale or concurrent), try next suffix
				continue
			}
			return "", false, fmt.Errorf("create partial backup file: %w", pathless(err))
		}

		// Verify owner and mode on the open fd
		partialFinfo, err := f.Stat()
		if err != nil {
			f.Close()
			os.Remove(partialPath)
			return "", false, fmt.Errorf("stat created partial backup file: %w", pathless(err))
		}

		if !ownedByCurrentUser(partialFinfo) {
			f.Close()
			os.Remove(partialPath)
			return "", false, fmt.Errorf("partial backup file %q is not owned by the user running peerline", filepath.Base(partialPath))
		}

		// Mode should be 0600 from OpenFile, but verify (unix-only check)
		if err := verifyBackupFileMode(partialFinfo, partialPath); err != nil {
			f.Close()
			os.Remove(partialPath)
			return "", false, err
		}
		f.Close()

		// Execute VACUUM INTO with context timeout
		opts.Logger.Info("starting pre-migration backup", "backup", filepath.Base(tryName), "size_bytes", "pending")
		backupStart := time.Now()

		timeout := opts.BackupTimeout
		if timeout == 0 {
			timeout = 5 * time.Minute // Default 5 minutes
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)

		vacuumFunc := opts.vacuumInto
		if vacuumFunc == nil {
			vacuumFunc = func(db *sql.DB, path string) error {
				_, err := db.ExecContext(ctx, `VACUUM INTO ?`, path)
				return err
			}
		}

		err = vacuumFunc(db, partialPath)
		cancel()
		if err != nil {
			os.Remove(partialPath)
			return "", false, fmt.Errorf("VACUUM INTO backup: %w", pathless(err))
		}

		backupDuration = time.Since(backupStart)

		// Verify the partial file hasn't been replaced (check inode)
		afterVacuum, err := os.Lstat(partialPath)
		if err != nil {
			os.Remove(partialPath)
			return "", false, fmt.Errorf("stat partial after VACUUM: %w", pathless(err))
		}
		if !os.SameFile(partialFinfo, afterVacuum) {
			os.Remove(partialPath)
			return "", false, fmt.Errorf("partial backup file was replaced during VACUUM")
		}
		if err := verifyBackupFileMode(afterVacuum, partialPath); err != nil {
			os.Remove(partialPath)
			return "", false, fmt.Errorf("mode changed during VACUUM: %w", err)
		}

		// Fsync the backup file
		if err := fsyncFile(partialPath, opts.Logger); err != nil {
			opts.Logger.Warn("backup fsync failed", "backup", filepath.Base(partialPath), "error", pathless(err).Error())
		}

		// Verify backup before linking
		// SQLite opens the .partial file by path and follows symlinks. This is acceptable
		// because the setupBackupDir check ensures the directory owner matches the current user.
		if err := verifyBackup(partialPath, currentVersion); err != nil {
			os.Remove(partialPath)
			return "", false, fmt.Errorf("backup verification failed: %w", err)
		}

		// Atomically link the partial file to the final name
		// os.Link fails if finalPath already exists
		if err := os.Link(partialPath, finalPath); err != nil {
			os.Remove(partialPath)
			if os.IsExist(err) {
				// Final name now exists (race with another process or stale file), retry with new suffix
				continue
			}
			return "", false, fmt.Errorf("link partial to final backup name: %w", pathless(err))
		}

		// Link succeeded, remove the .partial file (the final name now exists via hard link)
		os.Remove(partialPath)
		backupSize = afterVacuum.Size()
		linked = true
		break
	}

	// If we exhausted all retries, fail
	if !linked {
		return "", false, fmt.Errorf("backup failed after 10 collision retries")
	}

	// Fsync the backup directory to persist the final name
	if err := fsyncDirectory(backupDir, opts.Logger); err != nil {
		opts.Logger.Warn("backup directory fsync failed", "dir", backupDir, "error", pathless(err).Error())
	}

	opts.Logger.Info("pre-migration backup complete", "backup", filepath.Base(finalPath), "size_bytes", backupSize, "duration_seconds", backupDuration.Seconds())

	// Enforce retention policy
	if err := enforceBackupRetention(backupDir, dbBase, finalPath, opts.BackupRetentionCount, opts.Logger); err != nil {
		opts.Logger.Warn("backup retention cleanup failed", "error", pathless(err).Error())
	}

	return finalPath, false, nil
}

// verifyBackup runs basic checks on a backup file.
func verifyBackup(backupPath string, expectedVersion int) error {
	// Check that backup file exists and is not empty
	info, err := os.Stat(backupPath)
	if err != nil {
		return fmt.Errorf("stat backup: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("backup file is empty")
	}

	// Get absolute path for comparison
	absPath, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	// Build proper file: URI with url.URL to handle special characters (?, #, %, etc.)
	// On Windows, convert backslashes to forward slashes for the URI path
	uriPath := absPath
	if filepath.Separator == '\\' {
		uriPath = "/" + filepath.ToSlash(absPath)
	}

	u := url.URL{
		Scheme:   "file",
		Path:     uriPath,
		RawQuery: url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)"}}.Encode(),
	}
	dsn := u.String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer db.Close()

	// Verify we opened the expected file by checking PRAGMA database_list
	var seq int
	var name, file string
	if err := db.QueryRow(`SELECT seq, name, file FROM pragma_database_list() WHERE name='main'`).Scan(&seq, &name, &file); err != nil {
		return fmt.Errorf("read database_list: %w", err)
	}

	// Compare opened file with expected path using os.SameFile
	openedInfo, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("stat opened file %q: %w", file, err)
	}
	if !os.SameFile(info, openedInfo) {
		return fmt.Errorf("backup verification opened wrong file: expected %q, got %q", absPath, file)
	}

	// Verify query_only mode is active
	var queryOnly int
	if err := db.QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil {
		return fmt.Errorf("check query_only: %w", err)
	}
	if queryOnly != 1 {
		return fmt.Errorf("backup was not opened read-only")
	}

	// Quick check
	var ok string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&ok); err != nil {
		return fmt.Errorf("quick_check: %w", err)
	}
	if ok != "ok" {
		return fmt.Errorf("quick_check returned %q", ok)
	}

	// Check version matches
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if version != expectedVersion {
		return fmt.Errorf("backup user_version is %d, expected %d (hint: if another process migrated this database, retry)", version, expectedVersion)
	}

	// Check peers table is queryable if it exists
	// (Backups taken before schema initialization may not have it)
	var hasPeers int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='peers'`).Scan(&hasPeers); err != nil {
		return fmt.Errorf("check peers table: %w", err)
	}
	if hasPeers > 0 {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&count); err != nil {
			return fmt.Errorf("query peers table: %w", err)
		}
	}

	return nil
}

// enforceBackupRetention deletes old backups, keeping at most keepCount total (including excludePath).
func enforceBackupRetention(backupDir, dbBase, excludePath string, keepCount int, logger *slog.Logger) error {
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(dbBase) + `\.pre-v\d+-from-v\d+` + backupSuffixRE)

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("read backup directory: %w", pathless(err))
	}

	type backupInfo struct {
		path    string
		modTime time.Time
	}
	var backups []backupInfo

	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) && entry.Type().IsRegular() {
			fullPath := filepath.Join(backupDir, entry.Name())
			if fullPath == excludePath {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			backups = append(backups, backupInfo{path: fullPath, modTime: info.ModTime()})
		}
	}

	// Sort by mtime, newest first
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	// Keep keepCount-1 others (total including excluded == keepCount)
	toKeep := keepCount - 1
	if toKeep < 0 {
		toKeep = 0
	}

	for i := toKeep; i < len(backups); i++ {
		if err := os.Remove(backups[i].path); err != nil {
			logger.Warn("failed to delete old backup", "backup", filepath.Base(backups[i].path), "error", pathless(err).Error())
		}
	}

	return nil
}

// checkDiskSpace checks if there's enough disk space for a backup (approximate).
func checkDiskSpace(db *sql.DB, targetDir string, logger *slog.Logger) error {
	var pageCount, pageSize int64
	if err := db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return fmt.Errorf("read page_count: %w", err)
	}
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return fmt.Errorf("read page_size: %w", err)
	}

	dbSize := pageCount * pageSize

	avail, ok, err := availableDiskSpace(targetDir)
	if !ok || err != nil {
		logger.Warn("could not check available disk space", "error", fmt.Sprintf("%v", err))
		return nil // Non-fatal, continue
	}

	if avail < uint64(dbSize) {
		return fmt.Errorf("insufficient disk space: need ~%d bytes, available %d bytes", dbSize, avail)
	}

	return nil
}

// fsyncFile fsyncs a file to ensure durability.
func fsyncFile(path string, logger *slog.Logger) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncDirectory fsyncs a directory to persist directory entries.
func fsyncDirectory(path string, logger *slog.Logger) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// sweepPartialBackups removes stale .partial files older than 2 minutes
// from interrupted backups. Only removes files matching our naming pattern.
//
// Uses real time.Now() to compare against real file mtimes from the filesystem.
// An injected fake clock would incorrectly classify files as old or new.
func sweepPartialBackups(backupDir, dbBase string, logger *slog.Logger) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		// Silently skip if directory is unreadable
		return
	}

	cutoff := time.Now().Add(-2 * time.Minute)
	// Match: <dbBase>.pre-vN-from-vM.<timestamp>[.<suffix>].partial
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(dbBase) + `\.pre-v\d+-from-v\d+\.` + `\d{8}-\d{6}\.\d{6}` + `(\.[0-9a-f]{8}|\.\d+)?\.partial$`)

	for _, entry := range entries {
		if !pattern.MatchString(entry.Name()) {
			continue
		}

		path := filepath.Join(backupDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err == nil {
				logger.Info("removed stale partial backup", "file", entry.Name())
			}
		}
	}
}

// runMigrationStep runs a single migration step in its own transaction.
func runMigrationStep(db *sql.DB, target int, mig func(*sql.Tx) error, maxKnownVersion int, opts OpenOptions) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration v%d: %w", target, err)
	}
	defer tx.Rollback()

	// Re-check version inside tx
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version in migration v%d: %w", target, err)
	}

	// Validate version
	if version < 0 {
		return &ErrSchemaInvalid{Have: version}
	}
	if version > maxKnownVersion {
		return &ErrSchemaTooNew{Have: version, Max: maxKnownVersion}
	}

	if version >= target {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d skip: %w", target, err)
		}
		return nil
	}

	// Call hook if provided
	if opts.migrationStepHook != nil {
		if err := opts.migrationStepHook(target, version); err != nil {
			return err
		}
	}

	if err := mig(tx); err != nil {
		return fmt.Errorf("migration v%d: %w", target, err)
	}

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, target)); err != nil {
		return fmt.Errorf("update user_version to %d: %w", target, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration v%d: %w", target, err)
	}
	return nil
}

// migrateV1NotifyEmail adds the notify_email column to peers.
func migrateV1NotifyEmail(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name = 'notify_email'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Plaintext: Peerline has to address the wake-up mail later. The address
	// is returned only to the peer who set it.
	_, err := tx.Exec(`ALTER TABLE peers ADD COLUMN notify_email TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateV2PairingTokenHash adds the pairing_token_hash column and unique index to invites.
// PR #11 already added both (without user_version tracking), so this checks before acting.
// Also normalizes the index to the partial form if it differs.
func migrateV2PairingTokenHash(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name = 'pairing_token_hash'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE invites ADD COLUMN pairing_token_hash TEXT`); err != nil {
			return err
		}
	}

	// Check if the index exists and verify its definition
	var indexSQL sql.NullString
	err := tx.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&indexSQL)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	expectedSQL := "CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash) WHERE pairing_token_hash IS NOT NULL"
	needsRecreate := false

	if indexSQL.Valid {
		// Normalize both SQLs for comparison (remove extra whitespace)
		normalize := func(s string) string {
			return strings.Join(strings.Fields(s), " ")
		}
		if normalize(indexSQL.String) != normalize(expectedSQL) {
			needsRecreate = true
		}
	} else {
		needsRecreate = true
	}

	if needsRecreate {
		// Drop existing index if present
		if indexSQL.Valid {
			if _, err := tx.Exec(`DROP INDEX IF EXISTS invites_pairing_token_hash`); err != nil {
				return err
			}
		}
		// Create the partial index
		if _, err := tx.Exec(expectedSQL); err != nil {
			return err
		}
	}

	return nil
}

// migrateV3InvitePublicID adds the public_id column to invites and backfills existing rows.
// public_id is a random 16-byte hex string used in the API to avoid exposing reusable ROWIDs.
func migrateV3InvitePublicID(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name = 'public_id'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE invites ADD COLUMN public_id TEXT`); err != nil {
			return err
		}
	}

	if err := backfillInvitePublicIDs(tx); err != nil {
		return err
	}

	// Create unique index if it doesn't exist
	var hasIndex int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_public_id'`).Scan(&hasIndex); err != nil {
		return err
	}
	if hasIndex == 0 {
		if _, err := tx.Exec(`CREATE UNIQUE INDEX invites_public_id ON invites(public_id) WHERE public_id IS NOT NULL`); err != nil {
			return err
		}
	}

	return nil
}

// backfillInvitePublicIDs gives every invite row without a public_id a random one.
// It runs on every Open, not only in the v3 step, because an older binary can still
// insert NULL rows after the migration.
func backfillInvitePublicIDs(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT ROWID FROM invites WHERE public_id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rowids []int64
	for rows.Next() {
		var rowid int64
		if err := rows.Scan(&rowid); err != nil {
			return err
		}
		rowids = append(rowids, rowid)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, rowid := range rowids {
		publicID, err := generatePublicID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE invites SET public_id = ? WHERE ROWID = ?`, publicID, rowid); err != nil {
			return err
		}
	}
	return nil
}

// migrateV4EmailVerification adds notify_email_verified and notify_email_token columns to peers.
func migrateV4EmailVerification(tx *sql.Tx) error {
	// Check if notify_email_verified column exists
	var hasVerified int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name = 'notify_email_verified'`).Scan(&hasVerified); err != nil {
		return err
	}
	if hasVerified == 0 {
		if _, err := tx.Exec(`ALTER TABLE peers ADD COLUMN notify_email_verified INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}

	// Check if notify_email_token column exists
	var hasToken int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name = 'notify_email_token'`).Scan(&hasToken); err != nil {
		return err
	}
	if hasToken == 0 {
		if _, err := tx.Exec(`ALTER TABLE peers ADD COLUMN notify_email_token TEXT`); err != nil {
			return err
		}
	}

	return nil
}

// migrateV5InviteClaimState rebuilds invites (ALTER cannot add multi-column CHECKs or NOT NULL)
// with claim/confirm columns, DB-level state CHECKs and a public_id default, and marks peers
// created by an unconfirmed claim. Existing rows become plain offered/used invites.
// Downgrading is unsafe: older binaries ignore claim state, so restore a pre-migration backup.
func migrateV5InviteClaimState(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE invites_new (
  code_hash TEXT PRIMARY KEY,
  from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  bags TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_by TEXT,
  pairing_token_hash TEXT,
  public_id TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
  require_confirm INTEGER NOT NULL DEFAULT 0 CHECK (require_confirm IN (0,1)),
  claimed_by TEXT REFERENCES peers(id) ON DELETE CASCADE,
  confirm_by INTEGER,
  declined_at INTEGER,
  CHECK (NOT (declined_at IS NOT NULL AND used_by IS NOT NULL)),
  CHECK (claimed_by IS NOT NULL OR (confirm_by IS NULL AND declined_at IS NULL)),
  CHECK (require_confirm=0 OR used_by IS NULL OR used_by IS claimed_by)
);
INSERT INTO invites_new(code_hash,from_peer,scopes,bags,expires_at,used_by,pairing_token_hash,public_id)
  SELECT code_hash,from_peer,scopes,bags,expires_at,used_by,pairing_token_hash,
         COALESCE(public_id, lower(hex(randomblob(16)))) FROM invites;
DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash) WHERE pairing_token_hash IS NOT NULL;
CREATE UNIQUE INDEX invites_public_id ON invites(public_id);
CREATE INDEX invites_from_peer ON invites(from_peer);
CREATE INDEX invites_confirm_by ON invites(confirm_by) WHERE claimed_by IS NOT NULL AND used_by IS NULL;
ALTER TABLE peers ADD COLUMN created_via_invite INTEGER NOT NULL DEFAULT 0;`)
	return err
}

// migrateV6ClaimOffer stores what a claim binds: the per-claim nonce, the claimant's
// reciprocal offer and the wrong-code counter.
func migrateV6ClaimOffer(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE invites ADD COLUMN nonce BLOB;
ALTER TABLE invites ADD COLUMN back_scopes TEXT NOT NULL DEFAULT '';
ALTER TABLE invites ADD COLUMN back_bags TEXT NOT NULL DEFAULT '';
ALTER TABLE invites ADD COLUMN code_fails INTEGER NOT NULL DEFAULT 0;`)
	return err
}

// outstandingInvite is the one definition of an unused invite that can still be acted on
// (?1 = now): offered rows live until expires_at, claimed rows until confirm_by.
const outstandingInvite = `(used_by IS NULL AND declined_at IS NULL AND
  ((claimed_by IS NULL AND expires_at>=?1) OR (claimed_by IS NOT NULL AND confirm_by>=?1)))`

func (s *Store) Close() error { return s.db.Close() }

// generatePublicID returns a random 16-byte hex string for invite public_id.
func generatePublicID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---- peers ----

type Peer struct {
	ID        string    `json:"peer_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreatePeer(ctx context.Context, id, name, keyHash, notifyEmail, notifyToken string) error {
	verified := 0
	_, err := s.db.ExecContext(ctx, `INSERT INTO peers(id,name,key_hash,created_at,notify_email,notify_email_verified,notify_email_token) VALUES(?,?,?,?,?,?,?)`,
		id, name, keyHash, s.nowUnix(), notifyEmail, verified, notifyToken)
	if err == nil {
		// Add to key index after successful insert
		s.keyIndex.add(keyHash, id)
	}
	return err
}

// NotifyEmail returns the peer's wake-up address, or "" when unset.
func (s *Store) NotifyEmail(ctx context.Context, id string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT notify_email FROM peers WHERE id=?`, id).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

// SetNotifyEmail sets or clears the wake-up address. email is "" to clear.
// When setting a new email, it marks it as unverified and generates a confirmation token.
func (s *Store) SetNotifyEmail(ctx context.Context, id, email, token string) error {
	verified := 0
	if email == "" {
		// Clearing email
		res, err := s.db.ExecContext(ctx, `UPDATE peers SET notify_email=?, notify_email_verified=0, notify_email_token=NULL WHERE id=?`, email, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	}
	// Setting new email: unverified with token
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET notify_email=?, notify_email_verified=?, notify_email_token=? WHERE id=?`, email, verified, token, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetNotifyEmailStatus returns the email and whether it's verified (no token exposure).
func (s *Store) GetNotifyEmailStatus(ctx context.Context, id string) (email string, verified bool, err error) {
	var verifiedInt int
	err = s.db.QueryRowContext(ctx, `SELECT notify_email, notify_email_verified FROM peers WHERE id=?`, id).Scan(&email, &verifiedInt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	verified = verifiedInt != 0
	return email, verified, nil
}

// VerifyNotifyEmail marks the email as verified if the tokenHash matches and hasn't expired.
// Token is single-use: cleared on success. Returns ErrNotFound for invalid/expired/used tokens.
// tokenWithExpiry format: "<unix_issued>:<hash>". Legacy plaintext or malformed values are treated as invalid.
func (s *Store) VerifyNotifyEmail(ctx context.Context, id, tokenHash string) error {
	// Fetch stored token
	var storedToken sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT notify_email_token FROM peers WHERE id=?`, id).Scan(&storedToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("fetch notify_email_token: %w", err)
	}
	if !storedToken.Valid || storedToken.String == "" {
		return ErrNotFound
	}

	// Parse stored token: "<unix_issued>:<hash>"
	parts := strings.SplitN(storedToken.String, ":", 2)
	if len(parts) != 2 {
		// Malformed or legacy plaintext token
		return ErrNotFound
	}
	issuedUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ErrNotFound
	}
	storedHash := parts[1]

	// Check expiry (24 hours: valid at exactly issued+86400, expired at issued+86401)
	if s.nowUnix() > issuedUnix+86400 {
		return ErrNotFound
	}

	// Verify hash matches
	if tokenHash != storedHash {
		return ErrNotFound
	}

	// Single-use: clear token and mark verified
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET notify_email_verified=1, notify_email_token=NULL WHERE id=? AND notify_email_token=?`, id, storedToken.String)
	if err != nil {
		return fmt.Errorf("clear token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetVerifiedNotifyEmail returns the email only if it's verified, or "" if unset/unverified.
func (s *Store) GetVerifiedNotifyEmail(ctx context.Context, id string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT notify_email FROM peers WHERE id=? AND notify_email_verified=1 AND notify_email != ''`, id).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return email, err
}

// RotateKey replaces the peer's API key hash. The old key stops authenticating
// immediately; grants, bags and identity are untouched.
func (s *Store) RotateKey(ctx context.Context, id, newKeyHash string) error {
	s.keyIndexRemove(id)
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET key_hash=? WHERE id=?`, newKeyHash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.keyIndex.add(newKeyHash, id)
	return nil
}

// DeletePeer removes the peer and, via foreign keys, its grants, invites, messages and bags.
func (s *Store) DeletePeer(ctx context.Context, id string) error {
	s.keyIndexRemove(id)
	res, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PeerByKeyHash(ctx context.Context, keyHash string) (*Peer, error) {
	var p Peer
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM peers WHERE key_hash=?`, keyHash).Scan(&p.ID, &p.Name, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CreatedAt = time.Unix(ts, 0).UTC()
	return &p, nil
}

// PeerName returns the display name of peer id.
func (s *Store) PeerName(ctx context.Context, id string) (string, error) {
	var n string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM peers WHERE id=?`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return n, err
}

func (s *Store) PeerExists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM peers WHERE id=?`, id).Scan(&n)
	return n > 0, err
}

// Stats is the public, aggregate size of the relay. It has no peer ids, names,
// message bodies, bag contents, or invite codes.
type Stats struct {
	Peers    int64 `json:"peers"`
	Messages int64 `json:"messages"`
	Grants   int64 `json:"grants"`
	Bags     int64 `json:"bags"`
}

// Stats counts peers, messages, directional grants, and bags.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM peers),
			(SELECT COUNT(*) FROM messages),
			(SELECT COUNT(*) FROM grants),
			(SELECT COUNT(*) FROM bags)`).Scan(&st.Peers, &st.Messages, &st.Grants, &st.Bags)
	return st, err
}

// ---- invites & grants ----

type Grant struct {
	Owner   string   `json:"owner"`
	Grantee string   `json:"grantee"`
	Scopes  []string `json:"scopes"`
	Bags    []string `json:"bags"`
}

func join(v []string) string { return strings.Join(v, ",") }
func split(v string) []string {
	if v == "" {
		return []string{}
	}
	return strings.Split(v, ",")
}

// normalizeScopesAndBags sorts and deduplicates scopes and bags for set comparison.
// writeGrantsInTx stores the raw join() output (not sorted), so this normalization
// is only for grantsEqual to provide order-insensitive, duplicate-insensitive matching.
func normalizeScopesAndBags(scopes, bags string) (string, string) {
	normSlice := func(s string) string {
		if s == "" {
			return ""
		}
		parts := strings.Split(s, ",")
		// Deduplicate
		seen := make(map[string]bool)
		var unique []string
		for _, p := range parts {
			if !seen[p] {
				seen[p] = true
				unique = append(unique, p)
			}
		}
		// Sort
		sort.Strings(unique)
		return strings.Join(unique, ",")
	}
	return normSlice(scopes), normSlice(bags)
}

// grantsEqual compares two grants as sets (order-insensitive).
// Normalizes before comparison to match writeGrantsInTx behavior.
func grantsEqual(scopes1, bags1, scopes2, bags2 string) bool {
	ns1, nb1 := normalizeScopesAndBags(scopes1, bags1)
	ns2, nb2 := normalizeScopesAndBags(scopes2, bags2)
	return ns1 == ns2 && nb1 == nb2
}

func (s *Store) CreateInvite(ctx context.Context, codeHash, from string, scopes, bags []string, expires time.Time) error {
	publicID, err := generatePublicID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,public_id) VALUES(?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), publicID)
	return err
}

func (s *Store) CreateInviteWithPairing(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time) error {
	publicID, err := generatePublicID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,pairing_token_hash,public_id) VALUES(?,?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), pairingTokenHash, publicID)
	return err
}

// CreateInviteAtomic checks the per-peer invite cap and creates an invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's public_id on success.
func (s *Store) CreateInviteAtomic(ctx context.Context, codeHash, from string, scopes, bags []string, expires time.Time, cap int) (string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE from_peer=?2 AND `+outstandingInvite, s.nowUnix(), from).Scan(&count)
	if err != nil {
		return "", err
	}
	if count >= cap {
		return "", ErrTooManyInvites
	}

	publicID, err := generatePublicID()
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,public_id) VALUES(?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), publicID)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return publicID, nil
}

// CreateInviteWithPairingAtomic checks the per-peer invite cap and creates a pairing invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's public_id on success.
func (s *Store) CreateInviteWithPairingAtomic(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time, cap int) (string, error) {
	return s.createPairingInviteAtomic(ctx, codeHash, pairingTokenHash, from, scopes, bags, expires, cap, false)
}

// CreateConfirmInviteAtomic is CreateInviteWithPairingAtomic for a require_confirm invite:
// it can only be claimed, and only the inviter's confirm grants.
func (s *Store) CreateConfirmInviteAtomic(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time, cap int) (string, error) {
	return s.createPairingInviteAtomic(ctx, codeHash, pairingTokenHash, from, scopes, bags, expires, cap, true)
}

func (s *Store) createPairingInviteAtomic(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time, cap int, requireConfirm bool) (string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE from_peer=?2 AND `+outstandingInvite, s.nowUnix(), from).Scan(&count)
	if err != nil {
		return "", err
	}
	if count >= cap {
		return "", ErrTooManyInvites
	}

	publicID, err := generatePublicID()
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,pairing_token_hash,public_id,require_confirm) VALUES(?,?,?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), pairingTokenHash, publicID, requireConfirm)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return publicID, nil
}

// InviteMetadata holds non-secret information about an invite for listing.
type InviteMetadata struct {
	PublicID      string    `json:"public_id"`
	Scopes        []string  `json:"scopes"`
	Bags          []string  `json:"bags"`
	ExpiresAt     time.Time `json:"expires_at"`
	Used          bool      `json:"used"`
	IsPairingLink bool      `json:"is_pairing_link"`
}

// CountOutstandingInvites returns the number of active (non-expired, unused) invites created by the peer.
func (s *Store) CountOutstandingInvites(ctx context.Context, peerID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM invites WHERE from_peer=?2 AND `+outstandingInvite,
		s.nowUnix(), peerID).Scan(&count)
	return count, err
}

// ListInvitesByPeer returns non-secret metadata for active invites created by the peer.
// Results are ordered by creation (ROWID) and support pagination.
func (s *Store) ListInvitesByPeer(ctx context.Context, peerID string, limit, offset int) ([]InviteMetadata, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT COALESCE(public_id, ''), scopes, bags, expires_at, used_by IS NOT NULL, 
		        pairing_token_hash IS NOT NULL
		 FROM invites 
		 WHERE from_peer=?2 AND public_id IS NOT NULL
		   AND ((used_by IS NOT NULL AND expires_at>=?1) OR `+outstandingInvite+`)
		 ORDER BY ROWID
		 LIMIT ?3 OFFSET ?4`,
		s.nowUnix(), peerID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []InviteMetadata
	for rows.Next() {
		var im InviteMetadata
		var scopes, bags string
		var exp int64
		var used, hasPairingToken bool
		if err := rows.Scan(&im.PublicID, &scopes, &bags, &exp, &used, &hasPairingToken); err != nil {
			return nil, err
		}
		// Skip entries with empty public_id (defensive, should not happen after v3 migration)
		if im.PublicID == "" {
			continue
		}
		im.Scopes = split(scopes)
		im.Bags = split(bags)
		im.ExpiresAt = time.Unix(exp, 0).UTC()
		im.Used = used
		im.IsPairingLink = hasPairingToken
		invites = append(invites, im)
	}
	return invites, rows.Err()
}

// DeleteInvite revokes an unused invite by public_id (owner-only).
// Returns ErrNotFound if the invite doesn't exist, already used, or doesn't belong to owner.
func (s *Store) DeleteInvite(ctx context.Context, publicID, ownerID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM invites WHERE public_id=? AND from_peer=? AND used_by IS NULL`,
		publicID, ownerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const purgeBatchSize = 500

// purgeMaxBatches bounds how long one run holds the single connection.
var purgeMaxBatches = 100

// purgeYield is the pause after each full batch so request handlers get the connection.
var purgeYield = 25 * time.Millisecond

// PurgeExpiredInvites removes expired unused invites and old used invites.
// Unused invites: deleted when expires_at < now - 300 (5-minute grace).
// Used invites: deleted when expires_at < now - retentionSeconds (default 30 days).
// It stops after purgeMaxBatches batches and reports more=true so the caller can continue soon.
// On error (including cancellation) the count deleted so far is still returned.
func (s *Store) PurgeExpiredInvites(ctx context.Context, retentionSeconds int64) (deleted int, more bool, err error) {
	if retentionSeconds <= 0 {
		retentionSeconds = 30 * 24 * 60 * 60 // 30 days default
	}

	ts := s.nowUnix()
	// The grace does not guard an in-flight accept: acceptInviteInTx re-checks
	// expires_at inside an IMMEDIATE transaction, so accept and purge are serialised
	// and an expired row is rejected whether or not it was purged. It also does not
	// extend validity. It keeps the row briefly after expiry for audit/"expired" status.
	// v5: the predicate must exclude claimed rows, which outlive expires_at (#70).
	graceCutoff := ts - 300
	retentionCutoff := ts - retentionSeconds

	for batches := 0; ; batches++ {
		if err := ctx.Err(); err != nil {
			return deleted, false, err
		}
		if batches == purgeMaxBatches {
			return deleted, true, nil
		}

		res, err := s.db.ExecContext(ctx,
			`DELETE FROM invites WHERE rowid IN (
				SELECT rowid FROM invites 
				WHERE (used_by IS NULL AND claimed_by IS NULL AND expires_at < ?1)
				   OR (used_by IS NULL AND claimed_by IS NOT NULL AND COALESCE(declined_at, confirm_by) < ?1)
				   OR (used_by IS NOT NULL AND expires_at < ?2)
				LIMIT ?3
			)`,
			graceCutoff, retentionCutoff, purgeBatchSize)
		if err != nil {
			return deleted, false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return deleted, false, err
		}
		deleted += int(n)
		if int(n) < purgeBatchSize {
			return deleted, false, s.purgeOrphanPeers(ctx, graceCutoff)
		}

		select {
		case <-ctx.Done():
			return deleted, false, ctx.Err()
		case <-time.After(purgeYield):
		}
	}
}

// purgeOrphanPeers deletes peers created by an unconfirmed claim that never gained a grant,
// message, bag or invite. The grace cutoff protects a peer whose claim row is not yet written.
func (s *Store) purgeOrphanPeers(ctx context.Context, cutoff int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE created_via_invite=1 AND created_at<?
		AND NOT EXISTS (SELECT 1 FROM grants WHERE owner=peers.id OR grantee=peers.id)
		AND NOT EXISTS (SELECT 1 FROM messages WHERE sender=peers.id OR recipient=peers.id)
		AND NOT EXISTS (SELECT 1 FROM bags WHERE owner=peers.id)
		AND NOT EXISTS (SELECT 1 FROM invites WHERE from_peer=peers.id OR claimed_by=peers.id OR used_by=peers.id)`, cutoff)
	return err
}

type InviteInfo struct {
	FromPeer  string
	Scopes    []string
	Bags      []string
	ExpiresAt time.Time
}

// GetInviteByPairingToken retrieves invite details by pairing token (does not consume it).
func (s *Store) GetInviteByPairingToken(ctx context.Context, pairingTokenHash string) (*InviteInfo, error) {
	var from, scopes, bags string
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT from_peer,scopes,bags,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
		Scan(&from, &scopes, &bags, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < s.nowUnix() {
		return nil, ErrNotFound
	}
	return &InviteInfo{
		FromPeer:  from,
		Scopes:    split(scopes),
		Bags:      split(bags),
		ExpiresAt: time.Unix(exp, 0).UTC(),
	}, nil
}

// AcceptInviteByPairingToken atomically consumes an invite via pairing token and creates grants.
func (s *Store) AcceptInviteByPairingToken(ctx context.Context, pairingTokenHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	// Read-only pre-check to avoid taking write lock for invalid tokens
	var codeHash string
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT code_hash,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
		Scan(&codeHash, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < s.nowUnix() {
		return nil, ErrNotFound
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	grant, err := acceptInviteInTx(ctx, tx, codeHash, accepter, backScopes, backBags, s.nowUnix())
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// PairingTokenExists checks if a pairing token exists (is valid and not yet redeemed).
func (s *Store) PairingTokenExists(ctx context.Context, pairingTokenHash string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM invites WHERE pairing_token_hash=? AND used_by IS NULL AND expires_at >= ?`, pairingTokenHash, s.nowUnix()).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// AcceptInvite atomically consumes an invite and creates the inviter->accepter grant
// plus, optionally, a reciprocal accepter->inviter grant. Returns the inviter's grant.
func (s *Store) AcceptInvite(ctx context.Context, codeHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	// Read-only pre-check to avoid taking write lock for invalid codes
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT expires_at,used_by FROM invites WHERE code_hash=?`, codeHash).
		Scan(&exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < s.nowUnix() {
		return nil, ErrNotFound
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	grant, err := acceptInviteInTx(ctx, tx, codeHash, accepter, backScopes, backBags, s.nowUnix())
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// RegisterAndAcceptByPairing atomically registers a new peer and accepts a pairing invite.
// Returns the grant from the inviter.
func (s *Store) RegisterAndAcceptByPairing(ctx context.Context, pairingTokenHash, peerID, name, keyHash, notifyEmail, notifyToken string, backScopes, backBags []string) (grant *Grant, err error) {
	// #14 fix: Read-only check before BeginTx to avoid taking write lock for invalid tokens
	var codeHash, fromPeer string
	var exp int64
	var used sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT code_hash,from_peer,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
		Scan(&codeHash, &fromPeer, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	preCheckTime := s.nowUnix()
	if used.Valid || exp < preCheckTime {
		return nil, ErrNotFound
	}

	// Now begin transaction for writes
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Take timestamp inside tx for expires_at guard and created_at
	ts := s.nowUnix()

	verified := 0
	_, err = tx.ExecContext(ctx, `INSERT INTO peers(id,name,key_hash,created_at,notify_email,notify_email_verified,notify_email_token) VALUES(?,?,?,?,?,?,?)`,
		peerID, name, keyHash, ts, notifyEmail, verified, notifyToken)
	if err != nil {
		return nil, err
	}

	grant, err = acceptInviteInTx(ctx, tx, codeHash, peerID, backScopes, backBags, ts)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Add to key index after successful commit
	s.keyIndex.add(keyHash, peerID)

	return grant, nil
}

// acceptInviteInTx is the shared helper that atomically consumes an invite using a guarded
// update and creates grants. Must be called within a transaction. Every legacy accept path
// ends here, so confirm-mode, claimed and declined invites are refused here (as not found);
// only a confirm step may grant those.
func acceptInviteInTx(ctx context.Context, tx *sql.Tx, codeHash, accepter string, backScopes, backBags []string, now int64) (*Grant, error) {
	var from, scopes, bags string
	err := tx.QueryRowContext(ctx, `SELECT from_peer,scopes,bags FROM invites
		WHERE code_hash=? AND require_confirm=0 AND claimed_by IS NULL AND declined_at IS NULL
		AND used_by IS NULL AND expires_at>=?`, codeHash, now).
		Scan(&from, &scopes, &bags)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if from == accepter {
		return nil, ErrSelfPairing
	}

	// Before upserting grants, check if grants already exist and differ (#312).
	// Read existing grants inside the same transaction (never call Store methods in a write tx - #310).
	var existingScopes, existingBags sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT scopes, bags FROM grants WHERE owner=? AND grantee=?`, from, accepter).
		Scan(&existingScopes, &existingBags)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// If a grant exists and differs, return ErrConflict without touching the invite or grants
	forwardIdentical := false
	if existingScopes.Valid {
		if !grantsEqual(scopes, bags, existingScopes.String, existingBags.String) {
			return nil, ErrConflict
		}
		forwardIdentical = true
	}

	// If back scopes are present, also check the reverse grant
	reverseIdentical := false
	if len(backScopes) > 0 {
		backScopesStr, backBagsStr := join(backScopes), join(backBags)
		var existingBackScopes, existingBackBags sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT scopes, bags FROM grants WHERE owner=? AND grantee=?`, accepter, from).
			Scan(&existingBackScopes, &existingBackBags)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}

		if existingBackScopes.Valid {
			if !grantsEqual(backScopesStr, backBagsStr, existingBackScopes.String, existingBackBags.String) {
				return nil, ErrConflict
			}
			reverseIdentical = true
		}
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE invites SET used_by=? WHERE code_hash=? AND used_by IS NULL AND expires_at>=?
		 AND require_confirm=0 AND claimed_by IS NULL AND declined_at IS NULL`,
		accepter, codeHash, now)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrNotFound
	}

	// Skip grant rewrite on identical re-accept to keep created_at and row order stable.
	// Still consume the invite exactly as today.
	skipWrite := forwardIdentical && (len(backScopes) == 0 || reverseIdentical)
	if !skipWrite {
		if err := writeGrantsInTx(ctx, tx, from, accepter, scopes, bags, backScopes, backBags, now); err != nil {
			return nil, err
		}
	}

	return &Grant{Owner: from, Grantee: accepter, Scopes: split(scopes), Bags: split(bags)}, nil
}

// writeGrantsInTx upserts the inviter->accepter grant and, when backScopes is set, the reciprocal one.
func writeGrantsInTx(ctx context.Context, tx *sql.Tx, from, accepter, scopes, bags string, backScopes, backBags []string, now int64) error {
	up := `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)
	       ON CONFLICT(owner,grantee) DO UPDATE SET scopes=excluded.scopes, bags=excluded.bags, created_at=excluded.created_at`
	if _, err := tx.ExecContext(ctx, up, from, accepter, scopes, bags, now); err != nil {
		return err
	}
	if len(backScopes) > 0 {
		if _, err := tx.ExecContext(ctx, up, accepter, from, join(backScopes), join(backBags), now); err != nil {
			return err
		}
	}

	return nil
}

// GetGrant returns what grantee may do on owner's resources. ErrNotFound = deny.
func (s *Store) GetGrant(ctx context.Context, owner, grantee string) (*Grant, error) {
	var scopes, bags string
	err := s.db.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, owner, grantee).Scan(&scopes, &bags)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Grant{Owner: owner, Grantee: grantee, Scopes: split(scopes), Bags: split(bags)}, nil
}

// ListGrants returns grants where peer is owner or grantee.
func (s *Store) ListGrants(ctx context.Context, peer string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT owner,grantee,scopes,bags FROM grants WHERE owner=? OR grantee=? ORDER BY created_at`, peer, peer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		var sc, bg string
		if err := rows.Scan(&g.Owner, &g.Grantee, &sc, &bg); err != nil {
			return nil, err
		}
		g.Scopes, g.Bags = split(sc), split(bg)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant removes the grant owner->grantee.
func (s *Store) RevokeGrant(ctx context.Context, owner, grantee string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE owner=? AND grantee=?`, owner, grantee)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- messages ----

type Message struct {
	ID        int64     `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Type      string    `json:"type"`
	Body      string    `json:"body"`
	ReplyTo   *int64    `json:"reply_to,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) InsertMessage(ctx context.Context, m *Message) error {
	ts := s.nowUnix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO messages(sender,recipient,type,body,reply_to,created_at) VALUES(?,?,?,?,?,?)`,
		m.From, m.To, m.Type, m.Body, m.ReplyTo, ts)
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	m.CreatedAt = time.Unix(ts, 0).UTC()
	return nil
}

// MessageVisible reports whether message id was sent to or by peer (for reply_to checks).
func (s *Store) MessageVisible(ctx context.Context, id int64, peer string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM messages WHERE id=? AND (sender=? OR recipient=?)`, id, peer, peer).Scan(&n)
	return n > 0, err
}

func (s *Store) Inbox(ctx context.Context, recipient string, since int64, limit int) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,sender,recipient,type,body,reply_to,created_at FROM messages
		WHERE recipient=? AND id>? ORDER BY id LIMIT ?`, recipient, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		var rt sql.NullInt64
		var ts int64
		if err := rows.Scan(&m.ID, &m.From, &m.To, &m.Type, &m.Body, &rt, &ts); err != nil {
			return nil, err
		}
		if rt.Valid {
			v := rt.Int64
			m.ReplyTo = &v
		}
		m.CreatedAt = time.Unix(ts, 0).UTC()
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- bags ----

type Bag struct {
	Owner     string
	Name      string
	Content   []byte
	Version   int64
	UpdatedBy string
	UpdatedAt time.Time
}

func (s *Store) GetBag(ctx context.Context, owner, name string) (*Bag, error) {
	b := Bag{Owner: owner, Name: name}
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT content,version,updated_by,updated_at FROM bags WHERE owner=? AND name=?`, owner, name).
		Scan(&b.Content, &b.Version, &b.UpdatedBy, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.UpdatedAt = time.Unix(ts, 0).UTC()
	return &b, nil
}

// PutBag writes a bag. If ifVersion >= 0 it must match the current version
// (0 = must not exist yet); otherwise ErrConflict. ifVersion < 0 = unconditional.
// maxBagsPerPeer and maxBagBytesPerPeer enforce caps (must be positive; no zero = unlimited).
func (s *Store) PutBag(ctx context.Context, owner, name string, content []byte, by string, ifVersion int64, maxBagsPerPeer int, maxBagBytesPerPeer int64) (int64, error) {
	if maxBagsPerPeer <= 0 || maxBagBytesPerPeer <= 0 {
		return 0, errors.New("bag limits must be positive")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Get current version and content size
	var cur int64
	var oldSize int
	err = tx.QueryRowContext(ctx, `SELECT version, LENGTH(content) FROM bags WHERE owner=? AND name=?`, owner, name).Scan(&cur, &oldSize)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	if ifVersion >= 0 && ifVersion != cur {
		return cur, ErrConflict
	}

	// Enforce storage limits for creates and updates
	var count int
	var totalBytes int64
	err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) FROM bags WHERE owner=?`,
		owner).Scan(&count, &totalBytes)
	if err != nil {
		return 0, err
	}

	newSize := int64(len(content))

	// For new bag creation: enforce bag count limit
	if !exists && count >= maxBagsPerPeer {
		return 0, ErrBagLimitExceeded
	}

	// For both creates and updates: enforce byte quota
	// Allow updates that don't grow (newSize <= oldSize) even when over quota
	newTotal := totalBytes - int64(oldSize) + newSize
	if newSize > int64(oldSize) && newTotal > maxBagBytesPerPeer {
		return 0, ErrStorageQuotaExceeded
	}

	next := cur + 1
	_, err = tx.ExecContext(ctx, `INSERT INTO bags(owner,name,content,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(owner,name) DO UPDATE SET content=excluded.content, version=excluded.version,
		updated_by=excluded.updated_by, updated_at=excluded.updated_at`, owner, name, content, next, by, s.nowUnix())
	if err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// ---- Key Index (#112) ----

// LoadKeyIndex loads all active API key hashes from the peers table into memory.
// Must be called once at startup before serving requests.

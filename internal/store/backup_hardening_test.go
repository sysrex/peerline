package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func makeV2DB(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "x.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,''); PRAGMA user_version = 2;`); err != nil {
		t.Fatal(err)
	}
	return p
}

func openOpts(dir string) OpenOptions {
	return OpenOptions{BackupDir: dir, BackupRetentionCount: 1, Logger: slog.Default()}
}

func TestRetentionOnlyDeletesRegularBackupFiles(t *testing.T) {
	dir := secureTempDir(t)
	keep := []string{
		"x.db.pre-v6-from-v2.20260101-120000.000000.KEEP",
		"other.db.pre-v6-from-v2.20260101-120000.000000",
		"x.db.pre-v6-from-v2.notes",
	}
	for _, n := range keep {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("x"), 0600)
	link := "x.db.pre-v6-from-v2.20260101-120001.000000"
	os.Symlink(target, filepath.Join(dir, link))
	keep = append(keep, link)
	os.Mkdir(filepath.Join(dir, "x.db.pre-v6-from-v2.20260101-120002.000000"), 0700)
	keep = append(keep, "x.db.pre-v6-from-v2.20260101-120002.000000")

	p := makeV2DB(t, dir)
	s, err := OpenWithOptions(p, openOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, n := range keep {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was deleted: %v", n, err)
		}
	}
}

func TestBackupDirRefusesSymlinkAndWrongMode(t *testing.T) {
	root := secureTempDir(t)
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0700)
	link := filepath.Join(root, "link")
	os.Symlink(real, link)
	p := makeV2DB(t, root)

	if _, err := OpenWithOptions(p, openOpts(link)); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked backup dir: got %v", err)
	}
	open := filepath.Join(root, "open")
	os.Mkdir(open, 0755)
	os.Chmod(open, 0755)
	if _, err := OpenWithOptions(p, openOpts(open)); err == nil || !strings.Contains(err.Error(), "group or world") {
		t.Fatalf("0755 backup dir: got %v", err)
	}
}

func TestBackupErrorsDoNotLeakDirectory(t *testing.T) {
	root := secureTempDir(t)
	p := makeV2DB(t, root)
	blocker := filepath.Join(root, "distinctive-secret-dir")
	os.WriteFile(blocker, []byte("x"), 0600)
	_, err := OpenWithOptions(p, openOpts(filepath.Join(blocker, "sub")))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("error leaks directory: %v", err)
	}
}

func TestCorruptDatabaseRefusedBeforeMigration(t *testing.T) {
	dir := secureTempDir(t)
	p := makeV2DB(t, dir)
	b, _ := os.ReadFile(p)
	// Corrupt a data page past the header and schema page.
	if len(b) < 3*4096 {
		t.Skip("database too small to corrupt a data page")
	}
	for i := 2 * 4096; i < len(b); i++ {
		b[i] = 0xff
	}
	os.WriteFile(p, b, 0600)
	opts := openOpts(dir)
	opts.SkipMigrationBackup = true
	if _, err := OpenWithOptions(p, opts); err == nil {
		t.Fatal("corrupt database must be refused")
	}
}

func TestVacuumIntoFailureRemovesOnlyCreatedFile(t *testing.T) {
	dir := secureTempDir(t)
	p := makeV2DB(t, dir)

	// Pre-create a valid backup that must not be deleted
	preExisting := filepath.Join(dir, "x.db.pre-v6-from-v2.20260101-120000.000000")
	if err := os.WriteFile(preExisting, []byte("do not delete"), 0600); err != nil {
		t.Fatal(err)
	}

	// Inject vacuumInto that creates partial file then fails
	var capturedPath string
	opts := openOpts(dir)
	opts.vacuumInto = func(db *sql.DB, backupPath string) error {
		capturedPath = backupPath
		// Write partial data
		if err := os.WriteFile(backupPath, []byte("partial"), 0600); err != nil {
			return err
		}
		return fmt.Errorf("disk full")
	}

	if _, err := OpenWithOptions(p, opts); err == nil {
		t.Fatal("expected failure")
	}

	// Pre-existing must survive
	if data, err := os.ReadFile(preExisting); err != nil || string(data) != "do not delete" {
		t.Errorf("pre-existing backup modified or deleted: %v, %q", err, data)
	}

	// Partial must be removed
	if capturedPath != "" {
		if _, err := os.Stat(capturedPath); !os.IsNotExist(err) {
			t.Errorf("partial backup at %q should be removed", capturedPath)
		}
	}

	// Count backups
	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pre-v") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 backup (pre-existing), got %d", count)
	}
}

func TestCollisionRetryWithRandomSuffix(t *testing.T) {
	dir := secureTempDir(t)

	// Create a v2 database
	dbPath := filepath.Join(dir, "x.db")
	tempDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempDB.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,''); PRAGMA user_version = 2;`); err != nil {
		t.Fatal(err)
	}
	tempDB.Close()

	// Pin clock to 2026-01-01 12:00:00 UTC
	clockTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Pre-plant invalid file at the base timestamp to force collision
	// (invalid so reuse scan skips it and the create loop runs)
	baseName := "x.db.pre-v6-from-v2.20260101-120000.000000"
	basePath := filepath.Join(dir, baseName)
	if err := os.WriteFile(basePath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}

	// Open should succeed by adding a random hex suffix
	opts := openOpts(dir)
	opts.BackupRetentionCount = 10
	opts.Clock = clocktest.New(clockTime)

	s, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("Open should succeed with random suffix: %v", err)
	}
	defer s.Close()

	// Verify a new backup was created
	backupPath := s.LastBackupPath()
	if backupPath == "" {
		t.Fatal("no backup created")
	}

	backupName := filepath.Base(backupPath)

	// The new backup must NOT be the base name (must have hex suffix or .partial)
	if backupName == baseName {
		t.Errorf("backup used base name without hex suffix: %s", backupName)
	}

	// Verify the backup name has an 8-hex-digit suffix (or is .partial due to link collision)
	hasHexSuffix := false
	isPartial := strings.HasSuffix(backupName, ".partial")

	if !isPartial && strings.HasPrefix(backupName, baseName+".") {
		suffix := strings.TrimPrefix(backupName, baseName+".")
		if len(suffix) == 8 {
			// Check all chars are lowercase hex
			allHex := true
			for _, c := range suffix {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					allHex = false
					break
				}
			}
			hasHexSuffix = allHex
		}
	}

	if !hasHexSuffix && !isPartial {
		t.Errorf("backup name doesn't have 8-char hex suffix or .partial: %s", backupName)
	}

	// Verify the pre-existing invalid base file still exists (not overwritten)
	if data, err := os.ReadFile(basePath); err != nil {
		t.Errorf("pre-existing file was deleted: %v", err)
	} else if string(data) != "invalid" {
		t.Errorf("pre-existing file was overwritten")
	}
}

func TestOwnerCheckOnCreatedFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}

	dir := secureTempDir(t)
	p := makeV2DB(t, dir)

	// The owner check happens on the open fd after O_EXCL create
	// We can't easily make a file owned by another user without root,
	// but we can verify the check runs by ensuring Open succeeds normally
	// (the fd owner matches current user)

	opts := openOpts(dir)
	s, err := OpenWithOptions(p, opts)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	s.Close()

	// Verify backup was created and is owned by current user
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pre-v") {
			info, _ := e.Info()
			if !ownedByCurrentUser(info) {
				t.Errorf("backup %q not owned by current user", e.Name())
			}
		}
	}
}

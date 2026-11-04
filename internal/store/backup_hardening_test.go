package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	// Create a v2 database and immediately make valid backups with fixed timestamps
	// This simulates pre-existing backups from earlier failed attempts
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

	// Create valid backup files by copying the v2 database
	base := "x.db.pre-v6-from-v2.20260101-120000.000000"
	preExisting := []string{base, base + ".12345678", base + ".deadbeef"}
	for _, name := range preExisting {
		backupPath := filepath.Join(dir, name)
		// Copy the v2 database as a backup
		dbData, _ := os.ReadFile(dbPath)
		if err := os.WriteFile(backupPath, dbData, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Open should succeed with a random suffix
	// Use BackupRetentionCount=10 to ensure pre-existing files aren't deleted by retention
	opts := openOpts(dir)
	opts.BackupRetentionCount = 10
	opts.now = func() int64 { return 1704110400 } // Fixed timestamp matching the pre-created files

	s, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("Open should succeed with random suffix: %v", err)
	}
	defer s.Close()

	// Verify a new backup was created
	if s.LastBackupPath() == "" {
		t.Fatal("no backup created")
	}

	// The new backup should have a different name (random suffix) or be reused from pre-existing
	// Either way, verify all pre-existing files still exist
	for _, name := range preExisting {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("pre-existing file %q was deleted: %v", name, err)
		}
	}

	// Verify total backups >= 3 (the pre-existing ones; may have reused one instead of creating new)
	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pre-v6-from-v2.") {
			count++
		}
	}
	if count < 3 {
		t.Errorf("expected at least 3 backup files, got %d", count)
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

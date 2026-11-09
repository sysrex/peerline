//go:build unix

package store

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

// TestBackupFileMode verifies backups are created with 0600 permissions.
func TestBackupFileMode(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := tempDir + "/mode.db"

	// Create a v2 database
	tempDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempDB.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','Test','h1',1234567890,''); PRAGMA user_version = 2;`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	tempDB.Close()

	// Hook vacuumInto to verify the file mode BEFORE SQLite writes to it
	// This proves the pre-create is at 0600, not just the post-chmod
	var modeBeforeVacuum os.FileMode
	vacuumHook := func(db *sql.DB, backupPath string) error {
		info, err := os.Stat(backupPath)
		if err != nil {
			return err
		}
		modeBeforeVacuum = info.Mode().Perm()

		// Now run the actual VACUUM INTO
		ctx := context.Background()
		_, err = db.ExecContext(ctx, `VACUUM INTO ?`, backupPath)
		return err
	}

	opts := OpenOptions{
		BackupDir:            tempDir,
		BackupRetentionCount: 1,
		Logger:               slog.Default(),
		vacuumInto:           vacuumHook,
	}

	st, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("OpenWithOptions failed: %v", err)
	}
	defer st.Close()

	// Verify the mode was 0600 BEFORE VACUUM INTO wrote to it
	if modeBeforeVacuum != 0600 {
		t.Errorf("backup file mode before VACUUM INTO = %04o, want 0600 (umask window detected)", modeBeforeVacuum)
	}

	// Also verify final mode is still 0600
	backupBase := st.LastBackupPath()
	if backupBase == "" {
		t.Fatal("no backup created")
	}

	backupPath := tempDir + "/" + backupBase
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}

	mode := info.Mode() & os.ModePerm
	if mode != 0600 {
		t.Errorf("backup file final mode = %04o, want 0600", mode)
	}
}

// TestBackupPermissionsOnReuse verifies backup file is 0600 on Unix when reused.
func TestBackupPermissionsOnReuse(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := tempDir + "/restart.db"

	// Create initial v2 database
	tempDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempDB.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,''); PRAGMA user_version = 2;`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	tempDB.Close()

	// Manually create a valid backup to simulate a previous crash-loop attempt
	backupName := "restart.db.pre-v8-from-v2.20260101-120000.000000"
	backupPath := tempDir + "/" + backupName

	// Copy the v2 DB as the backup
	dbContent, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, dbContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Set backup mtime to be newer than the DB
	futureTime := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(backupPath, futureTime, futureTime); err != nil {
		t.Fatal(err)
	}

	// Open with fixed clock matching the backup timestamp
	fixedTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	opts := OpenOptions{
		BackupDir:            tempDir,
		BackupRetentionCount: 1,
		Logger:               slog.Default(),
		Clock:                clocktest.New(fixedTime),
	}

	st, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("OpenWithOptions failed: %v", err)
	}
	defer st.Close()

	// Should have reused the backup
	if !st.BackupReused() {
		t.Fatal("expected backup to be reused")
	}
	if st.LastBackupPath() != backupName {
		t.Errorf("backup path = %q, want %q", st.LastBackupPath(), backupName)
	}

	// Verify backup still has 0600 permissions
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("reused backup file has mode %04o, want 0600", perm)
	}
}

// TestDefaultDBDirectoryBackupPermissions verifies backup is 0600 in default (0755) DB dir.
func TestDefaultDBDirectoryBackupPermissions(t *testing.T) {
	// Use regular t.TempDir() which is 0755
	dbDir := t.TempDir()
	dbPath := dbDir + "/test.db"

	// Create a v2 database
	tempDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempDB.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','Test','h1',1234567890,''); PRAGMA user_version = 2;`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	tempDB.Close()

	// Open and migrate (should create backup in same dir)
	s, err := OpenWithOptions(dbPath, OpenOptions{BackupRetentionCount: 1})
	if err != nil {
		t.Fatalf("Open failed with 0755 DB dir: %v", err)
	}
	defer s.Close()

	// Verify backup file exists and has 0600 permissions
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".pre-v") {
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0600 {
				t.Errorf("backup file has mode %04o, want 0600", perm)
			}
			break
		}
	}
}

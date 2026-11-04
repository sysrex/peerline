//go:build unix

package store

import (
	"database/sql"
	"log/slog"
	"os"
	"testing"
)

// TestEarlyTighteningOnMigrationFailure verifies that existing database files
// are tightened to 0600 even when migration fails. This ensures files are secured
// before any migration or backup work begins.
func TestEarlyTighteningOnMigrationFailure(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"

	// Create a v2 database with loose permissions (0644)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1', 'Test', 'hash1', 1234567890, '');
		PRAGMA user_version = 2;
	`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	// Set the DB to 0644 (loose permissions)
	if err := os.Chmod(dbPath, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify it's 0644
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("setup failed: DB mode = %o, want 0644", info.Mode().Perm())
	}

	// Create an unwritable backup directory to force migration failure
	// (non-root test: we can make a dir unreadable/unwritable for ourselves)
	if os.Getuid() == 0 {
		t.Skip("test requires non-root to test unwritable directory")
	}

	badBackupDir := dir + "/bad-backup"
	if err := os.Mkdir(badBackupDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(badBackupDir, 0700) // Restore for cleanup

	// Attempt to open with migration - should fail due to unwritable backup dir
	opts := OpenOptions{
		BackupDir:            badBackupDir,
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
	}

	_, err = OpenWithOptions(dbPath, opts)
	if err == nil {
		t.Fatal("OpenWithOptions should have failed with unwritable backup dir")
	}

	// Verify the DB file was tightened to 0600 despite the migration failure
	info, err = os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("DB should be tightened to 0600 even on migration failure, got %o", info.Mode().Perm())
	}
}

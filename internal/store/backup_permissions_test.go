package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultDBDirectoryPermissions verifies that a 0755 database directory
// (the common default) allows backups when a migration is pending.
// This is the main fix for the review: default DB dir should only refuse writable (0022),
// not all access (0077).
func TestDefaultDBDirectoryPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root (chmod doesn't restrict root)")
	}

	ctx := context.Background()

	// Create a 0755 directory (typical default)
	baseDir := t.TempDir()
	dbDir := filepath.Join(baseDir, "data")
	if err := os.Mkdir(dbDir, 0755); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dbDir, "test.db")

	// Create a v2 database manually (will require migration to v6)
	db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}

	// Create minimal v2 schema
	schema := `
		PRAGMA journal_mode=WAL;
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT,
			pairing_token_hash TEXT
		);
		CREATE TABLE grants (
			owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (owner, grantee)
		);
		CREATE TABLE messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			body TEXT NOT NULL,
			reply_to INTEGER,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX messages_inbox ON messages(recipient, id);
		CREATE TABLE bags (
			owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			content BLOB NOT NULL,
			version INTEGER NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (owner, name)
		);
		CREATE INDEX invites_expires_at ON invites(expires_at);
		PRAGMA user_version = 2;
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		t.Fatal(err)
	}

	// Insert test data
	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('p1','test','h1',1,'')`); err != nil {
		db.Close()
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Now open the database - this should trigger migration from v2 to v6
	// With the fix, the 0755 directory should be accepted (only 0022 bits checked)
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with 0755 DB directory: %v", err)
	}
	defer s.Close()

	// Verify migration succeeded
	if s.SchemaVersionInUse() != SchemaVersion() {
		t.Errorf("expected schema version %d, got %d", SchemaVersion(), s.SchemaVersionInUse())
	}

	// Verify backup was created
	if s.LastBackupPath() == "" {
		t.Error("expected backup to be created during migration")
	}

	// Verify the peer exists
	_, err = s.PeerByKeyHash(ctx, "h1")
	if err != nil {
		t.Errorf("peer not found after migration: %v", err)
	}

	// Verify backup file exists and has 0600 permissions
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "test.db.pre-v") {
			found = true
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

	if !found {
		t.Error("backup file not found in database directory")
	}
}

// TestGroupWritableDBDirectoryRefused verifies that a group-writable (0775)
// or world-writable (0777) database directory is refused when migration is pending
// AND using the default backup location (the DB directory itself).
// Note: This only matters when the DB directory itself is writable; a 0755 (readable)
// directory is allowed. The test verifies the 0022 check works.
func TestGroupWritableDBDirectoryRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root (chmod doesn't restrict root)")
	}

	testCases := []struct {
		name string
		mode os.FileMode
		want string // substring expected in error
	}{
		{"group-writable 0770", 0770, "group or world writable"},
		{"world-writable 0777", 0777, "group or world writable"},
		{"group-and-world-writable 0766", 0766, "group or world writable"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := t.TempDir()
			dbDir := filepath.Join(baseDir, "data")
			if err := os.Mkdir(dbDir, 0700); err != nil {
				t.Fatal(err)
			}

			// Change to writable mode after creation
			if err := os.Chmod(dbDir, tc.mode); err != nil {
				t.Fatal(err)
			}

			dbPath := filepath.Join(dbDir, "test.db")

			// Create a v2 database that will need migration
			db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
			if err != nil {
				t.Fatal(err)
			}

			// Minimal v2 schema with data
			schema := `
				PRAGMA journal_mode=WAL;
				CREATE TABLE peers (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					key_hash TEXT NOT NULL UNIQUE,
					created_at INTEGER NOT NULL,
					notify_email TEXT NOT NULL DEFAULT ''
				);
				PRAGMA user_version = 2;
			`

			if _, err := db.Exec(schema); err != nil {
				db.Close()
				t.Fatal(err)
			}

			if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('p1','test','h1',1,'')`); err != nil {
				db.Close()
				t.Fatal(err)
			}

			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			// Now try to open - should fail due to directory permissions
			_, err = Open(dbPath)
			if err == nil {
				t.Fatal("expected error for writable directory, got nil")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestExplicitBackupDirStrictPermissions verifies that PEERLINE_BACKUP_DIR
// requires strict 0700 permissions (no group/world access at all).
func TestExplicitBackupDirStrictPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root (chmod doesn't restrict root)")
	}

	testCases := []struct {
		name string
		mode os.FileMode
		want string
	}{
		{"readable 0755", 0755, "allows group or world access"},
		{"group-writable 0770", 0770, "allows group or world access"},
		{"world-writable 0777", 0777, "allows group or world access"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := t.TempDir()
			dbDir := filepath.Join(baseDir, "data")
			if err := os.Mkdir(dbDir, 0700); err != nil {
				t.Fatal(err)
			}

			backupDir := filepath.Join(baseDir, "backups")
			if err := os.Mkdir(backupDir, tc.mode); err != nil {
				t.Fatal(err)
			}

			dbPath := filepath.Join(dbDir, "test.db")

			// Create a v2 database
			db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
			if err != nil {
				t.Fatal(err)
			}

			schema := `
				PRAGMA journal_mode=WAL;
				CREATE TABLE peers (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					key_hash TEXT NOT NULL UNIQUE,
					created_at INTEGER NOT NULL,
					notify_email TEXT NOT NULL DEFAULT ''
				);
				PRAGMA user_version = 2;
			`

			if _, err := db.Exec(schema); err != nil {
				db.Close()
				t.Fatal(err)
			}

			if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('p1','test','h1',1,'')`); err != nil {
				db.Close()
				t.Fatal(err)
			}

			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			// Try to open with explicit backup dir
			opts := OpenOptions{
				BackupDir:            backupDir,
				BackupRetentionCount: 3,
			}

			_, err = OpenWithOptions(dbPath, opts)
			if err == nil {
				t.Fatal("expected error for non-0700 explicit backup dir, got nil")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestBackupDir0700Success verifies that an explicit backup dir with 0700 works.
func TestBackupDir0700Success(t *testing.T) {
	ctx := context.Background()

	baseDir := t.TempDir()
	dbDir := filepath.Join(baseDir, "data")
	if err := os.Mkdir(dbDir, 0755); err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(baseDir, "backups")
	if err := os.Mkdir(backupDir, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dbDir, "test.db")

	// Create a v2 database
	db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}

	schema := `
		PRAGMA journal_mode=WAL;
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		PRAGMA user_version = 2;
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('p1','test','h1',1,'')`); err != nil {
		db.Close()
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Open with explicit 0700 backup dir - should succeed
	opts := OpenOptions{
		BackupDir:            backupDir,
		BackupRetentionCount: 3,
	}

	s, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("Open failed with 0700 backup dir: %v", err)
	}
	defer s.Close()

	// Verify migration succeeded
	if s.SchemaVersionInUse() != SchemaVersion() {
		t.Errorf("expected schema version %d, got %d", SchemaVersion(), s.SchemaVersionInUse())
	}

	// Verify backup was created
	if s.LastBackupPath() == "" {
		t.Error("expected backup to be created")
	}

	// Verify backup is in the explicit backup dir, not the DB dir
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "test.db.pre-v") {
			found = true
			break
		}
	}

	if !found {
		t.Error("backup file not found in explicit backup directory")
	}

	// Verify backup is NOT in the DB dir
	dbEntries, err := os.ReadDir(dbDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range dbEntries {
		if strings.HasPrefix(entry.Name(), "test.db.pre-v") {
			t.Error("backup file should not be in DB directory when explicit backup dir is used")
		}
	}

	// Verify the peer exists
	_, err = s.PeerByKeyHash(ctx, "h1")
	if err != nil {
		t.Errorf("peer not found after migration: %v", err)
	}
}

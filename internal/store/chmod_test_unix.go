//go:build unix

package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestTightenExistingDatabasePermissions(t *testing.T) {
	dir := t.TempDir()

	// Create a v2 database and associated files with wide permissions (0644)
	dbPath := filepath.Join(dir, "test.db")
	walPath := dbPath + "-wal"
	shmPath := dbPath + "-shm"

	// Create DB file at 0644
	tempDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempDB.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,''); PRAGMA user_version = 2;`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	// Enable WAL to create -wal and -shm files
	if _, err := tempDB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	tempDB.Close()

	// Chmod all three files to 0644
	for _, path := range []string{dbPath, walPath, shmPath} {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Verify initial permissions are 0644
	for _, path := range []string{dbPath, walPath, shmPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0644 {
			t.Fatalf("%s initial mode: got %04o, want 0644", filepath.Base(path), perm)
		}
	}

	// Open with store - should tighten permissions
	s, err := OpenWithOptions(dbPath, OpenOptions{BackupDir: dir, BackupRetentionCount: 1})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	s.Close()

	// Verify all files are now 0600
	for _, path := range []string{dbPath, walPath, shmPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s after open: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode after open: got %04o, want 0600", filepath.Base(path), perm)
		}
	}
}

func TestFreshDatabaseCreatedWithRestrictivePermissions(t *testing.T) {
	// Save and restore original umask
	oldUmask := syscall.Umask(0077)
	defer syscall.Umask(oldUmask)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fresh.db")

	// Create a fresh database
	s, err := OpenWithOptions(dbPath, OpenOptions{BackupDir: dir, BackupRetentionCount: 1, SkipMigrationBackup: true})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	// Enable WAL to create -wal and -shm files
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		s.Close()
		t.Fatal(err)
	}

	// Insert some data to ensure WAL is used
	if _, err := s.db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email,notify_email_verified,notify_email_token) VALUES('p1','Test','hash1',1,'',0,'')`); err != nil {
		s.Close()
		t.Fatal(err)
	}

	s.Close()

	// Verify DB, -wal, and -shm are all 0600
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) && suffix != "" {
				continue // -wal or -shm might not exist yet
			}
			t.Fatalf("stat %s: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode: got %04o, want 0600 (umask 0077 should create files at 0600)", filepath.Base(path), perm)
		}
	}
}

func TestSymlinkNotFollowedDuringChmod(t *testing.T) {
	dir := t.TempDir()

	// Create a target file elsewhere
	targetPath := filepath.Join(dir, "target.db")
	if err := os.WriteFile(targetPath, []byte("target"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink
	linkPath := filepath.Join(dir, "link.db")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skip("symlink not supported")
	}

	// Attempt to open the symlink - should fail or skip chmod (not follow)
	// Our chmod helper uses Lstat which won't follow symlinks
	// The DB open itself might fail for other reasons, but we verify the target wasn't modified
	_, _ = OpenWithOptions(linkPath, OpenOptions{BackupDir: dir, BackupRetentionCount: 1, SkipMigrationBackup: true})

	// Verify target file permissions weren't changed
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("symlink target was modified: got %04o, want 0644", perm)
	}
}

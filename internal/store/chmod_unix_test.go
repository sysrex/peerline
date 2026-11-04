//go:build unix

package store

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTightenExistingDatabasePermissions(t *testing.T) {
	dir := t.TempDir()
	// Make directory 0700 so migration doesn't reject it
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

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
	// Insert data to ensure WAL file is created
	if _, err := tempDB.Exec(`INSERT INTO peers VALUES ('p2','T2','h2',2,'')`); err != nil {
		tempDB.Close()
		t.Fatal(err)
	}
	tempDB.Close()

	// Chmod all three files to 0644 (WAL and SHM should exist now)
	for _, path := range []string{dbPath, walPath, shmPath} {
		if err := os.Chmod(path, 0644); err != nil {
			if os.IsNotExist(err) && (path == walPath || path == shmPath) {
				continue // WAL/SHM might not exist yet, that's OK
			}
			t.Fatal(err)
		}
	}

	// Verify initial permissions are 0644 (for files that exist)
	for _, path := range []string{dbPath, walPath, shmPath} {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) && (path == walPath || path == shmPath) {
				continue // WAL/SHM might not exist yet
			}
			t.Fatalf("stat %s: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0644 {
			t.Fatalf("%s initial mode: got %04o, want 0644", filepath.Base(path), perm)
		}
	}

	// Open with store - should tighten permissions
	s, err := OpenWithOptions(dbPath, OpenOptions{BackupDir: dir, BackupRetentionCount: 1, SkipMigrationBackup: true})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	s.Close()

	// Verify all files that exist are now 0600
	for _, path := range []string{dbPath, walPath, shmPath} {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) && (path == walPath || path == shmPath) {
				continue // WAL/SHM might not have been created
			}
			t.Fatalf("stat %s after open: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode after open: got %04o, want 0600", filepath.Base(path), perm)
		}
	}
}

// TestFreshDatabaseWithManualUmask verifies that a fresh database created under
// umask 0077 (set directly, not via the binary's startup) creates files at 0600.
// The real #299 test is TestUmaskProtectsNewDatabaseFiles in cmd/peerline.
func TestFreshDatabaseWithManualUmask(t *testing.T) {
	// Set umask 0077 directly for this test
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

func TestTightenSkipsFIFO(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	walPath := dbPath + "-wal"

	// Create a FIFO at the -wal path
	if err := syscall.Mkfifo(walPath, 0644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	// Verify it's a FIFO
	info, err := os.Lstat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("expected FIFO, got regular file")
	}
	originalMode := info.Mode().Perm()

	// Call tightenDatabaseFilePermissions in a goroutine with 2s timeout
	done := make(chan bool, 1)
	go func() {
		tightenDatabaseFilePermissions(dbPath, slog.Default())
		done <- true
	}()

	select {
	case <-done:
		// OK, returned in time
	case <-time.After(2 * time.Second):
		t.Fatal("tightenDatabaseFilePermissions blocked on FIFO for >2s")
	}

	// Verify FIFO mode is unchanged
	afterInfo, err := os.Lstat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != originalMode {
		t.Errorf("FIFO mode changed: got %04o, want %04o", afterInfo.Mode().Perm(), originalMode)
	}
}

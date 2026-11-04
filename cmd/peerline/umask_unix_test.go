//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/sysrex/peerline/internal/store"
)

// TestUmaskProtectsNewDatabaseFiles verifies that setRestrictiveUmask() causes
// new database files (DB, WAL, SHM) to be created at 0600 when starting from
// umask 022. This is the #299 test going through the binary's startup path.
func TestUmaskProtectsNewDatabaseFiles(t *testing.T) {
	// Start from umask 022 (typical default)
	oldUmask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	// Call the binary's startup function
	setRestrictiveUmask()

	// Create a fresh database
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s, err := store.OpenWithOptions(dbPath, store.OpenOptions{
		BackupDir:            dir,
		BackupRetentionCount: 1,
		SkipMigrationBackup:  true,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}

	// Enable WAL mode and write data using the store's exported methods
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "p1", "Test", "hash1", "", ""); err != nil {
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
				continue // WAL or SHM might not exist yet
			}
			t.Fatalf("stat %s: %v", filepath.Base(path), err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode: got %04o, want 0600 (umask 0077 should create files at 0600)", filepath.Base(path), perm)
		}
	}
}

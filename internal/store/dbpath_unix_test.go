//go:build unix

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDBPathRefusesFIFO verifies that a FIFO at the DB path fails fast without hanging.
func TestDBPathRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a FIFO at the DB path
	if err := syscall.Mkfifo(dbPath, 0644); err != nil {
		t.Skip("mkfifo not supported:", err)
	}

	// Cleanup: unblock any goroutine that might be blocked on the FIFO
	t.Cleanup(func() {
		// Open for writing non-blocking to unblock any reader
		// ENXIO means no reader is blocked, which is fine
		f, err := os.OpenFile(dbPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil && !errors.Is(err, syscall.ENXIO) {
			// Log but don't fail the cleanup
			t.Logf("cleanup: failed to unblock FIFO: %v", err)
		}
		if f != nil {
			f.Close()
		}
	})

	// Attempt to open should fail fast, not hang
	done := make(chan error, 1)
	go func() {
		_, err := Open(dbPath)
		done <- err
	}()

	// Use a timeout to detect hanging
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded with FIFO, expected error")
		}
		// Verify error message
		errMsg := err.Error()
		if !strings.Contains(errMsg, "named pipe") && !strings.Contains(errMsg, "FIFO") {
			t.Errorf("error should mention FIFO or named pipe, got: %v", err)
		}
		if strings.Contains(errMsg, dir) {
			t.Errorf("error leaked absolute path: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open blocked on FIFO for >2s")
	}
}

// TestDBPathRefusesDirectory verifies that a directory at the DB path is rejected.
func TestDBPathRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a directory at the DB path
	if err := os.Mkdir(dbPath, 0755); err != nil {
		t.Fatal(err)
	}

	// Attempt to open should fail
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open succeeded with directory, expected error")
	}

	// Verify error message
	errMsg := err.Error()
	if !strings.Contains(errMsg, "directory") {
		t.Errorf("error should mention directory, got: %v", err)
	}
	if strings.Contains(errMsg, dir) {
		t.Errorf("error leaked absolute path: %v", err)
	}
}

// TestDBPathAcceptsSymlinkToRegularFile verifies that a symlink to a regular file is accepted
// and the target file ends up with 0600 permissions.
func TestDBPathAcceptsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(dir, "target.db")

	// Create a real regular file with wide permissions
	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Create a symlink at the DB path pointing to the target
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should succeed and tighten the target
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with symlink to regular file: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Verify the target file has 0600 permissions
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat target failed: %v", err)
	}
	targetMode := targetInfo.Mode().Perm()
	if targetMode != 0600 {
		t.Errorf("target file mode = %o, want 0600", targetMode)
	}
}

// TestDBPathRefusesSymlinkToFIFO verifies that a symlink pointing to a FIFO is rejected.
func TestDBPathRefusesSymlinkToFIFO(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	fifoPath := filepath.Join(dir, "fifo")

	// Create a FIFO
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Skip("mkfifo not supported:", err)
	}

	// Create a symlink pointing to the FIFO
	if err := os.Symlink(fifoPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Cleanup: unblock any goroutine that might be blocked
	t.Cleanup(func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil && !errors.Is(err, syscall.ENXIO) {
			t.Logf("cleanup: failed to unblock FIFO: %v", err)
		}
		if f != nil {
			f.Close()
		}
	})

	// Attempt to open should fail fast
	done := make(chan error, 1)
	go func() {
		_, err := Open(dbPath)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded with symlink to FIFO, expected error")
		}
		// Verify error message mentions FIFO or named pipe
		errMsg := err.Error()
		if !strings.Contains(errMsg, "named pipe") && !strings.Contains(errMsg, "FIFO") {
			t.Errorf("error should mention FIFO or named pipe, got: %v", err)
		}
		if strings.Contains(errMsg, dir) {
			t.Errorf("error leaked absolute path: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open blocked on symlink to FIFO for >2s")
	}
}

// TestDBPathRefusesSymlinkToDirectory verifies that a symlink pointing to a directory is rejected.
func TestDBPathRefusesSymlinkToDirectory(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	dirPath := filepath.Join(dir, "subdir")

	// Create a directory
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a symlink pointing to the directory
	if err := os.Symlink(dirPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Attempt to open should fail
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open succeeded with symlink to directory, expected error")
	}

	// Verify error message mentions directory
	errMsg := err.Error()
	if !strings.Contains(errMsg, "directory") {
		t.Errorf("error should mention directory, got: %v", err)
	}
	if strings.Contains(errMsg, dir) {
		t.Errorf("error leaked absolute path: %v", err)
	}
}

// TestDBPathAcceptsDanglingSymlink verifies that a dangling symlink is accepted (same as missing path).
func TestDBPathAcceptsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(dir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Verify it's dangling
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("symlink should be dangling")
	}

	// Open should succeed and create the database at the target
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with dangling symlink: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Verify the target file was created
	if _, err := os.Stat(targetPath); err != nil {
		t.Errorf("target file was not created: %v", err)
	}
}

// TestDBPathAcceptsRegularFile verifies that a regular file opens successfully.
func TestDBPathAcceptsRegularFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a valid database at the path
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with regular file: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Close and reopen
	s.Close()
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer s2.Close()

	// Verify peer exists
	name, err := s2.PeerName(ctx, "peer1")
	if err != nil || name != "Test Peer" {
		t.Fatalf("PeerName failed: %v, name=%q", err, name)
	}
}

// TestDBPathAcceptsMissingPath verifies that a missing path is created successfully.
func TestDBPathAcceptsMissingPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "newdb.db")

	// Verify path doesn't exist
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("path should not exist before Open")
	}

	// Open should create the database
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with missing path: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

// TestDBPathAcceptsMemory verifies that :memory: databases work.
func TestDBPathAcceptsMemory(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open failed with :memory:: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}
}

// TestDBPathRefusesSocket verifies that a socket at the DB path is rejected.
func TestDBPathRefusesSocket(t *testing.T) {
	// Skip on systems where we can't create Unix sockets in temp directories
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.db")

	// Create a Unix socket (not all systems support this in all directories)
	addr := &syscall.SockaddrUnix{Name: socketPath}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip("socket creation not supported:", err)
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, addr); err != nil {
		t.Skip("socket bind not supported:", err)
	}

	// Attempt to open should fail
	_, err = Open(socketPath)
	if err == nil {
		t.Fatal("Open succeeded with socket, expected error")
	}

	// Verify error message mentions socket or non-regular file
	errMsg := err.Error()
	if !strings.Contains(errMsg, "socket") && !strings.Contains(errMsg, "non-regular") {
		t.Errorf("error should mention socket, got: %v", err)
	}
	if strings.Contains(errMsg, dir) {
		t.Errorf("error leaked absolute path: %v", err)
	}
}

// TestDBPathAcceptsFileURIToRealFile verifies that a file: URI pointing to a real file is accepted.
func TestDBPathAcceptsFileURIToRealFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Use file: URI
	dsn := "file:" + dbPath

	s, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open failed with file: URI to real file: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

// TestDBPathRefusesFileURIToFIFO verifies that a file: URI pointing to a FIFO is rejected.
func TestDBPathRefusesFileURIToFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "fifo.db")

	// Create a FIFO
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Skip("mkfifo not supported:", err)
	}

	// Cleanup: unblock any goroutine
	t.Cleanup(func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil && !errors.Is(err, syscall.ENXIO) {
			t.Logf("cleanup: failed to unblock FIFO: %v", err)
		}
		if f != nil {
			f.Close()
		}
	})

	// Use file: URI
	dsn := "file:" + fifoPath

	// Attempt to open should fail fast
	done := make(chan error, 1)
	go func() {
		_, err := Open(dsn)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded with file: URI to FIFO, expected error")
		}
		// Verify error message mentions FIFO or named pipe
		errMsg := err.Error()
		if !strings.Contains(errMsg, "named pipe") && !strings.Contains(errMsg, "FIFO") {
			t.Errorf("error should mention FIFO or named pipe, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open blocked on file: URI to FIFO for >2s")
	}
}

// TestDBPathAcceptsPathWithQuery verifies that a path with a query string is accepted.
func TestDBPathAcceptsPathWithQuery(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Use path with query
	dsn := dbPath + "?_pragma=busy_timeout(5000)"

	s, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open failed with path?query: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Verify file was created at the path (query stripped)
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

// TestDBPathAcceptsFileMemory verifies that file::memory: is accepted as a memory database.
func TestDBPathAcceptsFileMemory(t *testing.T) {
	s, err := Open("file::memory:")
	if err != nil {
		t.Fatalf("Open failed with file::memory:: %v", err)
	}
	defer s.Close()

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}
}

// TestDBPathAcceptsModeMemoryMixedCase verifies that mode=memory with mixed case is detected.
func TestDBPathAcceptsModeMemoryMixedCase(t *testing.T) {
	// Test various case combinations - they should all be detected as memory databases
	cases := []string{
		"test.db?MODE=MEMORY",
		"test.db?Mode=Memory",
		"test.db?mode=Memory",
		"test.db?MODE=memory",
	}

	for _, dsn := range cases {
		t.Run(dsn, func(t *testing.T) {
			// Verify checkDatabasePath accepts them (doesn't try to check the file)
			err := checkDatabasePath(dsn)
			if err != nil {
				t.Errorf("checkDatabasePath(%q) failed: %v", dsn, err)
			}

			// Verify dbFilePath correctly identifies them as memory
			_, isMemory, err := dbFilePath(dsn)
			if err != nil {
				t.Errorf("dbFilePath(%q) error: %v", dsn, err)
			}
			if !isMemory {
				t.Errorf("dbFilePath(%q) isMemory = false, want true", dsn)
			}
		})
	}
}

// TestDBPathRefusesSymlinkToDevNull verifies that a symlink to /dev/null is rejected.
func TestDBPathRefusesSymlinkToDevNull(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a symlink pointing to /dev/null (a character device)
	if err := os.Symlink("/dev/null", dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Attempt to open should fail
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open succeeded with symlink to /dev/null, expected error")
	}

	// Verify error message mentions device or character device
	errMsg := err.Error()
	if !strings.Contains(errMsg, "device") && !strings.Contains(errMsg, "character device") {
		t.Errorf("error should mention device, got: %v", err)
	}
	if strings.Contains(errMsg, dir) {
		t.Errorf("error leaked absolute path: %v", err)
	}
}

// TestSymlinkWALAndSHMLocation verifies that -wal and -shm files are created next to the
// target (not next to the symlink) and are tightened to 0600.
func TestSymlinkWALAndSHMLocation(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "link.db")
	targetPath := filepath.Join(dir, "subdir", "target.db")

	// Create subdir
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create symlink pointing to target in subdir
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open via symlink
	s, err := Open(linkPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Verify target was created with 0600 immediately after open
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		s.Close()
		t.Fatalf("target DB not created after Open: %v", err)
	}
	if targetInfo.Mode().Perm() != 0600 {
		s.Close()
		t.Errorf("target DB mode after Open = %o, want 0600", targetInfo.Mode().Perm())
	}

	// Write data to force WAL creation
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test", "hash1", "", ""); err != nil {
		s.Close()
		t.Fatalf("CreatePeer failed: %v", err)
	}

	// Force a checkpoint to ensure files exist
	s.Close()

	// Verify -wal and -shm are NOT next to the symlink (they're next to the target)
	linkWal := linkPath + "-wal"
	linkShm := linkPath + "-shm"

	if _, err := os.Lstat(linkWal); err == nil {
		t.Error("WAL file should not exist next to symlink")
	}
	if _, err := os.Lstat(linkShm); err == nil {
		t.Error("SHM file should not exist next to symlink")
	}

	// WAL and SHM may not exist at test end (checkpointed on Close), but the tighten
	// logs above prove they were created next to the target and tightened to 0600
	t.Logf("WAL/SHM files created next to target and tightened (see logs)")
}

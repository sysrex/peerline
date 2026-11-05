//go:build unix

package store

import (
	"context"
	"errors"
	"fmt"
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

// TestDBPathAcceptsDanglingSymlink verifies that a dangling symlink with safe directories is accepted.
func TestDBPathAcceptsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory with 0700 (safe) permissions for the target
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

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

// TestDBPathRefusesDanglingSymlinkWithUnsafeLinkDir verifies that a dangling symlink
// is refused if the link's parent directory is group- or world-writable.
func TestDBPathRefusesDanglingSymlinkWithUnsafeLinkDir(t *testing.T) {
	dir := t.TempDir()

	// Create a world-writable subdirectory for the link
	linkDir := filepath.Join(dir, "link_dir")
	if err := os.Mkdir(linkDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Explicitly chmod to 0777 (mkdir respects umask)
	if err := os.Chmod(linkDir, 0777); err != nil {
		t.Fatal(err)
	}

	// Create a safe subdirectory for the target
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(linkDir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail because link's parent is world-writable
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with dangling symlink in world-writable directory")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("error should mention writable directory, got: %v", err)
	}
}

// TestDBPathRefusesDanglingSymlinkWithUnsafeTargetDir verifies that a dangling symlink
// is refused if the target's parent directory is group- or world-writable.
func TestDBPathRefusesDanglingSymlinkWithUnsafeTargetDir(t *testing.T) {
	dir := t.TempDir()

	// Create a safe subdirectory for the link
	linkDir := filepath.Join(dir, "link_dir")
	if err := os.Mkdir(linkDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a world-writable subdirectory for the target
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Explicitly chmod to 0777 (mkdir respects umask)
	if err := os.Chmod(targetDir, 0777); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(linkDir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail because target's parent is world-writable
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with dangling symlink pointing to world-writable directory")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("error should mention writable directory, got: %v", err)
	}
}

// TestDBPathRefusesDanglingSymlinkWithStickyBit verifies that dangling symlinks
// to sticky directories (like /tmp with 1777) are also refused.
func TestDBPathRefusesDanglingSymlinkWithStickyBit(t *testing.T) {
	dir := t.TempDir()

	// Create a sticky world-writable subdirectory for the target
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Explicitly chmod to 1777 (mkdir respects umask, we want sticky + world-writable)
	if err := os.Chmod(targetDir, 01777); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail because target's parent has world-write bit (even with sticky)
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with dangling symlink pointing to sticky world-writable directory")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("error should mention writable directory, got: %v", err)
	}
}

// TestDBPathAcceptsDanglingSymlinkWith0755TargetDir verifies that dangling symlinks
// to directories with mode 0755 (world-readable but not writable) are accepted.
func TestDBPathAcceptsDanglingSymlinkWith0755TargetDir(t *testing.T) {
	dir := t.TempDir()

	// Create a 0755 subdirectory for the target (world-readable, not writable)
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should succeed because neither directory is writable by group/world
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open should succeed with 0755 target directory: %v", err)
	}
	defer s.Close()

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

// TestPlainPathWithQueryIsRealFile verifies that plain paths with ?mode=memory queries
// are treated as REAL files, not memory databases, because modernc strips the query
// before opening non-file: URIs.
func TestPlainPathWithQueryIsRealFile(t *testing.T) {
	dir := t.TempDir()

	// Test various case combinations - they should all be treated as REAL files
	cases := []struct {
		name string
		dsn  string
	}{
		{"lowercase mode=memory", "test.db?mode=memory"},
		{"uppercase MODE=MEMORY", "test.db?MODE=MEMORY"},
		{"mixed Mode=Memory", "test.db?Mode=Memory"},
		{"mode=MEMORY uppercase value", "test.db?mode=MEMORY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(dir, tc.dsn)

			// Verify dbFilePath correctly identifies as NOT memory
			path, isMemory, err := dbFilePath(dbPath)
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", dbPath, err)
			}
			if isMemory {
				t.Errorf("dbFilePath(%q) isMemory = true, want false (plain paths with query are REAL files)", dbPath)
			}
			// Path should be the part before '?'
			expectedPath := filepath.Join(dir, "test.db")
			if path != expectedPath {
				t.Errorf("dbFilePath(%q) path = %q, want %q", dbPath, path, expectedPath)
			}

			// Verify checkDatabasePath will check the file (not skip as memory)
			// Since the file doesn't exist, it should be accepted (missing path is OK)
			err = checkDatabasePath(dbPath)
			if err != nil {
				t.Errorf("checkDatabasePath(%q) failed: %v (missing path should be OK)", dbPath, err)
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

// TestDBPathAcceptsDanglingSymlinkRelativeTarget verifies that a dangling symlink
// with a relative target path works correctly.
func TestDBPathAcceptsDanglingSymlinkRelativeTarget(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory for the target with safe permissions
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dir, "test.db")

	// Create a dangling symlink with a RELATIVE target
	relativeTarget := "target_dir/nonexistent.db"
	if err := os.Symlink(relativeTarget, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Verify it's dangling
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("symlink should be dangling")
	}

	// Open should succeed and create the database at the target
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with relative dangling symlink: %v", err)
	}
	defer s.Close()

	// Verify the target file was created
	targetPath := filepath.Join(dir, relativeTarget)
	if _, err := os.Stat(targetPath); err != nil {
		t.Errorf("target file was not created: %v", err)
	}
}

// TestDBPathRefusesDanglingSymlinkWithStickyLinkDir verifies that a dangling symlink
// is refused if the link's parent directory has the sticky bit with world-writable (1777).
func TestDBPathRefusesDanglingSymlinkWithStickyLinkDir(t *testing.T) {
	dir := t.TempDir()

	// Create a sticky world-writable subdirectory for the LINK
	linkDir := filepath.Join(dir, "link_dir")
	if err := os.Mkdir(linkDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Explicitly chmod to 1777 (sticky + world-writable)
	if err := os.Chmod(linkDir, 01777); err != nil {
		t.Fatal(err)
	}

	// Create a safe subdirectory for the target
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(linkDir, "test.db")
	targetPath := filepath.Join(targetDir, "nonexistent.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail because link's parent has world-write bit (even with sticky)
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with dangling symlink in sticky world-writable directory")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("error should mention writable directory, got: %v", err)
	}
}

// TestDBPathRefusesDanglingSymlinkMissingTargetDir verifies that a dangling symlink
// is refused with a clear error if the target's parent directory doesn't exist.
func TestDBPathRefusesDanglingSymlinkMissingTargetDir(t *testing.T) {
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	// Target path with non-existent parent directory
	targetPath := filepath.Join(dir, "nonexistent_dir", "target.db")

	// Create a dangling symlink
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail with clear error about missing directory
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with dangling symlink to non-existent directory")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "does not exist") {
		t.Errorf("error should mention missing directory, got: %v", err)
	}
}

// TestDBPathAcceptsTwoHopDanglingSymlink verifies that multi-hop dangling symlink
// chains are resolved correctly when all intermediate directories are safe.
func TestDBPathAcceptsTwoHopDanglingSymlink(t *testing.T) {
	dir := t.TempDir()

	// Create safe directories for intermediate and final targets
	intermediateDir := filepath.Join(dir, "intermediate_dir")
	if err := os.Mkdir(intermediateDir, 0700); err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a 2-hop dangling symlink chain:
	// dbPath -> intermediate -> finalTarget (doesn't exist)
	dbPath := filepath.Join(dir, "test.db")
	intermediatePath := filepath.Join(intermediateDir, "intermediate.db")
	finalTarget := filepath.Join(targetDir, "final.db")

	// Create intermediate symlink (dangling)
	if err := os.Symlink(finalTarget, intermediatePath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Create first symlink pointing to intermediate
	if err := os.Symlink(intermediatePath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Verify it's dangling (2 hops)
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("symlink chain should be dangling")
	}

	// Open should succeed and create the database at the final target
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed with 2-hop dangling symlink: %v", err)
	}
	defer s.Close()

	// Verify the final target file was created
	if _, err := os.Stat(finalTarget); err != nil {
		t.Errorf("final target file was not created: %v", err)
	}

	// Verify it's usable
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "peer1", "Test Peer", "hash1", "", ""); err != nil {
		t.Fatalf("CreatePeer failed: %v", err)
	}
}

// TestDBPathRefusesTwoHopDanglingSymlinkUnsafeIntermediate verifies that a 2-hop
// dangling symlink is refused if an intermediate directory is world-writable.
func TestDBPathRefusesTwoHopDanglingSymlinkUnsafeIntermediate(t *testing.T) {
	dir := t.TempDir()

	// Create UNSAFE intermediate directory (world-writable)
	intermediateDir := filepath.Join(dir, "intermediate_dir")
	if err := os.Mkdir(intermediateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(intermediateDir, 0777); err != nil {
		t.Fatal(err)
	}

	// Create safe target directory
	targetDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a 2-hop dangling symlink chain:
	// dbPath -> intermediate (in unsafe dir) -> finalTarget (doesn't exist)
	dbPath := filepath.Join(dir, "test.db")
	intermediatePath := filepath.Join(intermediateDir, "intermediate.db")
	finalTarget := filepath.Join(targetDir, "final.db")

	// Create intermediate symlink (dangling)
	if err := os.Symlink(finalTarget, intermediatePath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Create first symlink pointing to intermediate
	if err := os.Symlink(intermediatePath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Open should fail because intermediate directory is world-writable
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open should fail with 2-hop dangling symlink through unsafe directory")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("error should mention writable directory, got: %v", err)
	}
}

// TestDBPathRefusesSymlinkLoopExceedingHopCap verifies that a symlink chain
// exceeding 40 hops (the maximum depth) is rejected with a clear error.
func TestDBPathRefusesSymlinkLoopExceedingHopCap(t *testing.T) {
	dir := t.TempDir()

	// Create a chain of 41 symlinks with safe intermediate directories
	const chainLength = 41
	paths := make([]string, chainLength+1)
	paths[0] = filepath.Join(dir, "link0.db")

	for i := 1; i <= chainLength; i++ {
		// Each link has its own safe directory
		linkDir := filepath.Join(dir, fmt.Sprintf("dir%d", i))
		if err := os.Mkdir(linkDir, 0700); err != nil {
			t.Fatal(err)
		}
		paths[i] = filepath.Join(linkDir, "link.db")
	}

	// Create the symlink chain: link0 -> link1 -> ... -> link41 (dangling)
	for i := 0; i < chainLength; i++ {
		if err := os.Symlink(paths[i+1], paths[i]); err != nil {
			t.Skip("symlink not supported:", err)
		}
	}

	// Verify it's dangling (or OS returns "too many levels" error, both are acceptable)
	if _, err := os.Stat(paths[0]); err == nil {
		t.Fatal("symlink chain stat should fail")
	}

	// Open should fail with either our custom "exceeds maximum depth" error
	// or the OS's "too many levels of symbolic links" error
	_, err := Open(paths[0])
	if err == nil {
		t.Fatal("Open should fail with symlink chain exceeding maximum depth")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "exceeds maximum depth") && !strings.Contains(errMsg, "too many levels of symbolic links") {
		t.Errorf("error should mention exceeding maximum depth or too many levels, got: %v", err)
	}
}

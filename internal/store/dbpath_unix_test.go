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

// TestDBPathRefusesSymlink verifies that a symlink at the DB path is rejected.
func TestDBPathRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	targetPath := filepath.Join(dir, "target.db")

	// Create a target file
	if err := os.WriteFile(targetPath, []byte("target"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink at the DB path
	if err := os.Symlink(targetPath, dbPath); err != nil {
		t.Skip("symlink not supported:", err)
	}

	// Attempt to open should fail
	_, err := Open(dbPath)
	if err == nil {
		t.Fatal("Open succeeded with symlink, expected error")
	}

	// Verify error message
	errMsg := err.Error()
	if !strings.Contains(errMsg, "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
	if strings.Contains(errMsg, dir) {
		t.Errorf("error leaked absolute path: %v", err)
	}

	// Verify target was not modified
	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "target" {
		t.Errorf("symlink target was modified")
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

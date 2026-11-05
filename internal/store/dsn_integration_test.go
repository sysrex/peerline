package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// TestDSNParsingMatchesDriver verifies that our dbFilePath helper correctly predicts
// what the actual modernc.org/sqlite driver will do with various DSN formats.
func TestDSNParsingMatchesDriver(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name             string
		dsn              string
		expectFileOnDisk bool
	}{
		{
			name:             "plain path with ?mode=memory creates REAL file",
			dsn:              filepath.Join(dir, "plain_mode_memory.db") + "?mode=memory",
			expectFileOnDisk: true,
		},
		{
			name:             "file: URI with ?mode=memory is memory only",
			dsn:              "file:" + filepath.Join(dir, "file_mode_memory.db") + "?mode=memory",
			expectFileOnDisk: false,
		},
		{
			name:             "file: URI with mode=memory&mode=rwc creates REAL file",
			dsn:              "file:" + filepath.Join(dir, "file_override.db") + "?mode=memory&mode=rwc",
			expectFileOnDisk: true,
		},
		{
			name:             "file: URI with mode=rwc&mode=memory is memory only",
			dsn:              "file:" + filepath.Join(dir, "file_memory_last.db") + "?mode=rwc&mode=memory",
			expectFileOnDisk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Predict what will happen using our helper
			path, isMemory, err := dbFilePath(tt.dsn)
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", tt.dsn, err)
			}

			// Our prediction
			ourPrediction := !isMemory // File on disk if NOT memory

			// Build DSN the same way OpenWithOptions does
			fullDSN := buildDSN(tt.dsn)

			// Open with actual driver
			db, err := sql.Open("sqlite", fullDSN)
			if err != nil {
				t.Fatalf("sql.Open failed: %v", err)
			}
			defer db.Close()

			// Write a row
			if _, err := db.Exec("CREATE TABLE test (id INTEGER); INSERT INTO test VALUES (1)"); err != nil {
				t.Fatalf("write failed: %v", err)
			}

			// Verify we can read it back
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM test").Scan(&count); err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if count != 1 {
				t.Fatalf("expected 1 row, got %d", count)
			}

			// Close to ensure flush
			db.Close()

			// Check if file exists on disk
			fileExists := false
			if path != "" {
				if _, err := os.Stat(path); err == nil {
					fileExists = true
				}
			}

			// Verify driver behavior matches expectation
			if fileExists != tt.expectFileOnDisk {
				t.Errorf("driver created file on disk: %v, expected: %v", fileExists, tt.expectFileOnDisk)
			}

			// Verify our helper prediction matches actual behavior
			if ourPrediction != tt.expectFileOnDisk {
				t.Errorf("dbFilePath predicted file on disk: %v, actual: %v", ourPrediction, fileExists)
			}
		})
	}
}

// TestDSNParsingErrors verifies that dbFilePath returns errors for invalid URIs.
func TestDSNParsingErrors(t *testing.T) {
	tests := []struct {
		name        string
		dsn         string
		expectError bool
	}{
		{
			name:        "file://remotehost/path rejected",
			dsn:         "file://remotehost/tmp/test.db",
			expectError: true,
		},
		{
			name:        "file://localhost/path accepted",
			dsn:         "file://localhost/tmp/test.db",
			expectError: false,
		},
		{
			name:        "file:///path accepted",
			dsn:         "file:///tmp/test.db",
			expectError: false,
		},
		{
			name:        "file://host without path rejected",
			dsn:         "file://somehost",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := dbFilePath(tt.dsn)
			if tt.expectError && err == nil {
				t.Errorf("dbFilePath(%q) should have returned error", tt.dsn)
			}
			if !tt.expectError && err != nil {
				t.Errorf("dbFilePath(%q) unexpected error: %v", tt.dsn, err)
			}
		})
	}
}

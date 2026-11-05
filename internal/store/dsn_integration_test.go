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
		name         string
		dsn          string
		expectedPath string // Expected file path on disk, or "" for memory-only
	}{
		{
			name:         ":memory:",
			dsn:          ":memory:",
			expectedPath: "",
		},
		{
			name:         "file::memory:",
			dsn:          "file::memory:",
			expectedPath: "",
		},
		{
			name:         "plain x.db?MODE=memory creates REAL file",
			dsn:          filepath.Join(dir, "plain_mode_memory.db") + "?MODE=memory",
			expectedPath: filepath.Join(dir, "plain_mode_memory.db"),
		},
		{
			name:         "file:x.db?MODE=memory creates REAL file (uppercase key)",
			dsn:          "file:" + filepath.Join(dir, "file_MODE_memory.db") + "?MODE=memory",
			expectedPath: filepath.Join(dir, "file_MODE_memory.db"),
		},
		{
			name:         "file: percent-encoded path",
			dsn:          "file:" + filepath.Join(dir, "my%20file.db"),
			expectedPath: filepath.Join(dir, "my file.db"),
		},
		{
			name:         "file://localhost/abs",
			dsn:          "file://localhost" + filepath.Join(dir, "localhost.db"),
			expectedPath: filepath.Join(dir, "localhost.db"),
		},
		{
			name:         "file:...#frag",
			dsn:          "file:" + filepath.Join(dir, "fragment.db") + "#section",
			expectedPath: filepath.Join(dir, "fragment.db"),
		},
		{
			name:         "file:...#?mode=memory NOT memory",
			dsn:          "file:" + filepath.Join(dir, "hash_question.db") + "#?mode=memory",
			expectedPath: filepath.Join(dir, "hash_question.db"),
		},
		{
			name:         "file:...#f?a=1 NOT memory",
			dsn:          "file:" + filepath.Join(dir, "hash_f_q.db") + "#f?a=1",
			expectedPath: filepath.Join(dir, "hash_f_q.db"),
		},
		{
			name:         "file: URI with mode=memory&mode=rwc creates REAL file",
			dsn:          "file:" + filepath.Join(dir, "override.db") + "?mode=memory&mode=rwc",
			expectedPath: filepath.Join(dir, "override.db"),
		},
		{
			name:         "file: URI with mode=rwc&mode=memory is memory only",
			dsn:          "file:" + filepath.Join(dir, "memory_last.db") + "?mode=rwc&mode=memory",
			expectedPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get dbFilePath prediction
			dbPath, isMemory, err := dbFilePath(tt.dsn)
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", tt.dsn, err)
			}

			// Verify dbFilePath matches expected path
			if dbPath != tt.expectedPath {
				t.Errorf("dbFilePath(%q) = %q, want %q", tt.dsn, dbPath, tt.expectedPath)
			}

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

			// Verify driver behavior matches expectations
			if tt.expectedPath == "" {
				// Memory-only: the specific file from this test should NOT exist
				// (We don't check if directory is empty because other tests may have created files)
				
				// For memory tests, we don't have an expectedPath, so we can't check a specific file.
				// Instead, verify that dbFilePath predicted memory
				if !isMemory {
					t.Errorf("dbFilePath predicted file %q, but test expects memory", dbPath)
				}
			} else {
				// File on disk: verify file exists at expected path
				if _, err := os.Stat(tt.expectedPath); err != nil {
					t.Errorf("expected file at %q, but it doesn't exist: %v", tt.expectedPath, err)
				}

				// Verify dbFilePath also predicted this path
				if isMemory {
					t.Errorf("dbFilePath predicted memory, but driver created file at %q", tt.expectedPath)
				}
				if dbPath != tt.expectedPath {
					t.Errorf("dbFilePath returned %q, but driver created file at %q", dbPath, tt.expectedPath)
				}
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

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
	tests := []struct {
		name            string
		buildDSN        func(dir string) string
		expectMemory    bool
		expectFile      string // Expected basename on disk (empty for memory-only)
		expectOpenError bool
	}{
		{
			name:         ":memory:",
			buildDSN:     func(dir string) string { return ":memory:" },
			expectMemory: true,
		},
		{
			name:         "file::memory:",
			buildDSN:     func(dir string) string { return "file::memory:" },
			expectMemory: true,
		},
		{
			name:         "file::memory:?cache=shared",
			buildDSN:     func(dir string) string { return "file::memory:?cache=shared" },
			expectMemory: true,
		},
		{
			name:       "plain x.db?MODE=memory creates REAL file (uppercase key)",
			buildDSN:   func(dir string) string { return filepath.Join(dir, "test.db") + "?MODE=memory" },
			expectFile: "test.db",
		},
		{
			name:       "file:x.db?MODE=memory creates REAL file (uppercase key)",
			buildDSN:   func(dir string) string { return "file:" + filepath.Join(dir, "test.db") + "?MODE=memory" },
			expectFile: "test.db",
		},
		{
			name: "file:x.db?mode=MEMORY fails with SQLite error (uppercase value)",
			buildDSN: func(dir string) string {
				return "file:" + filepath.Join(dir, "test.db") + "?mode=MEMORY"
			},
			expectOpenError: true,
		},
		{
			name: "file:x.db?mode=memory is memory only (named path)",
			buildDSN: func(dir string) string {
				return "file:" + filepath.Join(dir, "memory.db") + "?mode=memory"
			},
			expectMemory: true,
			expectFile:   "memory.db", // For asserting file does NOT exist
		},
		{
			name:       "file: percent-encoded path",
			buildDSN:   func(dir string) string { return "file:" + filepath.Join(dir, "my%20file.db") },
			expectFile: "my file.db",
		},
		{
			name:       "file://localhost/abs",
			buildDSN:   func(dir string) string { return "file://localhost" + filepath.Join(dir, "test.db") },
			expectFile: "test.db",
		},
		{
			name:       "file URI with fragment",
			buildDSN:   func(dir string) string { return "file:" + filepath.Join(dir, "test.db") + "#section" },
			expectFile: "test.db",
		},
		{
			name: "file URI fragment before query NOT memory",
			buildDSN: func(dir string) string {
				return "file:" + filepath.Join(dir, "test.db") + "#?mode=memory"
			},
			expectFile: "test.db",
		},
		{
			name:       "file URI fragment with query NOT memory",
			buildDSN:   func(dir string) string { return "file:" + filepath.Join(dir, "test.db") + "#f?a=1" },
			expectFile: "test.db",
		},
		{
			name: "file: URI with mode=memory&mode=rwc creates REAL file",
			buildDSN: func(dir string) string {
				return "file:" + filepath.Join(dir, "test.db") + "?mode=memory&mode=rwc"
			},
			expectFile: "test.db",
		},
		{
			name: "file: URI with mode=rwc&mode=memory is memory only (named path)",
			buildDSN: func(dir string) string {
				return "file:" + filepath.Join(dir, "memory2.db") + "?mode=rwc&mode=memory"
			},
			expectMemory: true,
			expectFile:   "memory2.db", // For asserting file does NOT exist
		},
		{
			name: "uppercase FILE: treated as plain path (not URI)",
			buildDSN: func(dir string) string {
				return filepath.Join(dir, "FILE:upper.db")
			},
			expectFile: "FILE:upper.db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each test gets its own directory
			rowDir := t.TempDir()
			dsn := tt.buildDSN(rowDir)

			// Get dbFilePath prediction
			dbPath, isMemory, err := dbFilePath(dsn)
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", dsn, err)
			}

			// Open with driver
			db, err := sql.Open("sqlite", dsn)
			if err != nil {
				if tt.expectOpenError {
					return
				}
				t.Fatalf("sql.Open failed: %v", err)
			}
			defer db.Close()

			// Get SQLite's actual backing file using PRAGMA database_list
			var seq int
			var dbName string
			var sqliteFile string
			if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &dbName, &sqliteFile); err != nil {
				if tt.expectOpenError {
					return
				}
				t.Fatalf("PRAGMA database_list failed: %v", err)
			}
			t.Logf("SQLite backing file: %q", sqliteFile)
			t.Logf("dbFilePath returned: %q", dbPath)
			t.Logf("rowDir: %q", rowDir)

			// Try to write
			if _, err := db.Exec("CREATE TABLE IF NOT EXISTS t (id INTEGER); INSERT INTO t VALUES (1)"); err != nil {
				if tt.expectOpenError {
					return
				}
				t.Fatalf("write failed: %v", err)
			}

			if tt.expectOpenError {
				t.Fatal("expected open or exec to fail, but succeeded")
			}

			// Verify we can read
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&count); err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if count < 1 {
				t.Fatalf("expected at least 1 row, got %d", count)
			}

			// Resolve symlinks if present (TempDir might use them)
			sqliteFileResolved := sqliteFile
			if sqliteFile != "" {
				if resolved, err := filepath.EvalSymlinks(sqliteFile); err == nil {
					sqliteFileResolved = resolved
				}
			}
			dbPathResolved := dbPath
			if dbPath != "" {
				if resolved, err := filepath.EvalSymlinks(dbPath); err == nil {
					dbPathResolved = resolved
				}
			}

			// Close to flush
			db.Close()

			// Check directory contents
			entries, err := os.ReadDir(rowDir)
			if err != nil {
				t.Fatalf("ReadDir failed: %v", err)
			}

			if tt.expectMemory {
				// Memory: SQLite's file column must be empty
				if sqliteFile != "" {
					t.Errorf("expected memory database (empty file column), but PRAGMA database_list returned %q", sqliteFile)
				}

				// Verify dbFilePath predicted memory
				if !isMemory {
					t.Errorf("dbFilePath predicted file %q, but driver used memory", dbPath)
				}
				if dbPath != "" {
					t.Errorf("dbFilePath returned path %q, but driver used memory (expected empty path)", dbPath)
				}

				// Directory must be empty
				if len(entries) > 0 {
					var fileNames []string
					for _, e := range entries {
						fileNames = append(fileNames, e.Name())
					}
					t.Errorf("expected memory-only (empty dir), found: %v", fileNames)
				}

				// If named path, verify that specific file doesn't exist
				if tt.expectFile != "" {
					expectedPath := filepath.Join(rowDir, tt.expectFile)
					if _, err := os.Stat(expectedPath); !os.IsNotExist(err) {
						t.Errorf("memory test: expected file %q to NOT exist", expectedPath)
					}
				}
			} else {
				// File: verify SQLite's backing file matches dbFilePath
				expectedPath := filepath.Join(rowDir, tt.expectFile)
				expectedPathResolved := expectedPath
				if resolved, err := filepath.EvalSymlinks(expectedPath); err == nil {
					expectedPathResolved = resolved
				}

				if sqliteFile == "" {
					t.Errorf("expected file-backed database, but PRAGMA database_list returned empty (memory)")
				} else if sqliteFileResolved != dbPathResolved {
					t.Errorf("PRAGMA database_list file %q doesn't match dbFilePath %q", sqliteFileResolved, dbPathResolved)
				}
				if sqliteFileResolved != expectedPathResolved {
					t.Errorf("PRAGMA database_list file %q doesn't match expected %q", sqliteFileResolved, expectedPathResolved)
				}

				// Verify dbFilePath predicted file
				if isMemory {
					t.Errorf("dbFilePath predicted memory, but driver created file %q", expectedPath)
				}
				if dbPath != expectedPath {
					t.Errorf("dbFilePath returned %q, want %q", dbPath, expectedPath)
				}

				// Verify expected file exists
				if _, err := os.Stat(expectedPath); err != nil {
					t.Errorf("expected file %q doesn't exist: %v", expectedPath, err)
				}

				// Verify only expected files exist in directory
				allowedFiles := map[string]bool{
					tt.expectFile:              true,
					tt.expectFile + "-wal":     true,
					tt.expectFile + "-shm":     true,
					tt.expectFile + "-journal": true,
				}

				for _, entry := range entries {
					if !allowedFiles[entry.Name()] {
						t.Errorf("unexpected file: %q (expected only %q and WAL/SHM/journal)", entry.Name(), tt.expectFile)
					}
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

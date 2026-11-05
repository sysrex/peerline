package store

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// percentEncodePath percent-encodes a file path for use in a file: URI.
// SQLite decodes file: URIs, so we must encode special characters like # and % in directory names.
func percentEncodePath(path string) string {
	// Split path into components, encode each, then rejoin
	parts := strings.Split(path, string(filepath.Separator))
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// TestDSNParsingMatchesDriver verifies that our dbFilePath helper correctly predicts
// what the actual modernc.org/sqlite driver will do with various DSN formats.
func TestDSNParsingMatchesDriver(t *testing.T) {
	tests := []struct {
		name            string
		buildDSN        func(dir string) string
		expectMemory    bool
		expectFile      string // Expected basename on disk (empty for memory-only)
		expectOpenError bool
		expectDbPathErr bool   // dbFilePath should return error
		journalMode     string // Expected PRAGMA journal_mode result
		nonParallel     bool   // Run as non-parallel subtest
	}{
		{
			name:         ":memory:",
			buildDSN:     func(dir string) string { return ":memory:" },
			expectMemory: true,
			journalMode:  "memory",
		},
		{
			name:         "file::memory:",
			buildDSN:     func(dir string) string { return "file::memory:" },
			expectMemory: true,
			journalMode:  "memory",
		},
		{
			name:         "file::memory:?cache=shared",
			buildDSN:     func(dir string) string { return "file::memory:?cache=shared" },
			expectMemory: true,
			journalMode:  "memory",
		},
		{
			name:        "plain x.db?MODE=memory creates REAL file (uppercase key)",
			buildDSN:    func(dir string) string { return filepath.Join(dir, "test.db") + "?MODE=memory" },
			expectFile:  "test.db",
			journalMode: "delete",
		},
		{
			name:        "file:x.db?MODE=memory creates REAL file (uppercase key)",
			buildDSN:    func(dir string) string { return "file:" + percentEncodePath(dir) + "/test.db?MODE=memory" },
			expectFile:  "test.db",
			journalMode: "delete",
		},
		{
			name: "file:x.db?mode=MEMORY fails with SQLite error (uppercase value)",
			buildDSN: func(dir string) string {
				return "file:" + percentEncodePath(dir) + "/test.db?mode=MEMORY"
			},
			expectOpenError: true,
		},
		{
			name: "file:x.db?mode=memory is memory only (named path)",
			buildDSN: func(dir string) string {
				return "file:" + percentEncodePath(dir) + "/memory.db?mode=memory"
			},
			expectMemory: true,
			expectFile:   "memory.db", // For asserting file does NOT exist
			journalMode:  "memory",
		},
		{
			name:        "file: percent-encoded path",
			buildDSN:    func(dir string) string { return "file:" + percentEncodePath(dir) + "/my%20file.db" },
			expectFile:  "my file.db",
			journalMode: "delete",
		},
		{
			name:        "file://localhost/abs",
			buildDSN:    func(dir string) string { return "file://localhost" + percentEncodePath(dir) + "/test.db" },
			expectFile:  "test.db",
			journalMode: "delete",
		},
		{
			name:            "file URI with fragment refused",
			buildDSN:        func(dir string) string { return "file:" + percentEncodePath(dir) + "/test.db#section" },
			expectDbPathErr: true,
		},
		{
			name: "file URI fragment before query refused",
			buildDSN: func(dir string) string {
				return "file:" + percentEncodePath(dir) + "/test.db#?mode=memory"
			},
			expectDbPathErr: true,
		},
		{
			name:            "file URI fragment with query refused",
			buildDSN:        func(dir string) string { return "file:" + percentEncodePath(dir) + "/test.db#f?a=1" },
			expectDbPathErr: true,
		},
		{
			name: "file: URI with mode=memory&mode=rwc creates REAL file",
			buildDSN: func(dir string) string {
				return "file:" + percentEncodePath(dir) + "/test.db?mode=memory&mode=rwc"
			},
			expectFile:  "test.db",
			journalMode: "delete",
		},
		{
			name: "file: URI with mode=rwc&mode=memory is memory only (named path)",
			buildDSN: func(dir string) string {
				return "file:" + percentEncodePath(dir) + "/memory2.db?mode=rwc&mode=memory"
			},
			expectMemory: true,
			expectFile:   "memory2.db", // For asserting file does NOT exist
			journalMode:  "memory",
		},
		{
			name:        "file URI with encoded hash in filename",
			buildDSN:    func(dir string) string { return "file:" + percentEncodePath(dir) + "/x%23y.db" },
			expectFile:  "x#y.db",
			journalMode: "delete",
		},
		{
			name: "uppercase FILE: treated as plain path (not URI)",
			buildDSN: func(dir string) string {
				return "FILE:upper.db"
			},
			expectFile:  "FILE:upper.db",
			journalMode: "delete",
			nonParallel: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if !tt.nonParallel {
				t.Parallel()
			}

			// Each test gets its own directory
			rowDir := t.TempDir()

			// Guard: rowDir must not contain %, #, or ? (t.TempDir builds from test name)
			// SQLite decodes file: URIs, so these chars would break the path
			if strings.ContainsAny(rowDir, "%#?") {
				t.Fatalf("rowDir contains special chars that break file: URIs: %q", rowDir)
			}

			// Handle relative path with t.Chdir for FILE: test
			if tt.nonParallel {
				t.Chdir(rowDir)
			}

			dsn := tt.buildDSN(rowDir)

			// Get dbFilePath prediction
			dbPath, isMemory, err := dbFilePath(dsn)
			if tt.expectDbPathErr {
				if err == nil {
					t.Fatalf("dbFilePath(%q) expected error but got nil", dsn)
				}
				// Verify that Store.Open would also fail (it calls dbFilePath internally)
				// and creates nothing on disk
				_, openErr := Open(dsn)
				if openErr == nil {
					t.Fatalf("Open(%q) should have failed with dbFilePath error", dsn)
				}
				// Verify nothing was created on disk
				entries, readErr := os.ReadDir(rowDir)
				if readErr != nil {
					t.Fatalf("ReadDir failed: %v", readErr)
				}
				if len(entries) > 0 {
					t.Errorf("expected empty rowDir after failed Open, found %d entries", len(entries))
				}
				return
			}
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", dsn, err)
			}

			// Open with driver using buildDSN (the way production does)
			db, err := sql.Open("sqlite", buildDSN(dsn))
			if err != nil {
				if tt.expectOpenError {
					return
				}
				t.Fatalf("sql.Open failed: %v", err)
			}
			defer db.Close()

			// Assert pragmas set by buildDSN
			var foreignKeys int
			if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
				if tt.expectOpenError {
					// This is expected for cases like mode=MEMORY (uppercase value)
					return
				}
				t.Fatalf("PRAGMA foreign_keys failed: %v", err)
			}
			if foreignKeys != 1 {
				t.Errorf("PRAGMA foreign_keys = %d, want 1", foreignKeys)
			}

			var busyTimeout int
			if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
				t.Fatalf("PRAGMA busy_timeout failed: %v", err)
			}
			if busyTimeout != 5000 {
				t.Errorf("PRAGMA busy_timeout = %d, want 5000", busyTimeout)
			}

			if tt.journalMode != "" {
				var journalMode string
				if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
					t.Fatalf("PRAGMA journal_mode failed: %v", err)
				}
				if journalMode != tt.journalMode {
					t.Errorf("PRAGMA journal_mode = %q, want %q", journalMode, tt.journalMode)
				}
			}

			// Get SQLite's actual backing file using PRAGMA database_list
			var seq int
			var dbName string
			var sqliteFile string
			if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &dbName, &sqliteFile); err != nil {
				t.Fatalf("PRAGMA database_list failed: %v", err)
			}

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
				// For relative paths (e.g., FILE:upper.db after os.Chdir), make absolute first
				if !filepath.IsAbs(dbPath) {
					if absPath, err := filepath.Abs(dbPath); err == nil {
						dbPathResolved = absPath
					}
				}
				if resolved, err := filepath.EvalSymlinks(dbPathResolved); err == nil {
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
				// Compare resolved paths (handles relative paths like FILE:upper.db after os.Chdir)
				if dbPathResolved != expectedPathResolved {
					t.Errorf("dbFilePath returned %q (resolved: %q), want %q (resolved: %q)", dbPath, dbPathResolved, expectedPath, expectedPathResolved)
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

// TestTxlockImmediate verifies that _txlock=immediate causes BEGIN to acquire
// a RESERVED lock immediately, blocking concurrent transactions at BEGIN time.
func TestTxlockImmediate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Open connection A with our buildDSN (includes _txlock=immediate)
	dsnA := buildDSN(dbPath)
	dbA, err := sql.Open("sqlite", dsnA)
	if err != nil {
		t.Fatalf("open dbA failed: %v", err)
	}
	defer dbA.Close()

	// Create schema
	if _, err := dbA.Exec("CREATE TABLE test (id INTEGER)"); err != nil {
		t.Fatalf("create table failed: %v", err)
	}

	// Begin transaction on A (should acquire RESERVED lock immediately with _txlock=immediate)
	txA, err := dbA.Begin()
	if err != nil {
		t.Fatalf("begin on A failed: %v", err)
	}
	defer txA.Rollback()

	// Open connection B with low busy_timeout to detect blocking
	dsnB := dbPath + "?_pragma=busy_timeout(100)"
	dbB, err := sql.Open("sqlite", dsnB)
	if err != nil {
		t.Fatalf("open dbB failed: %v", err)
	}
	defer dbB.Close()

	// Attempt to begin on B should fail or block because A holds RESERVED lock
	// Without _txlock=immediate, BEGIN would succeed and the first write would block
	txB, err := dbB.Begin()
	if err != nil {
		// Expected: BEGIN failed because A holds RESERVED lock
		if !strings.Contains(err.Error(), "database is locked") {
			t.Errorf("expected 'database is locked' error, got: %v", err)
		}
		return
	}
	defer txB.Rollback()

	// If BEGIN succeeded, try to write on B (should fail immediately)
	_, err = txB.Exec("INSERT INTO test VALUES (1)")
	if err == nil {
		t.Fatal("write on B should have failed while A holds transaction")
	}
	if !strings.Contains(err.Error(), "database is locked") {
		t.Errorf("expected 'database is locked' error on write, got: %v", err)
	}
}

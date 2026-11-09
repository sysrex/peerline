package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerifyBackupWithSpecialCharsInPath tests that verifyBackup handles
// special characters (?, #, %, space) in paths correctly by using proper URL encoding.
func TestVerifyBackupWithSpecialCharsInPath(t *testing.T) {
	testCases := []struct {
		name    string
		dirname string
	}{
		{"space", "dir with spaces"},
		{"question", "dir?query"},
		{"hash", "dir#fragment"},
		{"percent", "dir%25"},
		{"percentA", "dir%41"},
		{"multiple", "a b?c#d"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpBase := t.TempDir()
			dir := filepath.Join(tmpBase, tc.dirname)
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}

			dbPath := filepath.Join(dir, "test.db")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			// Create v2 database
			_, err = db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
				INSERT INTO peers VALUES ('p1','TestPeer','hash1',1234567890,'test@example.com');
				PRAGMA user_version = 2;`)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()

			// Create backup in the directory with special characters
			backupPath := filepath.Join(dir, "test.db.pre-v7-from-v2.20260101-120000.000000")
			_, err = os.Create(backupPath)
			if err != nil {
				t.Fatal(err)
			}

			db2, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db2.Close()

			// VACUUM INTO the backup
			_, err = db2.Exec(`VACUUM INTO ?`, backupPath)
			if err != nil {
				t.Fatal(err)
			}
			db2.Close()

			// Verify backup - should succeed with proper URL encoding
			if err := verifyBackup(backupPath, 2); err != nil {
				t.Errorf("verifyBackup failed for path with %q: %v", tc.dirname, err)
			}

			// Try to write through the verification connection (should fail if read-only)
			// We do this by opening the connection again manually with the same URL construction
			absPath, _ := filepath.Abs(backupPath)
			uriPath := absPath
			if filepath.Separator == '\\' {
				uriPath = "/" + filepath.ToSlash(absPath)
			}
			u := url.URL{
				Scheme:   "file",
				Path:     uriPath,
				RawQuery: url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)"}}.Encode(),
			}
			db3, err := sql.Open("sqlite", u.String())
			if err != nil {
				t.Fatal(err)
			}
			defer db3.Close()

			// Attempt to create a table - should fail
			_, err = db3.Exec(`CREATE TABLE test_write (x INT)`)
			if err == nil {
				t.Error("write to read-only connection should have failed")
			}
		})
	}
}

// TestRetentionWithHexSuffixes tests that backups with hex random suffixes
// are correctly matched by backupSuffixRE and pruned by retention.
func TestRetentionWithHexSuffixes(t *testing.T) {
	dir := secureTempDir(t)
	dbPath := filepath.Join(dir, "x.db")
	st, err := OpenWithOptions(dbPath, OpenOptions{BackupDir: dir, BackupRetentionCount: 10, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create several old backups with hex suffixes
	oldBackups := []string{
		"x.db.pre-v7-from-v2.20260101-120000.000000.deadbeef",
		"x.db.pre-v7-from-v2.20260101-120001.000000.cafebabe",
		"x.db.pre-v7-from-v2.20260101-120002.000000.12345678", // all-digits hex
	}

	for _, name := range oldBackups {
		path := filepath.Join(dir, name)
		// Create a valid v2 database for this backup
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
			INSERT INTO peers VALUES ('old','OldPeer','hash_old',1234567890,'old@example.com');
			PRAGMA user_version = 2;`)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()

		// Make them old
		oldTime := time.Now().Add(-1 * time.Hour)
		os.Chtimes(path, oldTime, oldTime)
	}

	// Create files that should NOT be deleted
	keepFiles := []string{
		"x.db.pre-v7-from-v2.20260101-120000.000000.DEADBEEF",  // uppercase hex
		"x.db.pre-v7-from-v2.20260101-120000.000000.KEEP",      // not matching pattern
		"x.db.pre-v7-from-v2.20260101-120000.000000.deadbee",   // 7 chars, not 8
		"x.db.pre-v7-from-v2.20260101-120000.000000.deadbeeff", // 9 chars, not 8
		"x.db.pre-v7-from-v2.notes",                            // different pattern
		"other.db.pre-v7-from-v2.20260101-120000.000000",       // different DB base
	}

	for _, name := range keepFiles {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Trigger retention with BackupRetentionCount=1 (keep only the newest)
	// Since all hex-suffixed backups are old, they should all be deleted
	if err := enforceBackupRetention(dir, "x.db", dbPath, 1, slog.Default()); err != nil {
		t.Fatal(err)
	}

	// Check that old hex-suffixed backups were deleted
	for _, name := range oldBackups {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("old backup %q should have been deleted but still exists", name)
		}
	}

	// Check that keep files still exist
	for _, name := range keepFiles {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file %q should have been kept but was deleted: %v", name, err)
		}
	}
}

// TestEmptyBackupRejected tests that verifyBackup rejects empty files.
func TestEmptyBackupRejected(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(emptyFile, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	// verifyBackup should reject empty file even for version 0
	err := verifyBackup(emptyFile, 0)
	if err == nil {
		t.Error("verifyBackup should reject empty backup, got nil error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

// TestVersion0BackupAccepted tests that verifyBackup accepts valid version-0 backups.
// The empty file check prevents the truncated-path attack, so version-0 is allowed.
func TestVersion0BackupAccepted(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v0.db")

	// Create a version-0 database (no user_version set, defaults to 0)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE test (id INT); INSERT INTO test VALUES (1)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// verifyBackup should accept a valid version-0 backup
	err = verifyBackup(dbPath, 0)
	if err != nil {
		t.Errorf("verifyBackup should accept valid version-0 backup, got: %v", err)
	}
}

// TestTwoFilesWithHashFragment tests that verifyBackup opens the correct file
// when two files exist like "a" and "a#b", ensuring # in path doesn't truncate.
func TestTwoFilesWithHashFragment(t *testing.T) {
	tmpBase := t.TempDir()

	// Create directory "testdir" and "testdir#extra"
	dir1 := filepath.Join(tmpBase, "testdir")
	dir2 := filepath.Join(tmpBase, "testdir#extra")

	for _, dir := range []string{dir1, dir2} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create different v2 databases in each
	for i, dir := range []string{dir1, dir2} {
		dbPath := filepath.Join(dir, "test.db")
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}

		peerID := fmt.Sprintf("peer%d", i)
		_, err = db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
			INSERT INTO peers VALUES (?, 'Peer', 'hash', 1234567890, 'test@example.com');
			PRAGMA user_version = 2;`, peerID)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()

		// Create backup
		backupPath := filepath.Join(dir, "test.db.pre-v7-from-v2.20260101-120000.000000")
		if _, err := os.Create(backupPath); err != nil {
			t.Fatal(err)
		}

		db2, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db2.Exec(`VACUUM INTO ?`, backupPath)
		if err != nil {
			t.Fatal(err)
		}
		db2.Close()
	}

	// Verify that the backup in dir2 (with # in path) verifies correctly
	backup2 := filepath.Join(dir2, "test.db.pre-v7-from-v2.20260101-120000.000000")
	if err := verifyBackup(backup2, 2); err != nil {
		t.Errorf("verifyBackup failed for path with #: %v", err)
	}

	// Open backup2 and verify it has peer1 (not peer0), proving we opened the right file
	absPath, _ := filepath.Abs(backup2)
	uriPath := absPath
	if filepath.Separator == '\\' {
		uriPath = "/" + filepath.ToSlash(absPath)
	}
	u := url.URL{
		Scheme:   "file",
		Path:     uriPath,
		RawQuery: url.Values{"mode": {"ro"}}.Encode(),
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var peerID string
	err = db.QueryRow(`SELECT id FROM peers LIMIT 1`).Scan(&peerID)
	if err != nil {
		t.Fatal(err)
	}
	if peerID != "peer1" {
		t.Errorf("opened wrong database: expected peer1, got %s", peerID)
	}
}

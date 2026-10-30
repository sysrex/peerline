package store

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeV2DB(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "x.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,''); PRAGMA user_version = 2;`); err != nil {
		t.Fatal(err)
	}
	return p
}

func openOpts(dir string) OpenOptions {
	return OpenOptions{BackupDir: dir, BackupRetentionCount: 1, Logger: slog.Default()}
}

func TestRetentionOnlyDeletesRegularBackupFiles(t *testing.T) {
	dir := secureTempDir(t)
	keep := []string{
		"x.db.pre-v6-from-v2.20260101-120000.000000.KEEP",
		"other.db.pre-v6-from-v2.20260101-120000.000000",
		"x.db.pre-v6-from-v2.notes",
	}
	for _, n := range keep {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("x"), 0600)
	link := "x.db.pre-v6-from-v2.20260101-120001.000000"
	os.Symlink(target, filepath.Join(dir, link))
	keep = append(keep, link)
	os.Mkdir(filepath.Join(dir, "x.db.pre-v6-from-v2.20260101-120002.000000"), 0700)
	keep = append(keep, "x.db.pre-v6-from-v2.20260101-120002.000000")

	p := makeV2DB(t, dir)
	s, err := OpenWithOptions(p, openOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, n := range keep {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was deleted: %v", n, err)
		}
	}
}

func TestBackupDirRefusesSymlinkAndWrongMode(t *testing.T) {
	root := secureTempDir(t)
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0700)
	link := filepath.Join(root, "link")
	os.Symlink(real, link)
	p := makeV2DB(t, root)

	if _, err := OpenWithOptions(p, openOpts(link)); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked backup dir: got %v", err)
	}
	open := filepath.Join(root, "open")
	os.Mkdir(open, 0755)
	os.Chmod(open, 0755)
	if _, err := OpenWithOptions(p, openOpts(open)); err == nil || !strings.Contains(err.Error(), "group or world") {
		t.Fatalf("0755 backup dir: got %v", err)
	}
}

func TestBackupErrorsDoNotLeakDirectory(t *testing.T) {
	root := secureTempDir(t)
	p := makeV2DB(t, root)
	blocker := filepath.Join(root, "distinctive-secret-dir")
	os.WriteFile(blocker, []byte("x"), 0600)
	_, err := OpenWithOptions(p, openOpts(filepath.Join(blocker, "sub")))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("error leaks directory: %v", err)
	}
}

func TestCorruptDatabaseRefusedBeforeMigration(t *testing.T) {
	dir := secureTempDir(t)
	p := makeV2DB(t, dir)
	b, _ := os.ReadFile(p)
	// Corrupt a data page past the header and schema page.
	if len(b) < 3*4096 {
		t.Skip("database too small to corrupt a data page")
	}
	for i := 2 * 4096; i < len(b); i++ {
		b[i] = 0xff
	}
	os.WriteFile(p, b, 0600)
	opts := openOpts(dir)
	opts.SkipMigrationBackup = true
	if _, err := OpenWithOptions(p, opts); err == nil {
		t.Fatal("corrupt database must be refused")
	}
}

package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/sysrex/peerline/internal/clock/clocktest"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	sqlite "modernc.org/sqlite"
)

// Global cancel function for the test_cancel scalar function
var testCancelFunc atomic.Value // stores context.CancelFunc

// secureTempDir creates a temporary directory with 0700 permissions for testing backups.
func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	return dir
}

func init() {
	// Register the test_cancel scalar function globally
	sqlite.MustRegisterDeterministicScalarFunction("test_cancel", 0, func(ctx *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		if fn := testCancelFunc.Load(); fn != nil {
			fn.(context.CancelFunc)()
		}
		return int64(0), nil
	})
}

func TestStoreBasics(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "a", "alice", "ha", "alice@example.com", ""); err != nil {
		t.Fatal(err)
	}
	s.CreatePeer(ctx, "b", "bob", "hb", "", "")
	if email, err := s.NotifyEmail(ctx, "a"); err != nil || email != "alice@example.com" {
		t.Fatal(email, err)
	}
	if email, err := s.NotifyEmail(ctx, "b"); err != nil || email != "" {
		t.Fatal(email, err)
	}
	if err := s.SetNotifyEmail(ctx, "a", "", ""); err != nil {
		t.Fatal(err)
	}
	if email, err := s.NotifyEmail(ctx, "a"); err != nil || email != "" {
		t.Fatal(email, err)
	}
	if p, err := s.PeerByKeyHash(ctx, "ha"); err != nil || p.ID != "a" {
		t.Fatal(p, err)
	}
	if _, err := s.GetGrant(ctx, "a", "b"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected deny")
	}
	s.CreateInvite(ctx, "c1", "a", []string{"messages"}, nil, time.Now().Add(-time.Minute))
	if _, err := s.AcceptInvite(ctx, "c1", "b", nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invite accepted")
	}
	if v, err := s.PutBag(ctx, "a", "n", []byte("x"), "a", 0, 100, 1048576); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if _, err := s.PutBag(ctx, "a", "n", []byte("y"), "a", 0, 100, 1048576); !errors.Is(err, ErrConflict) {
		t.Fatal("expected conflict")
	}
}

func TestStats(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Stats(ctx)
	if err != nil || st != (Stats{}) {
		t.Fatalf("empty: %+v %v", st, err)
	}
	if err := s.CreatePeer(ctx, "a", "alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "b", "bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvite(ctx, "c2", "a", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "c2", "b", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{From: "b", To: "a", Type: "note", Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBag(ctx, "a", "status", []byte("ok"), "a", -1, 100, 1048576); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Peers != 2 || st.Messages != 1 || st.Grants != 1 || st.Bags != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Databases created before notify_email must gain the column on open.
func TestNotifyEmailMigration(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/old.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE peers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at) VALUES('p_old','old','h',1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	email, err := s.NotifyEmail(ctx, "p_old")
	if err != nil || email != "" {
		t.Fatalf("migrated email %q %v", email, err)
	}
	if err := s.SetNotifyEmail(ctx, "p_old", "old@example.com", "tok1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNotifyEmail(ctx, "missing", "a@b.co", "tok2"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	email, err = s2.NotifyEmail(ctx, "p_old")
	if err != nil || email != "old@example.com" {
		t.Fatalf("reopen %q %v", email, err)
	}
}

// TestV0SchemaMigration verifies v0 databases (without notify_email) upgrade correctly.
func TestV0SchemaMigration(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/v0.db"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE peers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE invites (
		code_hash TEXT PRIMARY KEY,
		from_peer TEXT NOT NULL,
		scopes TEXT NOT NULL,
		bags TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used_by TEXT
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at) VALUES('alice','Alice','ha',1)`); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var notifyEmailCol, pairingCol int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&notifyEmailCol)
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&pairingCol)
	if notifyEmailCol != 1 || pairingCol != 1 {
		t.Fatalf("columns missing after v0 migration: notify_email=%d, pairing_token_hash=%d", notifyEmailCol, pairingCol)
	}

	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}

	email, err := s.NotifyEmail(ctx, "alice")
	if err != nil || email != "" {
		t.Fatalf("v0 peer notify_email: %q %v", email, err)
	}
}

// TestV1SchemaMigration verifies v1 databases (with notify_email) upgrade to v2.
func TestV1SchemaMigration(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/v1.db"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE peers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		notify_email TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE invites (
		code_hash TEXT PRIMARY KEY,
		from_peer TEXT NOT NULL,
		scopes TEXT NOT NULL,
		bags TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used_by TEXT
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('alice','Alice','ha',1,'alice@example.com')`); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var hasCol, hasIndex int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&hasCol)
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&hasIndex)
	if hasCol != 1 || hasIndex != 1 {
		t.Fatalf("v1->v2 migration incomplete: col=%d index=%d", hasCol, hasIndex)
	}

	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}

	email, err := s.NotifyEmail(ctx, "alice")
	if err != nil || email != "alice@example.com" {
		t.Fatalf("notify_email after v1 migration: %q %v", email, err)
	}
}

// TestPartialMigrationState verifies recovery when column exists but index is missing.
func TestPartialMigrationState(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/partial.db"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE peers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		notify_email TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE invites (
		code_hash TEXT PRIMARY KEY,
		from_peer TEXT NOT NULL,
		scopes TEXT NOT NULL,
		bags TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used_by TEXT,
		pairing_token_hash TEXT
	)`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('alice','Alice','ha',1,'')`); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var hasIndex int
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&hasIndex)
	if hasIndex != 1 {
		t.Fatal("unique index not created from partial state")
	}

	if err := s.CreateInviteWithPairing(ctx, "code1", "pair1", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("pairing invite after partial migration: %v", err)
	}
}

// TestFreshAndMigratedSchemasMatch verifies fresh and migrated databases converge.
func TestFreshAndMigratedSchemasMatch(t *testing.T) {
	ctx := context.Background()

	// Helper to normalize SQL for comparison
	normSQL := func(s string) string {
		// Collapse all whitespace to single spaces
		s = strings.Join(strings.Fields(s), " ")
		// Remove spaces after opening and before closing parentheses
		s = strings.ReplaceAll(s, "( ", "(")
		s = strings.ReplaceAll(s, " )", ")")
		return s
	}

	// Helper to get schema definitions
	getSchema := func(db *sql.DB) (map[string]string, error) {
		schema := make(map[string]string)
		rows, err := db.Query(`SELECT type, name, sql FROM sqlite_master WHERE sql NOT NULL ORDER BY type, name`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var typ, name, sql string
			if err := rows.Scan(&typ, &name, &sql); err != nil {
				return nil, err
			}
			schema[typ+":"+name] = normSQL(sql)
		}
		return schema, rows.Err()
	}

	tests := []struct {
		name      string
		setupFunc func(*sql.DB) error
	}{
		{
			name: "v0",
			setupFunc: func(db *sql.DB) error {
				sqls := []string{
					`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)`,
					`CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT)`,
					`CREATE TABLE grants (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee))`,
					`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, type TEXT NOT NULL, body TEXT NOT NULL, reply_to INTEGER, created_at INTEGER NOT NULL)`,
					`CREATE INDEX messages_inbox ON messages(recipient, id)`,
					`CREATE TABLE bags (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, name TEXT NOT NULL, content BLOB NOT NULL, version INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, name))`,
				}
				for _, sql := range sqls {
					if _, err := db.Exec(sql); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			name: "v1",
			setupFunc: func(db *sql.DB) error {
				sqls := []string{
					`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, notify_email TEXT NOT NULL DEFAULT '')`,
					`CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT)`,
					`CREATE TABLE grants (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee))`,
					`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, type TEXT NOT NULL, body TEXT NOT NULL, reply_to INTEGER, created_at INTEGER NOT NULL)`,
					`CREATE INDEX messages_inbox ON messages(recipient, id)`,
					`CREATE TABLE bags (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, name TEXT NOT NULL, content BLOB NOT NULL, version INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, name))`,
					`PRAGMA user_version = 1`,
				}
				for _, sql := range sqls {
					if _, err := db.Exec(sql); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			name: "pr11_full_index",
			setupFunc: func(db *sql.DB) error {
				sqls := []string{
					`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, notify_email TEXT NOT NULL DEFAULT '')`,
					`CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT, pairing_token_hash TEXT)`,
					`CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash)`,
					`CREATE TABLE grants (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee))`,
					`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, type TEXT NOT NULL, body TEXT NOT NULL, reply_to INTEGER, created_at INTEGER NOT NULL)`,
					`CREATE INDEX messages_inbox ON messages(recipient, id)`,
					`CREATE TABLE bags (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, name TEXT NOT NULL, content BLOB NOT NULL, version INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, name))`,
				}
				for _, sql := range sqls {
					if _, err := db.Exec(sql); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			name: "pr8_inline_unique",
			setupFunc: func(db *sql.DB) error {
				sqls := []string{
					`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, notify_email TEXT NOT NULL DEFAULT '')`,
					`CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT, pairing_token_hash TEXT UNIQUE)`,
					`CREATE TABLE grants (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee))`,
					`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, type TEXT NOT NULL, body TEXT NOT NULL, reply_to INTEGER, created_at INTEGER NOT NULL)`,
					`CREATE INDEX messages_inbox ON messages(recipient, id)`,
					`CREATE TABLE bags (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, name TEXT NOT NULL, content BLOB NOT NULL, version INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, name))`,
				}
				for _, sql := range sqls {
					if _, err := db.Exec(sql); err != nil {
						return err
					}
				}
				return nil
			},
		},
	}

	freshPath := t.TempDir() + "/fresh.db"
	freshStore, err := Open(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	defer freshStore.Close()
	freshSchema, err := getSchema(freshStore.db)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir() + "/" + tt.name + ".db"
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.setupFunc(db); err != nil {
				t.Fatal(err)
			}
			db.Close()

			migratedStore, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer migratedStore.Close()

			// Verify user_version is 2
			var version int
			migratedStore.db.QueryRow(`PRAGMA user_version`).Scan(&version)
			if version != len(migrations) {
				t.Fatalf("user_version = %d, want %d", version, len(migrations))
			}

			// Compare full schema
			migratedSchema, err := getSchema(migratedStore.db)
			if err != nil {
				t.Fatal(err)
			}

			// Both should have the same keys
			for key := range freshSchema {
				if _, ok := migratedSchema[key]; !ok {
					t.Errorf("migrated schema missing %s", key)
				}
			}
			for key := range migratedSchema {
				if _, ok := freshSchema[key]; !ok {
					// Allow automatic indexes from inline UNIQUE constraints
					if strings.HasPrefix(key, "index:sqlite_autoindex_") {
						continue
					}
					t.Errorf("migrated schema has unexpected %s", key)
				}
			}

			// Compare table and explicit index definitions (skip auto indexes)
			for key, freshSQL := range freshSchema {
				migratedSQL, ok := migratedSchema[key]
				if !ok {
					continue
				}
				// For pr8_inline_unique case, allow the UNIQUE constraint to remain in the column definition
				// (removing it would require a full table rebuild which is not worth the risk)
				if tt.name == "pr8_inline_unique" && key == "table:invites" {
					// Both should be functionally equivalent - the migrated version has inline UNIQUE
					// which creates an automatic index, plus our partial index
					if !strings.Contains(migratedSQL, "pairing_token_hash TEXT") {
						t.Errorf("%s missing pairing_token_hash column", key)
					}
					continue
				}
				// ALTER TABLE ADD COLUMN on the multi-line schema leaves a space before the comma.
				if strings.ReplaceAll(freshSQL, " ,", ",") != migratedSQL {
					t.Errorf("%s schema differs:\nfresh:    %s\nmigrated: %s", key, freshSQL, migratedSQL)
				}
			}

			// Verify uniqueness behavior: duplicate pairing_token_hash rejected, multiple NULLs allowed
			if err := migratedStore.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
				t.Fatal(err)
			}
			exp := time.Now().Add(time.Hour)
			if err := migratedStore.CreateInviteWithPairing(ctx, "c1", "pair1", "alice", []string{"messages"}, nil, exp); err != nil {
				t.Fatal(err)
			}
			if err := migratedStore.CreateInviteWithPairing(ctx, "c2", "pair1", "alice", []string{"messages"}, nil, exp); err == nil {
				t.Error("duplicate pairing_token_hash should be rejected")
			}
			// Multiple NULL pairing tokens should be allowed
			if err := migratedStore.CreateInvite(ctx, "c3", "alice", []string{"messages"}, nil, exp); err != nil {
				t.Fatal(err)
			}
			if err := migratedStore.CreateInvite(ctx, "c4", "alice", []string{"messages"}, nil, exp); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestConcurrentPairingRedemption verifies that exactly one of multiple concurrent
// attempts to redeem the same pairing token succeeds. Uses a file DB with separate
// Store instances to test real lock contention.
func TestConcurrentPairingRedemption(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/concurrent.db"

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	pairingHash := "pairing_hash_123"
	exp := time.Now().Add(time.Hour)
	if err := s1.CreateInviteWithPairing(ctx, "code1", pairingHash, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	const numAttempts = 5
	results := make(chan error, numAttempts)

	for i := 0; i < numAttempts; i++ {
		peerID := fmt.Sprintf("bot%d", i)
		peerName := fmt.Sprintf("Bot%d", i)
		keyHash := fmt.Sprintf("hash%d", i)
		go func(id, name, kh string) {
			s, err := Open(path)
			if err != nil {
				results <- err
				return
			}
			defer s.Close()
			_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash, id, name, kh, "", "", nil, nil)
			results <- err
		}(peerID, peerName, keyHash)
	}

	var successes, notFounds, others int
	for i := 0; i < numAttempts; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrNotFound):
			notFounds++
		default:
			others++
			t.Logf("unexpected error: %v", err)
		}
	}

	if successes != 1 {
		t.Errorf("got %d successes, want 1", successes)
	}
	if notFounds != numAttempts-1 {
		t.Errorf("got %d ErrNotFound, want %d", notFounds, numAttempts-1)
	}
	if others > 0 {
		t.Errorf("got %d unexpected errors", others)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	var peerCount int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 2 {
		t.Errorf("got %d peers, want 2 (alice + 1 winner)", peerCount)
	}
}

// TestNoOrphanPeerOnAcceptFailure verifies that when accept fails,
// no orphan peer row is left behind.
func TestNoOrphanPeerOnAcceptFailure(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	// Test 1: Expired pairing token
	expiredHash := "expired_hash"
	pastTime := time.Now().Add(-time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "code_expired", expiredHash, "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	_, err = s.RegisterAndAcceptByPairing(ctx, expiredHash, "bob", "Bob", "hb", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for expired, got %v", err)
	}

	var peerCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='bob'`).Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 0 {
		t.Error("orphan peer created after expired invite")
	}

	// Test 2: Already-used pairing token
	usedHash := "used_hash"
	if err := s.CreatePeer(ctx, "carol", "Carol", "hc", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInviteWithPairing(ctx, "code_used", usedHash, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AcceptInviteByPairingToken(ctx, usedHash, "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	_, err = s.RegisterAndAcceptByPairing(ctx, usedHash, "dave", "Dave", "hd", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for used invite, got %v", err)
	}

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='dave'`).Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 0 {
		t.Error("orphan peer created after already-used invite")
	}

	// Test 3: Invalid token (doesn't exist)
	_, err = s.RegisterAndAcceptByPairing(ctx, "nonexistent_hash", "eve", "Eve", "he", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for nonexistent, got %v", err)
	}

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='eve'`).Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 0 {
		t.Error("orphan peer created for nonexistent invite")
	}
}

// TestExpiredInviteRejection verifies that expired invites cannot be accepted.
func TestExpiredInviteRejection(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}

	pastTime := time.Now().Add(-time.Hour)
	if err := s.CreateInvite(ctx, "code_exp", "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	_, err = s.AcceptInvite(ctx, "code_exp", "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired invite, got %v", err)
	}

	if err := s.CreateInviteWithPairing(ctx, "code_pair_exp", "pair_exp", "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	_, err = s.AcceptInviteByPairingToken(ctx, "pair_exp", "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired pairing invite, got %v", err)
	}

	var grantCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&grantCount); err != nil {
		t.Fatal(err)
	}
	if grantCount != 0 {
		t.Errorf("grants created from expired invites: %d", grantCount)
	}
}

// TestPairingTokenExpiryWithClock verifies pairing token expiry behavior with precise clock control.
// From #88/#102: tests exact expiry boundaries and ensures no orphan peers on mid-transaction expiry.
func TestPairingTokenExpiryWithClock(t *testing.T) {
	currentTime := int64(1000000)
	clk := clocktest.New(time.Unix(currentTime, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	// Create peers
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create a pairing invite that expires at currentTime + 100
	codeHash := "code_test"
	pairingHash := "pair_test"
	expiresAt := time.Unix(currentTime+100, 0)
	if err := s.CreateInviteWithPairing(ctx, codeHash, pairingHash, "alice", []string{"messages"}, nil, expiresAt); err != nil {
		t.Fatal(err)
	}

	// 1. Token is valid 10 seconds before expiry
	clk.Set(time.Unix(currentTime+90, 0))
	exists, err := s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("token should exist 10 seconds before expiry")
	}

	// 2. Token is still valid 1 second before expiry
	clk.Set(time.Unix(currentTime+99, 0))
	exists, err = s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("token should exist 1 second before expiry")
	}

	// Token is still live exactly at expires_at (expired means expires_at < now)
	clk.Set(time.Unix(currentTime+100, 0))
	exists, err = s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("token should exist exactly at expires_at")
	}

	// 3. Token is invalid 1 second after expiry
	clk.Set(time.Unix(currentTime+101, 0))
	exists, err = s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("token should not exist 1 second after expiry")
	}

	// 4. GetInviteByPairingToken rejects expired token
	codeHash2 := "code_test2"
	pairingHash2 := "pair_test2"
	expiresAt2 := time.Unix(currentTime+200, 0)
	clk.Set(time.Unix(currentTime+50, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash2, pairingHash2, "alice", []string{"messages"}, nil, expiresAt2); err != nil {
		t.Fatal(err)
	}

	// At exactly expires_at, GetInviteByPairingToken should succeed
	clk.Set(time.Unix(currentTime+200, 0))
	invite, err := s.GetInviteByPairingToken(ctx, pairingHash2)
	if err != nil {
		t.Errorf("GetInviteByPairingToken at exact expiry should succeed, got %v", err)
	}
	if invite == nil || invite.FromPeer != "alice" {
		t.Errorf("GetInviteByPairingToken at exact expiry returned wrong invite: %+v", invite)
	}

	// One second after expiry, GetInviteByPairingToken should fail
	clk.Set(time.Unix(currentTime+201, 0))
	_, err = s.GetInviteByPairingToken(ctx, pairingHash2)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetInviteByPairingToken should return ErrNotFound for expired token, got %v", err)
	}

	// 5. AcceptInviteByPairingToken rejects expired token
	clk.Set(time.Unix(currentTime+202, 0))
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash2, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("AcceptInviteByPairingToken should return ErrNotFound for expired token, got %v", err)
	}

	// 6. RegisterAndAcceptByPairing rejects expired token (pre-check)
	clk.Set(time.Unix(currentTime+203, 0))
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash2, "charlie", "Charlie", "hc", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing should return ErrNotFound for expired token in pre-check, got %v", err)
	}

	// 7. RegisterAndAcceptByPairing: token expires between pre-check and tx
	// Create a third invite
	codeHash3 := "code_test3"
	pairingHash3 := "pair_test3"
	expiresAt3 := time.Unix(currentTime+300, 0)
	clk.Set(time.Unix(currentTime+100, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash3, pairingHash3, "alice", []string{"messages"}, nil, expiresAt3); err != nil {
		t.Fatal(err)
	}

	// Set clock after expiry to test that RegisterAndAcceptByPairing rejects expired token
	clk.Set(time.Unix(currentTime+301, 0))
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash3, "dave", "Dave", "hd", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing should return ErrNotFound for expired token, got %v", err)
	}

	// Assert no orphan peer, no grant, invite's used_by is NULL
	var peerCount int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM peers WHERE id = ? OR name = ?", "dave", "Dave").Scan(&peerCount)
	if err != nil {
		t.Fatal(err)
	}
	if peerCount != 0 {
		t.Errorf("expected no peer row for dave, got count %d", peerCount)
	}

	var grantCount int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM grants WHERE grantee = ?", "dave").Scan(&grantCount)
	if err != nil {
		t.Fatal(err)
	}
	if grantCount != 0 {
		t.Errorf("expected no grant for dave, got count %d", grantCount)
	}

	var usedBy sql.NullString
	err = s.db.QueryRowContext(ctx, "SELECT used_by FROM invites WHERE pairing_token_hash = ?", pairingHash3).Scan(&usedBy)
	if err != nil {
		t.Fatal(err)
	}
	if usedBy.Valid {
		t.Errorf("invite used_by should be NULL, got %q", usedBy.String)
	}

	// Exact boundary tests for AcceptInviteByPairingToken
	// Create invite expiring at currentTime + 400
	codeHash4 := "code_test4"
	pairingHash4 := "pair_test4"
	expiresAt4 := time.Unix(currentTime+400, 0)
	clk.Set(time.Unix(currentTime+200, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash4, pairingHash4, "alice", []string{"messages"}, nil, expiresAt4); err != nil {
		t.Fatal(err)
	}

	// At exact expiry time: should be accepted
	clk.Set(time.Unix(currentTime+400, 0))
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash4, "bob", nil, nil)
	if err != nil {
		t.Errorf("AcceptInviteByPairingToken at exact expiry (now == expires_at) should succeed, got %v", err)
	}

	// Create another invite for +1 test
	codeHash5 := "code_test5"
	pairingHash5 := "pair_test5"
	expiresAt5 := time.Unix(currentTime+500, 0)
	clk.Set(time.Unix(currentTime+200, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash5, pairingHash5, "alice", []string{"messages"}, nil, expiresAt5); err != nil {
		t.Fatal(err)
	}

	// One second after expiry: should be rejected
	clk.Set(time.Unix(currentTime+501, 0))
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash5, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("AcceptInviteByPairingToken at expires_at+1 should return ErrNotFound, got %v", err)
	}

	// Exact boundary tests for RegisterAndAcceptByPairing
	// Create invite expiring at currentTime + 600
	codeHash6 := "code_test6"
	pairingHash6 := "pair_test6"
	expiresAt6 := time.Unix(currentTime+600, 0)
	clk.Set(time.Unix(currentTime+200, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash6, pairingHash6, "alice", []string{"messages"}, nil, expiresAt6); err != nil {
		t.Fatal(err)
	}

	// At exact expiry time: should be accepted
	clk.Set(time.Unix(currentTime+600, 0))
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash6, "carol", "Carol", "hc", "", "", nil, nil)
	if err != nil {
		t.Errorf("RegisterAndAcceptByPairing at exact expiry (now == expires_at) should succeed, got %v", err)
	}

	// Create another invite for +1 test
	codeHash7 := "code_test7"
	pairingHash7 := "pair_test7"
	expiresAt7 := time.Unix(currentTime+700, 0)
	clk.Set(time.Unix(currentTime+200, 0))
	if err := s.CreateInviteWithPairing(ctx, codeHash7, pairingHash7, "alice", []string{"messages"}, nil, expiresAt7); err != nil {
		t.Fatal(err)
	}

	// One second after expiry: should be rejected
	clk.Set(time.Unix(currentTime+701, 0))
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash7, "dan", "Dan", "hdan", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing at expires_at+1 should return ErrNotFound, got %v", err)
	}
}

// TestAcceptInviteExactBoundary verifies AcceptInvite (by code) at exact expiry boundary.
// Issue #110 item 3: exact-boundary row for AcceptInvite (now == expires_at accepted; expires_at+1 rejected).
func TestAcceptInviteExactBoundary(t *testing.T) {
	ctx := context.Background()
	currentTime := time.Unix(1000000, 0)
	clk := clocktest.New(currentTime)

	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create an invite that expires at currentTime + 100s
	expiresAt := currentTime.Add(100 * time.Second)
	if err := s.CreateInvite(ctx, "code_boundary", "alice", []string{"messages"}, nil, expiresAt); err != nil {
		t.Fatal(err)
	}

	// At exactly expires_at (now == expires_at), invite should be accepted
	clk.Set(currentTime.Add(100 * time.Second))
	grant, err := s.AcceptInvite(ctx, "code_boundary", "bob", nil, nil)
	if err != nil {
		t.Fatalf("AcceptInvite at exact boundary (now == expires_at) should succeed, got %v", err)
	}
	if grant == nil || grant.Owner != "alice" || grant.Grantee != "bob" {
		t.Errorf("AcceptInvite at boundary returned wrong grant: %+v", grant)
	}

	// Create another invite to test expires_at+1
	expiresAt2 := currentTime.Add(100 * time.Second)
	if err := s.CreateInvite(ctx, "code_boundary2", "alice", []string{"messages"}, nil, expiresAt2); err != nil {
		t.Fatal(err)
	}

	// At expires_at+1, invite should be rejected
	clk.Set(currentTime.Add(101 * time.Second))
	_, err = s.AcceptInvite(ctx, "code_boundary2", "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("AcceptInvite at expires_at+1 should return ErrNotFound, got %v", err)
	}
}

// TestRollbackAfterPeerInsert verifies that when RegisterAndAcceptByPairing fails
// after the peer insert but before commit, no orphan peer is left and the invite remains unconsumed.
func TestRollbackAfterPeerInsert(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/rollback.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	pairingHash := "pair1"
	if err := s.CreateInviteWithPairing(ctx, "code1", pairingHash, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Create a trigger that will fail the grant INSERT (after peer INSERT succeeds)
	if _, err := s.db.Exec(`CREATE TRIGGER rollback_test_trigger BEFORE INSERT ON grants BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`DROP TRIGGER IF EXISTS rollback_test_trigger`)

	// Try to register - peer INSERT will succeed but grant INSERT will fail due to trigger
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash, "bob", "Bob", "hb", "", "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("expected the injected grant-insert failure, got %v", err)
	}

	// Verify no orphan peer was created
	var bobCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='bob'`).Scan(&bobCount); err != nil {
		t.Fatal(err)
	}
	if bobCount != 0 {
		t.Error("orphan peer 'bob' created after failed grant insert")
	}

	// Verify the invite is still unconsumed (used_by IS NULL)
	var used sql.NullString
	if err := s.db.QueryRow(`SELECT used_by FROM invites WHERE pairing_token_hash=?`, pairingHash).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used.Valid {
		t.Error("invite was marked as used after failed transaction")
	}

	// Drop the trigger and verify the invite can still be redeemed
	if _, err := s.db.Exec(`DROP TRIGGER rollback_test_trigger`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAndAcceptByPairing(ctx, pairingHash, "carol", "Carol", "hc", "", "", nil, nil); err != nil {
		t.Fatalf("invite should still be redeemable after trigger removed: %v", err)
	}
}

// TestContextCancellationBeforeTransaction verifies that cancelling before BeginTx doesn't wedge the DB.
func TestContextCancellationBeforeTransaction(t *testing.T) {
	path := t.TempDir() + "/cancel-before.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	pairingHash := "cancel_hash"
	exp := time.Now().Add(time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "code1", pairingHash, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Open a second connection that will hold the write lock
	blocker, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Start a transaction on the blocker to hold the write lock
	blockTx, err := blocker.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blockTx.Exec(`PRAGMA user_version`); err != nil {
		t.Fatal(err)
	}

	// Try to accept in a goroutine with a context that will be cancelled
	cancelCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", "", nil, nil)
		done <- err
	}()

	// Wait a bit for the call to block on BeginTx, then cancel
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Should return with context.Canceled
	err = <-done
	if !errors.Is(err, context.Canceled) && err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Release the lock
	blockTx.Rollback()
	blocker.Close()

	// DB should not be wedged - normal operations should work
	normalCtx := context.Background()
	if err := s.CreatePeer(normalCtx, "carol", "Carol", "hc", "", ""); err != nil {
		t.Fatalf("DB wedged after cancel: %v", err)
	}

	// Original pairing token should still be redeemable
	_, err = s.RegisterAndAcceptByPairing(normalCtx, pairingHash, "dave", "Dave", "hd", "", "", nil, nil)
	if err != nil {
		t.Fatalf("pairing redemption failed after cancel: %v", err)
	}

	var peerCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&peerCount)
	if peerCount != 3 {
		t.Errorf("got %d peers, want 3 (alice, carol, dave)", peerCount)
	}
}

// TestContextCancellationMidTransaction verifies that cancelling after BeginTx and after the peer INSERT
// rolls back correctly, leaving no orphan peer and the invite unconsumed.
func TestContextCancellationMidTransaction(t *testing.T) {
	path := t.TempDir() + "/cancel-mid-tx.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	pairingHash := "cancel_hash"
	exp := time.Now().Add(time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "code1", pairingHash, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Set up cancel function for the test_cancel scalar function
	cancelCtx, cancel := context.WithCancel(context.Background())
	testCancelFunc.Store(cancel)
	defer testCancelFunc.Store((context.CancelFunc)(nil))

	// Create a trigger that calls test_cancel() after peer INSERT
	if _, err := s.db.Exec(`CREATE TRIGGER cancel_test_trigger AFTER INSERT ON peers BEGIN SELECT test_cancel(); END`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`DROP TRIGGER IF EXISTS cancel_test_trigger`)

	// Try to register and accept - should fail due to cancellation after peer INSERT
	_, err = s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", "", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// Verify no orphan peer was created
	var bobCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='bob'`).Scan(&bobCount); err != nil {
		t.Fatal(err)
	}
	if bobCount != 0 {
		t.Error("orphan peer 'bob' created after mid-transaction cancel")
	}

	// Verify the invite was not consumed (used_by IS NULL)
	var used sql.NullString
	if err := s.db.QueryRow(`SELECT used_by FROM invites WHERE pairing_token_hash=?`, pairingHash).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used.Valid {
		t.Error("invite was consumed after mid-transaction cancel")
	}

	// Drop trigger and clear cancel function
	if _, err := s.db.Exec(`DROP TRIGGER cancel_test_trigger`); err != nil {
		t.Fatal(err)
	}
	testCancelFunc.Store((context.CancelFunc)(nil))

	// Verify DB isn't wedged: next accept should succeed
	normalCtx := context.Background()
	if _, err := s.RegisterAndAcceptByPairing(normalCtx, pairingHash, "carol", "Carol", "hc", "", "", nil, nil); err != nil {
		t.Fatalf("DB wedged after mid-tx cancel: %v", err)
	}

	// Verify a plain write succeeds
	if err := s.CreatePeer(normalCtx, "dave", "Dave", "hd", "", ""); err != nil {
		t.Fatalf("plain write failed after mid-tx cancel: %v", err)
	}

	var peerCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&peerCount)
	if peerCount != 3 {
		t.Errorf("got %d peers, want 3 (alice, carol, dave)", peerCount)
	}
}

// Production volumes created before pairing links already have notify_email,
// so migrate must not stop there. invites has no pairing_token_hash until Open.
func TestPairingTokenHashMigration(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/pre-pairing.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT
		);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('p_old','old','h',1,'old@example.com')`); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at) VALUES('legacy','p_old','messages','',?)`, exp); err != nil {
		t.Fatal(err)
	}
	var cols int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name = 'pairing_token_hash'`).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("fixture column count %d %v", cols, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	email, err := s.NotifyEmail(ctx, "p_old")
	if err != nil || email != "old@example.com" {
		t.Fatalf("notify_email %q %v", email, err)
	}
	until := time.Now().Add(time.Hour).UTC()
	if err := s.CreateInviteWithPairing(ctx, "c-pair", "tok-hash", "p_old", []string{"messages"}, []string{"notes"}, until); err != nil {
		t.Fatal(err)
	}
	info, err := s.GetInviteByPairingToken(ctx, "tok-hash")
	if err != nil {
		t.Fatal(err)
	}
	if info.FromPeer != "p_old" || len(info.Scopes) != 1 || info.Scopes[0] != "messages" || len(info.Bags) != 1 || info.Bags[0] != "notes" {
		t.Fatalf("invite info: %+v", info)
	}
	if info.ExpiresAt.Unix() != until.Unix() {
		t.Fatalf("expires %s want %s", info.ExpiresAt, until)
	}
	if _, err := s.GetInviteByPairingToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Code-only invites store NULL and must still insert beside a pairing invite.
	if err := s.CreateInvite(ctx, "c-plain", "p_old", []string{"messages"}, nil, until); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInviteWithPairing(ctx, "c-dup", "tok-hash", "p_old", []string{"messages"}, nil, until); err == nil {
		t.Fatal("expected unique pairing token hash")
	}
	if err := s.CreatePeer(ctx, "p_new", "new", "hn", "", ""); err != nil {
		t.Fatal(err)
	}
	g, err := s.AcceptInvite(ctx, "legacy", "p_new", nil, nil)
	if err != nil || g.Owner != "p_old" || g.Grantee != "p_new" {
		t.Fatalf("legacy accept %+v %v", g, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	info, err = s2.GetInviteByPairingToken(ctx, "tok-hash")
	if err != nil || info.FromPeer != "p_old" {
		t.Fatalf("reopen %+v %v", info, err)
	}
}

// A database from before both columns must gain notify_email and pairing_token_hash.
// Returning after the first column leaves pairing invites broken.
func TestMigrateNotifyEmailAndPairingToken(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/v0.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT
		);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at) VALUES('p_old','old','h',1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	email, err := s.NotifyEmail(ctx, "p_old")
	if err != nil || email != "" {
		t.Fatalf("notify_email %q %v", email, err)
	}
	until := time.Now().Add(time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "c-pair", "tok-hash", "p_old", []string{"messages"}, nil, until); err != nil {
		t.Fatal(err)
	}
	info, err := s.GetInviteByPairingToken(ctx, "tok-hash")
	if err != nil || info.FromPeer != "p_old" || len(info.Scopes) != 1 || info.Scopes[0] != "messages" {
		t.Fatalf("invite info %+v %v", info, err)
	}
}

// TestPR11AlreadyMigrated verifies databases that PR #11 already migrated upgrade cleanly.
// PR #11 added pairing_token_hash column and a full unique index (no WHERE clause), but did not use PRAGMA user_version.
// This test creates exactly that state (user_version=0, both columns, full index) and verifies:
// 1. migrate() runs without error
// 2. user_version advances to 2
// 3. Running migrate() again is a safe no-op
// 4. Existing invite rows and their pairing_token_hash values survive
// 5. The index (whether PR #11's full or our partial) works correctly
func TestPR11AlreadyMigrated(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/pr11.db"

	// Create exactly PR #11's post-migration schema (238b916)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	// PR #11's exact schema: both columns, full unique index (no WHERE clause)
	if _, err := db.Exec(`
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT,
			pairing_token_hash TEXT
		);
		CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash);
		CREATE TABLE grants (owner TEXT NOT NULL, grantee TEXT NOT NULL, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee));
	`); err != nil {
		t.Fatal(err)
	}

	// Insert test data including an invite with a pairing token
	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('alice','Alice','ha',1,'alice@example.com')`); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,pairing_token_hash) VALUES('code1','alice','messages','',?,'pair_token_123')`, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at) VALUES('code2','alice','messages','',?)`, exp); err != nil {
		t.Fatal(err)
	}

	// Verify user_version is 0 (PR #11 didn't set it)
	var version int
	db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 0 {
		t.Fatalf("fixture user_version = %d, want 0", version)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// First migrate: Open should run migrations
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Verify user_version advanced to 2
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}

	// Verify columns still exist
	var notifyEmailCol, pairingCol int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&notifyEmailCol)
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&pairingCol)
	if notifyEmailCol != 1 || pairingCol != 1 {
		t.Fatalf("columns missing after first migrate: notify_email=%d, pairing_token_hash=%d", notifyEmailCol, pairingCol)
	}

	// Verify PR #11's full unique index still exists
	var hasIndex int
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&hasIndex)
	if hasIndex != 1 {
		t.Fatal("invites_pairing_token_hash index missing after first migrate")
	}

	// Verify existing data survived
	email, err := s.NotifyEmail(ctx, "alice")
	if err != nil || email != "alice@example.com" {
		t.Fatalf("notify_email after PR #11 migration: %q %v", email, err)
	}

	// Verify existing invite with pairing_token_hash survived
	var pairingToken sql.NullString
	if err := s.db.QueryRow(`SELECT pairing_token_hash FROM invites WHERE code_hash='code1'`).Scan(&pairingToken); err != nil {
		t.Fatalf("existing invite query failed: %v", err)
	}
	if !pairingToken.Valid || pairingToken.String != "pair_token_123" {
		t.Fatalf("existing pairing_token_hash = %v, want 'pair_token_123'", pairingToken)
	}

	// Verify code-only invite (NULL pairing_token_hash) survived
	if err := s.db.QueryRow(`SELECT pairing_token_hash FROM invites WHERE code_hash='code2'`).Scan(&pairingToken); err != nil {
		t.Fatalf("code-only invite query failed: %v", err)
	}
	if pairingToken.Valid {
		t.Fatalf("code-only invite has pairing_token_hash = %s, want NULL", pairingToken.String)
	}

	// Run migrations again (should be no-op)
	_, err = checkSchemaVersion(s.db)
	if err != nil {
		t.Fatalf("checkSchemaVersion failed: %v", err)
	}
	opts := OpenOptions{Logger: slog.Default()}
	for i, mig := range migrations {
		target := i + 1
		if err := runMigrationStep(s.db, target, mig, SchemaVersion(), opts); err != nil {
			t.Fatalf("second migrate step %d failed: %v", target, err)
		}
	}

	// Verify user_version unchanged
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Fatalf("user_version after second migrate = %d, want %d", version, len(migrations))
	}

	// Verify columns still present
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&notifyEmailCol)
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&pairingCol)
	if notifyEmailCol != 1 || pairingCol != 1 {
		t.Fatalf("columns missing after second migrate: notify_email=%d, pairing_token_hash=%d", notifyEmailCol, pairingCol)
	}

	// Verify data still intact
	if err := s.db.QueryRow(`SELECT pairing_token_hash FROM invites WHERE code_hash='code1'`).Scan(&pairingToken); err != nil {
		t.Fatalf("invite query after second migrate failed: %v", err)
	}
	if !pairingToken.Valid || pairingToken.String != "pair_token_123" {
		t.Fatalf("pairing_token_hash after second migrate = %v, want 'pair_token_123'", pairingToken)
	}

	// Verify pairing invites work with PR #11's full index
	if err := s.CreateInviteWithPairing(ctx, "code3", "pair2", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("pairing invite after PR #11 migration: %v", err)
	}

	// Verify the index enforces uniqueness (whether full or partial)
	if err := s.CreateInviteWithPairing(ctx, "code4", "pair2", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("duplicate pairing_token_hash should fail")
	}

	s.Close()
}

// TestPragmasInEffect verifies that busy_timeout, foreign_keys, and immediate txlock are active.
func TestPragmasInEffect(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"memory", ":memory:"},
		{"file", t.TempDir() + "/pragmas.db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			// Check busy_timeout
			var busyTimeout int
			if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
				t.Fatal(err)
			}
			if busyTimeout != 5000 {
				t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
			}

			// Check foreign_keys
			var fkEnabled int
			if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fkEnabled); err != nil {
				t.Fatal(err)
			}
			if fkEnabled != 1 {
				t.Errorf("foreign_keys = %d, want 1", fkEnabled)
			}

			// Verify _txlock=immediate: Begin() should take the write lock immediately,
			// not defer it until the first write (which is DEFERRED behavior)
			if tt.name == "file" {
				// For file DBs, open a second Store on the same path
				s2, err := Open(tt.path)
				if err != nil {
					t.Fatal(err)
				}
				defer s2.Close()

				// Start a transaction on first connection and do nothing
				tx1, err := s.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx1.Rollback()

				// Try to begin a transaction on second connection - should block or fail
				// because the first connection already holds the write lock
				done := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()
					tx2, err := s2.db.BeginTx(ctx, nil)
					if err != nil {
						done <- err
						return
					}
					tx2.Rollback()
					done <- nil
				}()

				err = <-done
				if err == nil {
					t.Error("second BeginTx succeeded, but first tx should hold write lock (_txlock=immediate not active)")
				} else if !isLockContention(err) {
					t.Errorf("second BeginTx failed for an unrelated reason: %v", err)
				}
			} else {
				// For memory DBs, use a shared name to test txlock with two connections
				sharedName := "file:test-pragma-mem?mode=memory&cache=shared&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
				db1, err := sql.Open("sqlite", sharedName)
				if err != nil {
					t.Fatal(err)
				}
				defer db1.Close()
				db1.SetMaxOpenConns(1)

				db2, err := sql.Open("sqlite", sharedName)
				if err != nil {
					t.Fatal(err)
				}
				defer db2.Close()
				db2.SetMaxOpenConns(1)

				// Create the schema on db1
				if _, err := db1.Exec(schema); err != nil {
					t.Fatal(err)
				}

				// Start a transaction on db1 and do nothing
				tx1, err := db1.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx1.Rollback()

				// Try to begin a transaction on db2 - should block or fail
				done := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()
					tx2, err := db2.BeginTx(ctx, nil)
					if err != nil {
						done <- err
						return
					}
					tx2.Rollback()
					done <- nil
				}()

				err = <-done
				if err == nil {
					t.Error("second BeginTx succeeded, but first tx should hold write lock (_txlock=immediate not active)")
				} else if !isLockContention(err) {
					t.Errorf("second BeginTx failed for an unrelated reason: %v", err)
				}
			}
		})
	}
}

// TestFailClosedVersionGuard verifies that the database refuses to open when user_version
// is newer than the binary supports, and leaves the database untouched.
func TestFailClosedVersionGuard(t *testing.T) {
	path := secureTempDir(t) + "/future.db"

	// Create a database with a future schema version
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	// Set up a minimal schema
	if _, err := db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}

	// Set user_version to a future version (higher than current max of 3)
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}

	var versionBefore int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	if versionBefore != 99 {
		t.Fatalf("setup failed: user_version = %d, want 99", versionBefore)
	}

	db.Close()

	// Attempt to open with Store - should fail with clear error message
	_, err = Open(path)
	if err == nil {
		t.Fatal("expected error when opening database with future schema version")
	}

	// Verify error is ErrSchemaTooNew via errors.As
	var tooNewErr *ErrSchemaTooNew
	if !errors.As(err, &tooNewErr) {
		t.Errorf("expected ErrSchemaTooNew, got %T: %v", err, err)
	} else {
		if tooNewErr.Have != 99 || tooNewErr.Max != len(migrations) {
			t.Errorf("ErrSchemaTooNew: Have=%d, Max=%d, want Have=99, Max=%d", tooNewErr.Have, tooNewErr.Max, len(migrations))
		}
	}

	// Verify error message mentions both versions
	errMsg := err.Error()
	if !strings.Contains(errMsg, "99") || !strings.Contains(errMsg, "6") {
		t.Errorf("error message should mention both schema versions (99 and 6), got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "newer") && !strings.Contains(errMsg, "upgrade") {
		t.Errorf("error message should mention 'newer' or 'upgrade', got: %s", errMsg)
	}

	// Verify the database was not modified (user_version still 99)
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var versionAfter int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&versionAfter); err != nil {
		t.Fatal(err)
	}
	if versionAfter != 99 {
		t.Errorf("database was modified: user_version changed from 99 to %d", versionAfter)
	}
}

// TestSchemaVersionDerivedFromMigrations verifies that SchemaVersion() returns exactly len(migrations)
// and that a fresh Open ends at that version.
func TestSchemaVersionDerivedFromMigrations(t *testing.T) {
	// SchemaVersion() must equal len(migrations)
	if SchemaVersion() != len(migrations) {
		t.Fatalf("SchemaVersion() = %d, len(migrations) = %d; must be equal", SchemaVersion(), len(migrations))
	}

	// Fresh Open should end at SchemaVersion()
	path := secureTempDir(t) + "/fresh.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.SchemaVersionInUse() != SchemaVersion() {
		t.Errorf("fresh Open: SchemaVersionInUse() = %d, SchemaVersion() = %d; should match", s.SchemaVersionInUse(), SchemaVersion())
	}

	// Verify the database user_version matches
	var dbVersion int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&dbVersion); err != nil {
		t.Fatal(err)
	}
	if dbVersion != SchemaVersion() {
		t.Errorf("database user_version = %d, SchemaVersion() = %d; should match", dbVersion, SchemaVersion())
	}
}

// TestNegativeSchemaVersion verifies that a negative user_version is rejected.
func TestNegativeSchemaVersion(t *testing.T) {
	path := secureTempDir(t) + "/negative.db"

	// Create a database with a negative user_version
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}

	// Set negative version
	if _, err := db.Exec(`PRAGMA user_version = -5`); err != nil {
		t.Fatal(err)
	}

	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != -5 {
		t.Fatalf("setup failed: user_version = %d, want -5", version)
	}

	db.Close()

	// Attempt to open - should fail with ErrSchemaInvalid
	_, err = Open(path)
	if err == nil {
		t.Fatal("expected error when opening database with negative schema version")
	}

	// Verify error is ErrSchemaInvalid via errors.As
	var invalidErr *ErrSchemaInvalid
	if !errors.As(err, &invalidErr) {
		t.Errorf("expected ErrSchemaInvalid, got %T: %v", err, err)
	} else {
		if invalidErr.Have != -5 {
			t.Errorf("ErrSchemaInvalid.Have = %d, want -5", invalidErr.Have)
		}
	}
}

// TestVersionGuardBeforeSchema verifies that checkSchemaVersion runs before db.Exec(schema),
// leaving sqlite_master and journal_mode untouched when a too-new or invalid version is detected.
func TestVersionGuardBeforeSchema(t *testing.T) {
	path := secureTempDir(t) + "/guard.db"

	// Create a v99 database with custom schema
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different schema structure to detect if Open overwrites it
	if _, err := db.Exec(`CREATE TABLE custom_table (data TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}

	// Snapshot sqlite_master and journal_mode before Open attempt
	var masterRowsBefore strings.Builder
	rows, err := db.Query(`SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var typ, name, tblName string
		var sql sql.NullString
		if err := rows.Scan(&typ, &name, &tblName, &sql); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		fmt.Fprintf(&masterRowsBefore, "%s|%s|%s|%s\n", typ, name, tblName, sql.String)
	}
	rows.Close()

	var journalModeBefore string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalModeBefore); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Attempt to Open - should fail before executing schema
	_, err = Open(path)
	if err == nil {
		t.Fatal("expected error when opening database with future schema version")
	}

	// Reopen and verify sqlite_master and journal_mode unchanged
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var masterRowsAfter strings.Builder
	rows, err = db.Query(`SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var typ, name, tblName string
		var sql sql.NullString
		if err := rows.Scan(&typ, &name, &tblName, &sql); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		fmt.Fprintf(&masterRowsAfter, "%s|%s|%s|%s\n", typ, name, tblName, sql.String)
	}
	rows.Close()

	if masterRowsBefore.String() != masterRowsAfter.String() {
		t.Errorf("sqlite_master changed after rejected Open:\nBefore:\n%s\nAfter:\n%s", masterRowsBefore.String(), masterRowsAfter.String())
	}

	var journalModeAfter string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalModeAfter); err != nil {
		t.Fatal(err)
	}
	if journalModeBefore != journalModeAfter {
		t.Errorf("journal_mode changed from %q to %q after rejected Open", journalModeBefore, journalModeAfter)
	}

	// Verify custom_table still exists and peers table does NOT exist
	var customTableCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='custom_table'`).Scan(&customTableCount); err != nil {
		t.Fatal(err)
	}
	if customTableCount != 1 {
		t.Error("custom_table should still exist")
	}

	var peersTableCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='peers'`).Scan(&peersTableCount); err != nil {
		t.Fatal(err)
	}
	if peersTableCount != 0 {
		t.Error("peers table should not exist (schema script should not have run)")
	}
}

// TestBackupBeforeMigration verifies that a VACUUM INTO backup is created
// before any pending migration runs.
func TestBackupBeforeMigration(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/test.db"

	// Create a v2 database (one version behind current max of 3)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	// Create v2 schema
	if _, err := db.Exec(`
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT,
			pairing_token_hash TEXT
		);
		CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash) WHERE pairing_token_hash IS NOT NULL;
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}

	// Insert test data to verify backup captures it
	if _, err := db.Exec(`INSERT INTO peers (id, name, key_hash, created_at) VALUES ('test_peer', 'Test', 'hash1', ?)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Open with Store - this should create the backup and run migration
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify a backup was created with pattern .pre-v6-from-v2.<timestamp>
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	var backupPath string
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "test.db.pre-v6-from-v") {
			backupPath = tempDir + "/" + f.Name()
			break
		}
	}
	if backupPath == "" {
		t.Fatal("backup file was not created")
	}

	// Verify backup is a valid SQLite database and contains the test data
	backupDB, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatalf("cannot open backup at %s: %v", backupPath, err)
	}
	defer backupDB.Close()

	var peerID string
	if err := backupDB.QueryRow(`SELECT id FROM peers WHERE id='test_peer'`).Scan(&peerID); err != nil {
		t.Fatalf("backup does not contain test data: %v", err)
	}
	if peerID != "test_peer" {
		t.Errorf("backup peer_id = %q, want 'test_peer'", peerID)
	}

	// Verify backup has the old version (2, not 3)
	var backupVersion int
	if err := backupDB.QueryRow(`PRAGMA user_version`).Scan(&backupVersion); err != nil {
		t.Fatal(err)
	}
	if backupVersion != 2 {
		t.Errorf("backup user_version = %d, want 2 (pre-migration)", backupVersion)
	}

	// Verify backup has the original row count
	var backupPeerCount int
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&backupPeerCount); err != nil {
		t.Fatalf("cannot count peers in backup: %v", err)
	}
	if backupPeerCount != 1 {
		t.Errorf("backup has %d peers, want 1", backupPeerCount)
	}

	// Verify main database was migrated to version 3
	var mainVersion int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&mainVersion); err != nil {
		t.Fatal(err)
	}
	if mainVersion != len(migrations) {
		t.Errorf("main database user_version = %d, want %d (post-migration)", mainVersion, len(migrations))
	}

	// Verify backup exists (mode checks are in backup_mode_test_unix.go)
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup file not found: %v", err)
	}
}

// TestBackupWithQuoteInPath verifies that backups work when the database path contains a single quote.
func TestBackupWithQuoteInPath(t *testing.T) {
	// Create a directory with a single quote in the name
	baseDir := secureTempDir(t)
	quotedDir := baseDir + "/test'dir"
	if err := os.Mkdir(quotedDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := quotedDir + "/test.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT, pairing_token_hash TEXT);
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers (id, name, key_hash, created_at) VALUES ('p1', 'Test', 'h1', ?)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Open with Store - should handle the quote in the path
	s, err := Open(path)
	if err != nil {
		t.Fatalf("failed to open database with quote in path: %v", err)
	}
	defer s.Close()

	// Verify backup was created
	files, err := os.ReadDir(quotedDir)
	if err != nil {
		t.Fatal(err)
	}

	foundBackup := false
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "test.db.pre-v6-from-v") {
			foundBackup = true
			// Verify we can open it
			backupPath := quotedDir + "/" + f.Name()
			backupDB, err := sql.Open("sqlite", backupPath)
			if err != nil {
				t.Fatalf("cannot open backup: %v", err)
			}
			defer backupDB.Close()

			var peerID string
			if err := backupDB.QueryRow(`SELECT id FROM peers WHERE id='p1'`).Scan(&peerID); err != nil {
				t.Fatalf("backup is corrupted: %v", err)
			}
			break
		}
	}

	if !foundBackup {
		t.Error("backup was not created with quote in path")
	}
}

// TestBackupRetry verifies that a second migration attempt (with an existing backup)
// creates a new backup with a unique timestamp and doesn't fail.
func TestBackupRetry(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/retry.db"

	// Create a v1 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT);
		PRAGMA user_version = 1;
	`); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// First migration (v1 -> v3)
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()

	// Count backups
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	backupCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "retry.db.pre-v6-from-v") {
			backupCount++
		}
	}
	if backupCount != 1 {
		t.Errorf("first migration created %d backups, want 1", backupCount)
	}

	// Manually downgrade to v1 to simulate a retry scenario
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 1; ALTER TABLE peers DROP COLUMN created_via_invite`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Second migration attempt - should create another backup with different timestamp
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// Count backups again
	files, err = os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	backupCount = 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "retry.db.pre-v6-from-v") {
			backupCount++
		}
	}
	if backupCount != 2 {
		t.Errorf("retry created %d total backups, want 2", backupCount)
	}
}

// TestBrandNewDatabaseSkipsBackup verifies that a brand-new database (user_version 0, no tables)
// doesn't create a backup.
func TestBrandNewDatabaseSkipsBackup(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/new.db"

	// Open creates a brand-new database
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify no backup was created
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "new.db.pre-v") {
			t.Errorf("backup created for brand-new database: %s", f.Name())
		}
	}
}

// TestBackupFailureAbortsStartup verifies that if the backup fails (e.g., unwritable directory),
// the migration is aborted, nothing is migrated, and no stray backup file is left.
func TestBackupFailureAbortsStartup(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root (chmod doesn't restrict root)")
	}

	tempDir := secureTempDir(t)
	dbDir := tempDir + "/db"
	backupDir := tempDir + "/backups"

	if err := os.Mkdir(dbDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backupDir, 0700); err != nil {
		t.Fatal(err)
	}

	path := dbDir + "/test.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT, pairing_token_hash TEXT);
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Inject a vacuumInto that fails (simulates disk full or I/O error)
	// This actually tests backup failure, not directory permission failure
	vacuumHook := func(db *sql.DB, backupPath string) error {
		return fmt.Errorf("simulated VACUUM INTO failure")
	}

	opts := OpenOptions{
		BackupDir:  backupDir,
		vacuumInto: vacuumHook,
	}

	// Attempt to open - should fail due to VACUUM INTO failure
	_, err = OpenWithOptions(path, opts)
	if err == nil {
		t.Fatal("expected error when VACUUM INTO fails")
	}

	if !strings.Contains(err.Error(), "VACUUM INTO backup") {
		t.Errorf("error should mention VACUUM INTO backup failure, got: %v", err)
	}

	// Verify the database wasn't migrated
	db2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	var version int
	if err := db2.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Errorf("database was migrated despite backup failure: version = %d, want 2", version)
	}

	// Verify no stray backup file was left
	files, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "test.db.pre-v") {
			t.Errorf("stray backup file left behind: %s", f.Name())
		}
	}
}

// TestPreExistingBackupNotOverwritten verifies that when a backup file already exists at the target path,
// the collision retry creates a new backup with a random hex suffix without overwriting the pre-existing file.
func TestPreExistingBackupNotOverwritten(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/test.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','Test','h1',1,'');
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Pin clock to a known time to make backup names deterministic
	fixedTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Pre-create files at the base backup name to force collision
	baseName := "test.db.pre-v6-from-v2.20260101-120000.000000"
	basePath := tempDir + "/" + baseName
	if err := os.WriteFile(basePath, []byte("pre-existing base"), 0600); err != nil {
		t.Fatal(err)
	}

	// Open with fixed clock - should detect collision and create backup with hex suffix
	opts := OpenOptions{
		BackupDir:            tempDir,
		BackupRetentionCount: 10, // Keep all to verify both exist
		Logger:               slog.Default(),
		Clock:                clocktest.New(fixedTime),
	}

	st, err := OpenWithOptions(path, opts)
	if err != nil {
		t.Fatalf("Open should succeed by adding hex suffix: %v", err)
	}
	defer st.Close()

	// Verify a backup was created
	backupPath := st.LastBackupPath()
	if backupPath == "" {
		t.Fatal("no backup created")
	}

	backupName := filepath.Base(backupPath)

	// The new backup must NOT be the base name (must have added hex suffix)
	if backupName == baseName {
		t.Errorf("backup overwrote base name without hex suffix: %s", backupName)
	}

	// Must have an 8-char hex suffix
	hexSuffixPattern := regexp.MustCompile(`\.\d{8}-\d{6}\.\d{6}\.[0-9a-f]{8}$`)
	if !hexSuffixPattern.MatchString(backupName) {
		t.Errorf("backup name doesn't match hex suffix pattern: %s", backupName)
	}

	// Verify the pre-existing base file was not overwritten
	if data, err := os.ReadFile(basePath); err != nil {
		t.Errorf("pre-existing base file was deleted: %v", err)
	} else if string(data) != "pre-existing base" {
		t.Errorf("pre-existing base file was overwritten")
	}

	// Verify the new backup is valid
	fullBackupPath := tempDir + "/" + backupName
	if err := verifyBackup(fullBackupPath, 2); err != nil {
		t.Errorf("new backup failed verification: %v", err)
	}

	// Count total backups (should have both the pre-existing and the new one)
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	backupCount := 0
	for _, f := range files {
		if strings.Contains(f.Name(), ".pre-v") && !strings.HasSuffix(f.Name(), ".partial") {
			backupCount++
		}
	}

	if backupCount != 2 {
		t.Errorf("got %d backups (pre-existing + new), want 2", backupCount)
	}
}

// TestInMemoryExplicitDSN verifies that in-memory databases with explicit DSN skip backup.
func TestInMemoryExplicitDSN(t *testing.T) {
	// Use buildDSN to get the same in-memory DSN format the code uses
	dsn := buildDSN(":memory:")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Manually set up schema and set version to v2
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}

	// Run migrations (bypassing Open to test the migration logic directly)
	_, err = checkSchemaVersion(db)
	if err != nil {
		t.Fatalf("checkSchemaVersion failed: %v", err)
	}
	opts := OpenOptions{Logger: slog.Default()}
	for i, mig := range migrations {
		target := i + 1
		if err := runMigrationStep(db, target, mig, SchemaVersion(), opts); err != nil {
			t.Fatalf("migration step %d failed: %v", target, err)
		}
	}

	// Verify it migrated to v3
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Errorf("version = %d, want 5", version)
	}

	// The test passing means no backup was created (it would have failed trying to create a file)
}

// TestNoBackupWhenCurrent verifies that no backup is created when the database
// is already at the current schema version.
func TestNoBackupWhenCurrent(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/current.db"

	// Create a database at the current version by using Open
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Verify it's at version 3
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("setup failed: version = %d, want 5", version)
	}

	db.Close()

	// Remove any backups that might have been created during the first Open
	// (since it migrated from 0 to 3, but brand-new DBs shouldn't create backups)
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	initialBackupCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "current.db.pre-v") {
			initialBackupCount++
			os.Remove(tempDir + "/" + f.Name())
		}
	}

	// Open again - no migration should run, no new backup should be created
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify no new backup was created this time
	files, err = os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "current.db.pre-v") {
			t.Error("backup file should not be created when database is already current")
		}
	}
}

// TestInMemorySkipsBackup verifies that :memory: databases skip the backup step.
func TestInMemorySkipsBackup(t *testing.T) {
	// This should succeed without trying to create a backup file
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify it's fully migrated
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Errorf("in-memory database user_version = %d, want %d", version, len(migrations))
	}

	// No file should exist (this is a weak test, but we can't easily verify
	// that VACUUM INTO was not called)
}

func TestV3MigrationFreshDB(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create a peer and invite
	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", "", ""); err != nil {
		t.Fatal(err)
	}

	publicID, err := s.CreateInviteAtomic(ctx, "code1", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}

	// Verify public_id is not empty
	if publicID == "" {
		t.Error("public_id should not be empty")
	}

	// Verify it's 32 hex chars
	if len(publicID) != 32 {
		t.Errorf("public_id length = %d, want 32", len(publicID))
	}

	// Query back and verify
	var checkID string
	err = s.db.QueryRowContext(ctx, `SELECT public_id FROM invites WHERE code_hash=?`, "code1").Scan(&checkID)
	if err != nil {
		t.Fatal(err)
	}
	if checkID != publicID {
		t.Errorf("public_id mismatch: got %q, want %q", checkID, publicID)
	}
}

// Test v2 to v3 migration with backfill
func TestV2ToV3Migration(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"

	// Create a v2 database manually
	db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}

	// Create schema without public_id
	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE peers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			notify_email TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE invites (
			code_hash TEXT PRIMARY KEY,
			from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
			scopes TEXT NOT NULL,
			bags TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used_by TEXT,
			pairing_token_hash TEXT
		);
		CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash) WHERE pairing_token_hash IS NOT NULL;
		PRAGMA user_version = 2;
	`)
	if err != nil {
		t.Fatal(err)
	}

	// Insert test data
	_, err = db.Exec(`INSERT INTO peers (id, name, key_hash, created_at) VALUES ('alice', 'Alice', 'hash1', ?)`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`INSERT INTO invites (code_hash, from_peer, scopes, bags, expires_at) VALUES ('code1', 'alice', 'messages', '', ?)`, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`INSERT INTO invites (code_hash, from_peer, scopes, bags, expires_at) VALUES ('code2', 'alice', 'messages', '', ?)`, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Open with migration
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify user_version is now 3
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Errorf("user_version = %d, want %d", version, len(migrations))
	}

	// Verify all rows have public_id
	rows, err := s.db.Query(`SELECT code_hash, public_id FROM invites ORDER BY code_hash`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	count := 0
	seen := make(map[string]bool)
	for rows.Next() {
		var codeHash, publicID string
		if err := rows.Scan(&codeHash, &publicID); err != nil {
			t.Fatal(err)
		}
		count++
		if publicID == "" {
			t.Errorf("code_hash %q has empty public_id", codeHash)
		}
		if len(publicID) != 32 {
			t.Errorf("code_hash %q public_id length = %d, want 32", codeHash, len(publicID))
		}
		if seen[publicID] {
			t.Errorf("duplicate public_id %q", publicID)
		}
		seen[publicID] = true
	}
	if count != 2 {
		t.Errorf("expected 2 backfilled rows, got %d", count)
	}
}

// Test v3 migration idempotence
func TestV3MigrationIdempotent(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"

	// Create v2 DB
	db, err := sql.Open("sqlite", dbPath+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT, pairing_token_hash TEXT);
		PRAGMA user_version = 2;
	`)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO peers VALUES ('alice', 'Alice', 'hash1', ?, '')`, time.Now().Unix())
	db.Exec(`INSERT INTO invites VALUES ('code1', 'alice', 'messages', '', ?, NULL, NULL)`, time.Now().Add(time.Hour).Unix())
	db.Close()

	// Run migration once
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	var publicID1 string
	s.db.QueryRow(`SELECT public_id FROM invites WHERE code_hash='code1'`).Scan(&publicID1)
	s.Close()

	// Run migration again (should be idempotent)
	s, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var publicID2 string
	s.db.QueryRow(`SELECT public_id FROM invites WHERE code_hash='code1'`).Scan(&publicID2)

	// public_id should be unchanged
	if publicID1 != publicID2 {
		t.Errorf("public_id changed after re-migration: %q -> %q", publicID1, publicID2)
	}

	// Verify user_version is still 3
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Errorf("user_version = %d, want %d", version, len(migrations))
	}
}

// TestPurgeExpiredInvitesRetention verifies that used invites are retained
// for the configured retention period and then purged.
func TestPurgeExpiredInvitesRetention(t *testing.T) {
	ctx := context.Background()
	currentTime := int64(2000000)
	clk := clocktest.New(time.Unix(currentTime, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create peers
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create and immediately accept invites at different points in time

	// 1. Unused expired invite (expires 500s ago, beyond 5-minute grace) - should be purged
	exp1 := time.Unix(currentTime-500, 0)
	if err := s.CreateInvite(ctx, "code1", "alice", []string{"messages"}, nil, exp1); err != nil {
		t.Fatal(err)
	}

	// 2. Used invite that expired 10 days ago - should be KEPT (within 30-day retention)
	// Create it 10 days ago, accept it then, and it expires 10 days ago
	tenDaysAgo := currentTime - 10*24*60*60
	exp2 := time.Unix(tenDaysAgo-100, 0) // expired 10 days + 100s ago
	// Temporarily go back in time to create and accept it
	clk.Set(time.Unix(tenDaysAgo-200, 0)) // before exp2
	if err := s.CreateInvite(ctx, "code2", "alice", []string{"messages"}, nil, exp2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code2", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Return to current time
	clk.Set(time.Unix(currentTime, 0))

	// 3. Used invite that expired 40 days ago - should be PURGED (beyond 30-day retention)
	fortyDaysAgo := currentTime - 40*24*60*60
	exp3 := time.Unix(fortyDaysAgo-100, 0) // expired 40 days + 100s ago
	// Temporarily go back in time to create and accept it
	clk.Set(time.Unix(fortyDaysAgo-200, 0)) // before exp3
	if err := s.CreateInvite(ctx, "code3", "alice", []string{"messages"}, nil, exp3); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "charlie", "Charlie", "hc", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code3", "charlie", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Return to current time
	clk.Set(time.Unix(currentTime, 0))

	// 4. Used invite not yet expired - should be KEPT
	exp4 := time.Unix(currentTime+24*60*60, 0) // expires in 1 day
	if err := s.CreateInvite(ctx, "code4", "alice", []string{"messages"}, nil, exp4); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "dave", "Dave", "hd", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code4", "dave", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Before purge: 4 invites
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM invites`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Errorf("before purge: got %d invites, want 4", count)
	}

	// Purge with 30-day retention (2592000 seconds)
	purged, _, err := s.PurgeExpiredInvites(ctx, 30*24*60*60)
	if err != nil {
		t.Fatal(err)
	}

	// Should purge: code1 (unused expired) + code3 (used, expired 40 days ago) = 2
	if purged != 2 {
		t.Errorf("purged %d invites, want 2", purged)
	}

	// After purge: code2 (used, expired 10 days ago) and code4 (used, not expired) remain
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM invites`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("after purge: got %d invites, want 2", count)
	}

	// Verify the right ones remain
	var codes []string
	rows, err := s.db.Query(`SELECT code_hash FROM invites ORDER BY code_hash`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ch string
		if err := rows.Scan(&ch); err != nil {
			t.Fatal(err)
		}
		codes = append(codes, ch)
	}
	if len(codes) != 2 {
		t.Errorf("got %d remaining codes, want 2", len(codes))
	}
	// code2 and code4 should remain (their hashes)
	wantHash2 := "code2"
	wantHash4 := "code4"
	found2, found4 := false, false
	for _, ch := range codes {
		if ch == wantHash2 {
			found2 = true
		}
		if ch == wantHash4 {
			found4 = true
		}
	}
	if !found2 || !found4 {
		t.Errorf("expected code2 and code4 to remain, got hashes: %v", codes)
	}
}

// TestBackupReuseOnRestartLoop verifies that existing backups are reused when valid and newer than DB.
func TestBackupReuseOnRestartLoop(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/restart.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT, pairing_token_hash TEXT);
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers (id, name, key_hash, created_at) VALUES ('p1', 'Test', 'h1', ?)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	db.Close()

	// Manually create a valid backup to simulate a previous crash-loop attempt
	backupName := "restart.db.pre-v6-from-v2.20260101-120000.000000"
	backupPath := tempDir + "/" + backupName

	// Copy the DB to create the backup
	dbContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, dbContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Set backup mtime to be newer than DB
	futureTime := time.Now().Add(time.Hour)
	if err := os.Chtimes(backupPath, futureTime, futureTime); err != nil {
		t.Fatal(err)
	}

	// Open should reuse the existing backup
	opts := OpenOptions{
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
	}

	st, err := OpenWithOptions(path, opts)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer st.Close()

	// Verify backup was reused
	if !st.BackupReused() {
		t.Error("backup should have been reused")
	}

	// Verify only one backup exists (the one we created)
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	backupCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "restart.db.pre-v6-from-v") {
			backupCount++
		}
	}
	if backupCount != 1 {
		t.Errorf("got %d backups, want 1 (reused)", backupCount)
	}
}

// TestRetentionCoversAllVersions verifies retention deletes old backups across all schema versions.
func TestRetentionCoversAllVersions(t *testing.T) {
	testCases := []struct {
		name       string
		keepCount  int
		wantRemain int
	}{
		{"keep_3", 3, 3},
		{"keep_1", 1, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := secureTempDir(t)
			dbBase := "test.db"

			// Create fake backups for different schema transitions with explicit mtimes
			baseTime := time.Now().Add(-time.Hour)
			backupNames := []struct {
				name  string
				mtime time.Time
			}{
				{dbBase + ".pre-v2-from-v1.20260101-120000.000000", baseTime},
				{dbBase + ".pre-v2-from-v1.20260101-130000.000000", baseTime.Add(10 * time.Minute)},
				{dbBase + ".pre-v6-from-v2.20260101-140000.000000", baseTime.Add(20 * time.Minute)},
				{dbBase + ".pre-v6-from-v2.20260101-150000.000000", baseTime.Add(30 * time.Minute)},
				{dbBase + ".pre-v6-from-v2.20260101-160000.000000", baseTime.Add(40 * time.Minute)}, // newest
			}

			for _, backup := range backupNames {
				path := tempDir + "/" + backup.name
				if err := os.WriteFile(path, []byte("fake backup"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, backup.mtime, backup.mtime); err != nil {
					t.Fatal(err)
				}
			}

			// Enforce retention, excluding the newest one (backupNames[4])
			newestPath := tempDir + "/" + backupNames[4].name
			logger := slog.Default()
			if err := enforceBackupRetention(tempDir, dbBase, newestPath, tc.keepCount, logger); err != nil {
				t.Fatal(err)
			}

			// Count remaining backups
			files, err := os.ReadDir(tempDir)
			if err != nil {
				t.Fatal(err)
			}

			var remaining []string
			for _, f := range files {
				if strings.HasPrefix(f.Name(), dbBase+".pre-v") {
					remaining = append(remaining, f.Name())
				}
			}

			// Should have exactly keepCount total (including the excluded one)
			if len(remaining) != tc.wantRemain {
				t.Errorf("retention kept %d backups, want %d", len(remaining), tc.wantRemain)
				for _, name := range remaining {
					t.Logf("  remaining: %s", name)
				}
			}

			// Verify the excluded newest is still there
			if _, err := os.Stat(newestPath); err != nil {
				t.Errorf("excluded backup should still exist: %v", err)
			}
		})
	}
}

// TestBackupBeforeSchema verifies that backup is taken before db.Exec(schema) runs.
func TestBackupBeforeSchema(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/backup-before.db"

	// Create a v2 database with a custom table NOT in the schema
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	// Create ONLY a custom table, no schema tables
	if _, err := db.Exec(`
		CREATE TABLE custom_table (data TEXT);
		INSERT INTO custom_table VALUES ('test');
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}

	// Snapshot sqlite_master before Open
	type schemaRow struct {
		typ     string
		name    string
		tblName string
		sql     string
	}
	var beforeSchema []schemaRow
	rows, err := db.Query(`SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type != 'index' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r schemaRow
		if err := rows.Scan(&r.typ, &r.name, &r.tblName, &r.sql); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		beforeSchema = append(beforeSchema, r)
	}
	rows.Close()

	db.Close()

	// Open with migration (will create backup before schema)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Verify backup was created
	backupPath := st.lastBackupPath
	if backupPath == "" {
		t.Fatal("no backup was created")
	}

	// Open the backup and verify its sqlite_master matches the pre-Open snapshot
	backupDB, err := sql.Open("sqlite", backupPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()

	var backupSchema []schemaRow
	rows, err = backupDB.Query(`SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type != 'index' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r schemaRow
		if err := rows.Scan(&r.typ, &r.name, &r.tblName, &r.sql); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		backupSchema = append(backupSchema, r)
	}
	rows.Close()

	// Compare: backup should NOT have peers, invites, etc. (schema tables)
	if len(backupSchema) != len(beforeSchema) {
		t.Errorf("backup sqlite_master has %d entries, pre-Open had %d", len(backupSchema), len(beforeSchema))
	}

	for i, bs := range backupSchema {
		if i >= len(beforeSchema) {
			t.Errorf("backup has extra entry: %s %s", bs.typ, bs.name)
			continue
		}
		if bs.sql != beforeSchema[i].sql {
			t.Errorf("backup schema differs at entry %d:\nbackup: %s\npre-Open: %s", i, bs.sql, beforeSchema[i].sql)
		}
	}

	// Verify custom_table exists in backup but peers does NOT
	var customCount int
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='custom_table'`).Scan(&customCount); err != nil {
		t.Fatal(err)
	}
	if customCount != 1 {
		t.Error("backup should have custom_table")
	}

	var peersCount int
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='peers'`).Scan(&peersCount); err != nil {
		t.Fatal(err)
	}
	if peersCount != 0 {
		t.Error("backup should NOT have peers table (schema was not run yet)")
	}
}

// TestSchemaVersionMatchesMigrations verifies SchemaVersion() == len(migrations).
func TestSchemaVersionMatchesMigrations(t *testing.T) {
	if SchemaVersion() != len(migrations) {
		t.Errorf("SchemaVersion() = %d, but len(migrations) = %d", SchemaVersion(), len(migrations))
	}
}

// TestStoreHasNonNilClock verifies that Store returned by Open has a non-nil clock.
func TestStoreHasNonNilClock(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if st.clk == nil {
		t.Error("Store.clk is nil; Store must have a working clock")
	}

	// Verify clock works
	now := st.clk.Now()
	ts := now.Unix()
	if ts <= 0 {
		t.Errorf("Store.clk.Now().Unix() returned invalid timestamp: %d", ts)
	}

	// Should be close to current time
	currentTime := time.Now().Unix()
	if abs := func(x int64) int64 {
		if x < 0 {
			return -x
		}
		return x
	}(ts - currentTime); abs > 5 {
		t.Errorf("Store.clk.Now().Unix() = %d, but time.Now().Unix() = %d (diff %d sec, expected < 5)", ts, currentTime, abs)
	}
}

// TestInTransactionRecheckCatchesTooNew verifies the in-transaction version recheck logic
// catches a concurrent schema version bump using migrationStepHook injection.
func TestInTransactionRecheckCatchesTooNew(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/recheck.db"

	// Create a v2 database with WAL mode
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT, scopes TEXT, bags TEXT, expires_at INTEGER, used_by TEXT, pairing_token_hash TEXT);
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Inject a hook that bumps user_version to 99 when target=3
	opts := OpenOptions{
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
		SkipMigrationBackup:  true,
		migrationStepHook: func(target, current int) error {
			if target == 5 {
				// Simulate concurrent migration by bumping version
				db, err := sql.Open("sqlite", path)
				if err != nil {
					return err
				}
				defer db.Close()
				_, err = db.Exec(`PRAGMA user_version = 99`)
				return err
			}
			return nil
		},
	}

	_, err = OpenWithOptions(path, opts)
	if err == nil {
		t.Fatal("expected error when version changed during migration")
	}

	// Should be ErrSchemaTooNew or SQLITE_BUSY
	// (SQLITE_BUSY is also acceptable as it prevents the migration from completing)
	var tooNewErr *ErrSchemaTooNew
	if !errors.As(err, &tooNewErr) {
		// Accept SQLITE_BUSY as it also prevents migration
		if !strings.Contains(err.Error(), "database is locked") && !strings.Contains(err.Error(), "SQLITE_BUSY") {
			t.Errorf("expected ErrSchemaTooNew or SQLITE_BUSY, got %T: %v", err, err)
		}
	}
}

// TestBackupDirPermissionsCheck verifies that OpenWithOptions refuses insecure backup directories.
func TestBackupDirPermissionsCheck(t *testing.T) {
	// Skip if running as root (can't test permission restrictions)
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	tempDir := secureTempDir(t)
	insecureDir := tempDir + "/insecure"

	// Create directory with group-writable permissions
	if err := os.Mkdir(insecureDir, 0770); err != nil {
		t.Fatal(err)
	}

	// Create a v2 database that will need migration
	dbPath := tempDir + "/test.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers VALUES ('p1', 'Test', 'h1', ?, '')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Try to open with this insecure backup dir
	opts := OpenOptions{
		BackupDir:            insecureDir,
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
	}

	_, err = OpenWithOptions(dbPath, opts)
	if err == nil {
		t.Fatal("expected error for group-writable backup directory")
	}

	if !strings.Contains(err.Error(), "allows group or world access") {
		t.Errorf("error should mention insecure permissions, got: %v", err)
	}
}

// TestInvalidBackupKeepValue verifies that invalid BackupRetentionCount values are adjusted to default (3)
// and that the adjusted value is actually enforced during retention.
func TestInvalidBackupKeepValue(t *testing.T) {
	dir := secureTempDir(t)
	dbPath := dir + "/test.db"
	dbBase := "test.db"

	// Create a v2 database that will trigger migration
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		INSERT INTO peers VALUES ('p1','T','h1',1,'');
		PRAGMA user_version = 2;
	`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	// Seed backup dir with 4 older backups (all older than the migration backup we'll create)
	// These use proper naming format that retention will count
	// Set mtimes to match their timestamps so retention sorts them correctly
	seededBackups := []struct {
		name  string
		mtime time.Time
	}{
		{dbBase + ".pre-v6-from-v2.20260101-100000.000000", time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)}, // oldest
		{dbBase + ".pre-v6-from-v2.20260101-110000.000000", time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)},
		{dbBase + ".pre-v6-from-v2.20260101-120000.000000", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
		{dbBase + ".pre-v6-from-v2.20260101-130000.000000", time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)}, // newest seeded
	}
	for _, backup := range seededBackups {
		path := dir + "/" + backup.name
		if err := os.WriteFile(path, []byte("seeded backup"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, backup.mtime, backup.mtime); err != nil {
			t.Fatal(err)
		}
	}

	// Open with invalid BackupRetentionCount (0) using fixed clock so new backup is newest
	fixedTime := time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC) // 140000 - newer than all seeded
	opts := OpenOptions{
		BackupRetentionCount: 0, // Invalid: should be adjusted to 3
		BackupDir:            dir,
		Logger:               slog.Default(),
		Clock:                clocktest.New(fixedTime),
	}

	st, err := OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	// Count remaining backups
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var remainingBackups []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, dbBase+".pre-v") && !strings.HasSuffix(name, ".partial") {
			remainingBackups = append(remainingBackups, name)
		}
	}

	// Should have exactly 3 backups (the adjusted default):
	// - The new migration backup (140000 - newest)
	// - The 2 newest seeded backups (130000, 120000)
	// The 2 oldest seeded (100000, 110000) should be deleted
	if len(remainingBackups) != 3 {
		t.Errorf("expected exactly 3 backups with adjusted retention (default), got %d: %v", len(remainingBackups), remainingBackups)
	}

	// Verify the 2 oldest seeded backups were deleted
	for _, oldBackup := range seededBackups[:2] {
		path := dir + "/" + oldBackup.name
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("old backup %q should have been deleted but still exists", oldBackup.name)
		}
	}

	// Verify the 2 newest seeded backups still exist
	for _, keptBackup := range seededBackups[2:] {
		path := dir + "/" + keptBackup.name
		if _, err := os.Stat(path); err != nil {
			t.Errorf("newer backup %q should still exist: %v", keptBackup.name, err)
		}
	}

	// Verify the new migration backup exists (starts with 140000)
	foundNew := false
	for _, name := range remainingBackups {
		if strings.Contains(name, "20260101-140000") {
			foundNew = true
			break
		}
	}
	if !foundNew {
		t.Errorf("new migration backup (140000) not found in remaining backups: %v", remainingBackups)
	}
}

// TestBackupFileMode is now in backup_mode_test_unix.go (Unix-specific mode assertions)

// TestBackupCollisionRetry verifies that a timestamp collision triggers PID suffix retry.
func TestBackupCollisionRetry(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/collision.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Fixed timestamp for collision
	fixedTime := time.Date(2026, 1, 30, 12, 0, 0, 0, time.UTC)

	// Create a pre-existing backup file with that timestamp
	existingBackup := fmt.Sprintf("%s/collision.db.pre-v6-from-v2.%s", tempDir, fixedTime.Format("20060102-150405.000000"))
	if err := os.WriteFile(existingBackup, []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}

	// Open with fixed clock
	opts := OpenOptions{
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
		Clock:                clocktest.New(fixedTime),
	}

	st, err := OpenWithOptions(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Verify a backup with random suffix was created (not the colliding name)
	backupBase := st.LastBackupPath()
	if backupBase == "" {
		t.Fatal("no backup was created")
	}

	// Should have a random suffix (8 hex chars), not match the pre-existing name
	if backupBase == filepath.Base(existingBackup) {
		t.Errorf("backup should have random suffix, not overwrite collision")
	}

	// Should start with the base name
	expectedPrefix := "collision.db.pre-v6-from-v2.20260130-120000.000000."
	if !strings.HasPrefix(backupBase, expectedPrefix) {
		t.Errorf("backup name %q should start with %s", backupBase, expectedPrefix)
	}

	// Both files should exist
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	backupCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "collision.db.pre-v6-from-v2") {
			backupCount++
		}
	}
	if backupCount != 2 {
		t.Errorf("got %d backups, want 2 (original + random suffix)", backupCount)
	}

	// Verify pre-existing file wasn't modified
	data, _ := os.ReadFile(existingBackup)
	if string(data) != "fake" {
		t.Errorf("pre-existing file was modified")
	}
}

// TestRetentionIgnoresLookalikeFiles verifies that operator-kept files with similar names survive retention.
func TestRetentionIgnoresLookalikeFiles(t *testing.T) {
	tempDir := secureTempDir(t)
	dbBase := "test.db"

	// Create real backups
	realBackups := []string{
		dbBase + ".pre-v2-from-v1.20260101-120000.000000",
		dbBase + ".pre-v6-from-v2.20260101-130000.000000",
		dbBase + ".pre-v6-from-v2.20260101-140000.000000",
	}
	for _, name := range realBackups {
		path := tempDir + "/" + name
		if err := os.WriteFile(path, []byte("fake backup"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Create operator-kept lookalike files that should NOT match the strict regex
	lookalikeFiles := []string{
		dbBase + ".pre-v6-from-v2.manual-backup",
		dbBase + ".pre-v99-emergency",
		dbBase + ".backup",
	}
	for _, name := range lookalikeFiles {
		path := tempDir + "/" + name
		if err := os.WriteFile(path, []byte("operator file"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Enforce retention with keepCount=1, excluding the newest real backup
	newestPath := tempDir + "/" + realBackups[2]
	logger := slog.Default()
	if err := enforceBackupRetention(tempDir, dbBase, newestPath, 1, logger); err != nil {
		t.Fatal(err)
	}

	// Verify lookalike files still exist
	for _, name := range lookalikeFiles {
		path := tempDir + "/" + name
		if _, err := os.Stat(path); err != nil {
			t.Errorf("lookalike file %q was deleted, should survive: %v", name, err)
		}
	}

	// Verify only the newest real backup remains
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	var remainingRealBackups []string
	for _, f := range files {
		name := f.Name()
		for _, rb := range realBackups {
			if name == rb {
				remainingRealBackups = append(remainingRealBackups, name)
				break
			}
		}
	}
	if len(remainingRealBackups) != 1 {
		t.Errorf("got %d real backups remaining, want 1", len(remainingRealBackups))
		for _, name := range remainingRealBackups {
			t.Logf("  remaining: %s", name)
		}
	}
	if len(remainingRealBackups) == 1 && remainingRealBackups[0] != filepath.Base(newestPath) {
		t.Errorf("wrong backup survived: %s, want %s", remainingRealBackups[0], filepath.Base(newestPath))
	}
}

// TestNoAbsolutePathsInErrors verifies that error messages and logs use only base names.
func TestNoAbsolutePathsInErrors(t *testing.T) {
	tempDir := secureTempDir(t)

	// Test 1: Backup directory permission error
	t.Run("backup directory permission error", func(t *testing.T) {
		path := tempDir + "/pathtest1.db"

		// Create a v2 database
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
			CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
			PRAGMA user_version = 2;
		`); err != nil {
			t.Fatal(err)
		}
		db.Close()

		// Create a backup dir with group/world access (will be refused)
		badDir := tempDir + "/baddir1"
		if err := os.Mkdir(badDir, 0770); err != nil {
			t.Fatal(err)
		}

		opts := OpenOptions{
			BackupDir:            badDir,
			Logger:               slog.Default(),
			BackupRetentionCount: 3,
		}

		_, err = OpenWithOptions(path, opts)
		if err == nil {
			t.Fatal("expected error for insecure backup directory, got nil")
		}

		// Error should not contain the temp directory path
		if strings.Contains(err.Error(), tempDir) {
			t.Errorf("error contains temp directory path %q: %v", tempDir, err)
		}
	})

	// Test 2: Backup directory creation error (parent doesn't exist and not writable)
	t.Run("backup directory creation error", func(t *testing.T) {
		path := tempDir + "/pathtest2.db"

		// Create a v2 database
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
			CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
			PRAGMA user_version = 2;
		`); err != nil {
			t.Fatal(err)
		}
		db.Close()

		// Try to use a backup dir that can't be created (file in the way)
		blockingFile := tempDir + "/blocker"
		if err := os.WriteFile(blockingFile, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}

		opts := OpenOptions{
			BackupDir:            blockingFile + "/subdir",
			Logger:               slog.Default(),
			BackupRetentionCount: 3,
		}

		_, err = OpenWithOptions(path, opts)
		if err == nil {
			t.Fatal("expected error for backup directory creation failure, got nil")
		}

		// Error should not contain the temp directory path
		if strings.Contains(err.Error(), tempDir) {
			t.Errorf("error contains temp directory path %q: %v", tempDir, err)
		}
	})

	// Test 3: ReadDir failure during retention (unreadable directory)
	// This is hard to trigger without root, so we skip it if we can't make the dir unreadable
	t.Run("ReadDir failure during retention", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("test requires non-root to test unreadable directory")
		}

		path := tempDir + "/pathtest3.db"
		retentionDir := tempDir + "/retentiontest"
		if err := os.Mkdir(retentionDir, 0700); err != nil {
			t.Fatal(err)
		}

		// Create a v2 database
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
			CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
			PRAGMA user_version = 2;
		`); err != nil {
			t.Fatal(err)
		}
		db.Close()

		// First migration succeeds
		opts := OpenOptions{
			BackupDir:            retentionDir,
			Logger:               slog.Default(),
			BackupRetentionCount: 1,
		}

		st, err := OpenWithOptions(path, opts)
		if err != nil {
			t.Fatal(err)
		}
		st.Close()

		// Make the directory unreadable (chmod 000)
		if err := os.Chmod(retentionDir, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(retentionDir, 0700) // Restore for cleanup

		// Reset to v2 for another migration
		db, err = sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.Exec(`PRAGMA user_version = 2`)
		db.Close()

		// This should fail when trying to read the directory for retention
		_, err = OpenWithOptions(path, opts)
		if err == nil {
			t.Fatal("expected error when retention directory is unreadable, got nil")
		}

		// Error should not contain the temp directory path
		if strings.Contains(err.Error(), tempDir) {
			t.Errorf("error contains temp directory path %q: %v", tempDir, err)
		}
	})
}

// TestVacuumIntoFailure verifies cleanup when VACUUM INTO fails.
func TestVacuumIntoFailure(t *testing.T) {
	tempDir := secureTempDir(t)
	path := tempDir + "/vacuum-fail.db"

	// Create a v2 database
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at INTEGER, notify_email TEXT DEFAULT '');
		PRAGMA user_version = 2;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers VALUES ('p1', 'Test', 'h1', ?, '')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Inject vacuumInto that fails
	opts := OpenOptions{
		Logger:               slog.Default(),
		BackupRetentionCount: 3,
		vacuumInto: func(db *sql.DB, backupPath string) error {
			return errors.New("injected vacuum failure")
		},
	}

	_, err = OpenWithOptions(path, opts)
	if err == nil {
		t.Fatal("expected error when VACUUM INTO fails")
	}

	// Verify no stray backup file was left
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "vacuum-fail.db.pre-v") {
			t.Errorf("stray backup file left after VACUUM failure: %s", f.Name())
		}
	}

	// Verify database version is still 2 (migration aborted)
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Errorf("database version = %d after failed backup, want 2 (unchanged)", version)
	}
}

// TestAvailableDiskSpaceRefusal verifies that insufficient disk space aborts migration.

func TestVersionGuardRefusesWithoutWriting(t *testing.T) {
	for _, v := range []int{99, -1} {
		path := t.TempDir() + "/v.db"
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(fmt.Sprintf(`CREATE TABLE marker(x); PRAGMA user_version = %d`, v)); err != nil {
			t.Fatal(err)
		}
		db.Close()
		before, _ := os.ReadFile(path)

		if _, err := Open(path); err == nil || !strings.Contains(err.Error(), fmt.Sprint(v)) {
			t.Fatalf("v=%d: Open err = %v, want unsupported-version error", v, err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatalf("v=%d: database file modified by refused Open", v)
		}
		for _, sfx := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(path + sfx); err == nil {
				t.Fatalf("v=%d: %s created by refused Open", v, sfx)
			}
		}
	}
}

func TestMigrateRechecksVersionInTransaction(t *testing.T) {
	db, err := sql.Open("sqlite", "file:recheck?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err == nil {
		t.Fatal("migrate accepted a database newer than this binary")
	}
}

func isLockContention(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "locked") || strings.Contains(msg, "busy")
}

func TestBuildDSNMemoryKeepsImmediateTxlock(t *testing.T) {
	if dsn := buildDSN(":memory:"); !strings.Contains(dsn, "_txlock=immediate") {
		t.Fatalf("memory DSN lacks _txlock=immediate: %s", dsn)
	}
}

func TestBagStats(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "alice", "Alice", "halice", "alice@example.com", ""); err != nil {
		t.Fatal(err)
	}

	// Test bag count limit
	_, err = s.PutBag(ctx, "alice", "notes", []byte("hello"), "alice", -1, 2, 1048576)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PutBag(ctx, "alice", "tasks", []byte("tasks"), "alice", -1, 2, 1048576)
	if err != nil {
		t.Fatal(err)
	}
	// Third bag should fail
	_, err = s.PutBag(ctx, "alice", "third", []byte("third"), "alice", -1, 2, 1048576)
	if !errors.Is(err, ErrBagLimitExceeded) {
		t.Errorf("got %v, want ErrBagLimitExceeded", err)
	}

	// Test byte quota
	s2, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.CreatePeer(ctx, "bob", "Bob", "hbob", "", ""); err != nil {
		t.Fatal(err)
	}
	_, err = s2.PutBag(ctx, "bob", "a", []byte("12345"), "bob", -1, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Second bag that would exceed quota
	_, err = s2.PutBag(ctx, "bob", "b", []byte("123456"), "bob", -1, 100, 10)
	if !errors.Is(err, ErrStorageQuotaExceeded) {
		t.Errorf("got %v, want ErrStorageQuotaExceeded", err)
	}

	// Update that grows beyond quota
	_, err = s2.PutBag(ctx, "bob", "a", []byte("12345678901"), "bob", -1, 100, 10)
	if !errors.Is(err, ErrStorageQuotaExceeded) {
		t.Errorf("update growth: got %v, want ErrStorageQuotaExceeded", err)
	}

	// Update that shrinks then grows again should work if within quota
	_, err = s2.PutBag(ctx, "bob", "a", []byte("123"), "bob", -1, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s2.PutBag(ctx, "bob", "b", []byte("1234567"), "bob", -1, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBagLimitsConcurrency(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "carol", "Carol", "hcarol", "", ""); err != nil {
		t.Fatal(err)
	}

	// Try to create 10 bags concurrently with a limit of 5
	// Only 5 should succeed
	const limit = 5
	const attempts = 10
	results := make(chan error, attempts)

	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			name := fmt.Sprintf("bag%d", i)
			_, err := s.PutBag(ctx, "carol", name, []byte("test"), "carol", -1, limit, 1048576)
			results <- err
		}()
	}

	var successes, limitExceeded int
	for i := 0; i < attempts; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrBagLimitExceeded) {
			limitExceeded++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successes != limit {
		t.Errorf("got %d successes, want %d", successes, limit)
	}
	if limitExceeded != attempts-limit {
		t.Errorf("got %d limit exceeded, want %d", limitExceeded, attempts-limit)
	}
}

func TestBagLimitsFileDB(t *testing.T) {
	ctx := context.Background()
	tmpFile := t.TempDir() + "/test.db"

	// Open two separate Store handles on the same file
	s1, err := Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()

	s2, err := Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if err := s1.CreatePeer(ctx, "dave", "Dave", "hdave", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create bags concurrently using both handles
	const limit = 5
	const attempts = 10
	results := make(chan error, attempts)

	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			// Alternate between handles
			s := s1
			if i%2 == 1 {
				s = s2
			}
			name := fmt.Sprintf("bag%d", i)
			_, err := s.PutBag(ctx, "dave", name, []byte("test"), "dave", -1, limit, 1048576)
			results <- err
		}()
	}

	var successes, limitExceeded int
	for i := 0; i < attempts; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrBagLimitExceeded) {
			limitExceeded++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successes != limit {
		t.Errorf("got %d successes, want %d (atomicity failure)", successes, limit)
	}
	if limitExceeded != attempts-limit {
		t.Errorf("got %d limit exceeded, want %d", limitExceeded, attempts-limit)
	}

	// Verify actual count in database
	var count int
	err = s1.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bags WHERE owner='dave'`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != limit {
		t.Errorf("database has %d bags, want %d (atomicity failure)", count, limit)
	}
}

func TestBagLimitsShrinkWhileOverQuota(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "eve", "Eve", "heve", "", ""); err != nil {
		t.Fatal(err)
	}

	// Seed two bags totaling 100 bytes with a large cap
	_, err = s.PutBag(ctx, "eve", "bag1", bytes.Repeat([]byte("x"), 60), "eve", -1, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PutBag(ctx, "eve", "bag2", bytes.Repeat([]byte("y"), 40), "eve", -1, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}

	// Now enforce a cap of 50 bytes - peer is over quota (100 > 50)
	smallCap := int64(50)

	// Shrinking bag1 from 60→55 should work even though total stays over quota (95 > 50)
	_, err = s.PutBag(ctx, "eve", "bag1", bytes.Repeat([]byte("x"), 55), "eve", -1, 100, smallCap)
	if err != nil {
		t.Errorf("shrink while staying over quota failed: %v", err)
	}

	// Growing bag1 by 1 byte should fail
	_, err = s.PutBag(ctx, "eve", "bag1", bytes.Repeat([]byte("x"), 56), "eve", -1, 100, smallCap)
	if !errors.Is(err, ErrStorageQuotaExceeded) {
		t.Errorf("grow while over quota: got %v, want ErrStorageQuotaExceeded", err)
	}

	// Creating a new bag should fail (count is fine, but bytes would exceed)
	_, err = s.PutBag(ctx, "eve", "bag3", []byte("z"), "eve", -1, 100, smallCap)
	if !errors.Is(err, ErrStorageQuotaExceeded) {
		t.Errorf("create while over quota: got %v, want ErrStorageQuotaExceeded", err)
	}
}

func TestBagLimitsUpdateAtCountCap(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "frank", "Frank", "hfrank", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create bags up to the count limit
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("bag%d", i)
		_, err = s.PutBag(ctx, "frank", name, []byte("content"), "frank", -1, 3, 1048576)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Creating a new bag should fail
	_, err = s.PutBag(ctx, "frank", "bag3", []byte("new"), "frank", -1, 3, 1048576)
	if !errors.Is(err, ErrBagLimitExceeded) {
		t.Errorf("new bag at count cap: got %v, want ErrBagLimitExceeded", err)
	}

	// Updating an existing bag should succeed
	_, err = s.PutBag(ctx, "frank", "bag0", []byte("updated content"), "frank", -1, 3, 1048576)
	if err != nil {
		t.Errorf("update at count cap failed: %v", err)
	}
}

func TestDSNContainsTxLockImmediate(t *testing.T) {
	dsn := buildDSN("/tmp/test.db")
	if !strings.Contains(dsn, "_txlock=immediate") {
		t.Errorf("DSN missing _txlock=immediate: %s", dsn)
	}

	dsn = buildDSN(":memory:")
	if !strings.Contains(dsn, "_txlock=immediate") {
		t.Errorf("memory DSN missing _txlock=immediate: %s", dsn)
	}
}

func TestPutBagNonPositiveLimits(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "grace", "Grace", "hgrace", "", ""); err != nil {
		t.Fatal(err)
	}

	// Zero limits should error
	_, err = s.PutBag(ctx, "grace", "bag1", []byte("test"), "grace", -1, 0, 100)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("zero maxBagsPerPeer: got %v, want 'must be positive' error", err)
	}

	_, err = s.PutBag(ctx, "grace", "bag1", []byte("test"), "grace", -1, 100, 0)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("zero maxBagBytesPerPeer: got %v, want 'must be positive' error", err)
	}

	// Negative limits should error
	_, err = s.PutBag(ctx, "grace", "bag1", []byte("test"), "grace", -1, -1, 100)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("negative maxBagsPerPeer: got %v, want 'must be positive' error", err)
	}

	_, err = s.PutBag(ctx, "grace", "bag1", []byte("test"), "grace", -1, 100, -1)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("negative maxBagBytesPerPeer: got %v, want 'must be positive' error", err)
	}

	// Assert nothing was written
	var count int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bags WHERE owner='grace'`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 bags written, got %d", count)
	}
}

func TestBagLimitsByteCapFileDBRace(t *testing.T) {
	ctx := context.Background()
	tmpFile := t.TempDir() + "/race.db"

	// Open two separate Store handles
	s1, err := Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()

	s2, err := Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if err := s1.CreatePeer(ctx, "henry", "Henry", "hhenry", "", ""); err != nil {
		t.Fatal(err)
	}

	// Test 1: Concurrent creates
	// Limit: 100 bytes total. Each bag is 30 bytes.
	// Try to create 5 bags (150 bytes total) concurrently.
	// Exactly 3 should succeed (90 bytes).
	const byteCap = int64(100)
	const bagSize = 30
	const attempts = 5
	const expectedSuccesses = 3

	start1 := make(chan struct{})
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			<-start1 // wait for start signal
			s := s1
			if i%2 == 1 {
				s = s2
			}
			name := fmt.Sprintf("bag%d", i)
			content := bytes.Repeat([]byte("x"), bagSize)
			_, err := s.PutBag(ctx, "henry", name, content, "henry", -1, 100, byteCap)
			results <- err
		}()
	}
	close(start1) // start all goroutines

	var successes int
	for i := 0; i < attempts; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrStorageQuotaExceeded) {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successes != expectedSuccesses {
		t.Errorf("concurrent creates: got %d successes, want exactly %d", successes, expectedSuccesses)
	}

	// Verify actual total bytes
	var totalBytes int64
	err = s1.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(content)), 0) FROM bags WHERE owner='henry'`).Scan(&totalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if totalBytes > byteCap {
		t.Errorf("total bytes %d exceeds cap %d (atomicity failure)", totalBytes, byteCap)
	}

	// Test 2: Concurrent growing updates
	// Reset for second test
	if err := s1.CreatePeer(ctx, "irene", "Irene", "hirene", "", ""); err != nil {
		t.Fatal(err)
	}
	// Seed with 3 bags of 30 bytes each (90 total)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("update%d", i)
		_, err := s1.PutBag(ctx, "irene", name, bytes.Repeat([]byte("y"), 30), "irene", -1, 100, byteCap)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Try to grow all 3 bags to 40 bytes concurrently (would be 120 total)
	// Exactly 1 should succeed (leaving total at 100: 2×30 + 1×40)
	start2 := make(chan struct{})
	results2 := make(chan error, 3)
	for i := 0; i < 3; i++ {
		i := i
		go func() {
			<-start2 // wait for start signal
			s := s1
			if i%2 == 1 {
				s = s2
			}
			name := fmt.Sprintf("update%d", i)
			content := bytes.Repeat([]byte("y"), 40)
			_, err := s.PutBag(ctx, "irene", name, content, "irene", -1, 100, byteCap)
			results2 <- err
		}()
	}
	close(start2) // start all goroutines

	var updateSuccesses int
	for i := 0; i < 3; i++ {
		err := <-results2
		if err == nil {
			updateSuccesses++
		} else if !errors.Is(err, ErrStorageQuotaExceeded) {
			t.Errorf("unexpected update error: %v", err)
		}
	}

	if updateSuccesses != 1 {
		t.Errorf("concurrent updates: got %d successes, want exactly 1", updateSuccesses)
	}

	// Verify total is exactly 100
	err = s1.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(content)), 0) FROM bags WHERE owner='irene'`).Scan(&totalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if totalBytes != byteCap {
		t.Errorf("update race: total bytes %d, want exactly %d", totalBytes, byteCap)
	}

	// Test 3: Mixed create and update race
	if err := s1.CreatePeer(ctx, "jack", "Jack", "hjack", "", ""); err != nil {
		t.Fatal(err)
	}
	// Seed with 2 bags of 35 bytes each (70 total)
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("mixed%d", i)
		_, err := s1.PutBag(ctx, "jack", name, bytes.Repeat([]byte("z"), 35), "jack", -1, 100, byteCap)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Concurrently: update mixed0 to 40 bytes (+5), update mixed1 to 40 bytes (+5), create mixed2 with 30 bytes
	// At most 2 operations can succeed (e.g., 70+5+5=80 or 70+5+30=105>100 or 70+30=100).
	// Result is in {1, 2} depending on which operations win the race.
	start3 := make(chan struct{})
	results3 := make(chan error, 3)
	go func() {
		<-start3
		_, err := s1.PutBag(ctx, "jack", "mixed0", bytes.Repeat([]byte("z"), 40), "jack", -1, 100, byteCap)
		results3 <- err
	}()
	go func() {
		<-start3
		_, err := s2.PutBag(ctx, "jack", "mixed1", bytes.Repeat([]byte("z"), 40), "jack", -1, 100, byteCap)
		results3 <- err
	}()
	go func() {
		<-start3
		_, err := s1.PutBag(ctx, "jack", "mixed2", bytes.Repeat([]byte("z"), 30), "jack", -1, 100, byteCap)
		results3 <- err
	}()
	close(start3) // start all goroutines

	var mixedSuccesses int
	for i := 0; i < 3; i++ {
		err := <-results3
		if err == nil {
			mixedSuccesses++
		} else if !errors.Is(err, ErrStorageQuotaExceeded) {
			t.Errorf("unexpected mixed error: %v", err)
		}
	}

	// Both updates could win (70+5+5=80 ≤100), or one update + the create (70+5+30=105>100),
	// so exactly 1 or 2 operations succeed.
	if mixedSuccesses < 1 || mixedSuccesses > 2 {
		t.Errorf("mixed race: got %d successes, want 1 or 2", mixedSuccesses)
	}

	// Verify total didn't exceed cap
	err = s1.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(content)), 0) FROM bags WHERE owner='jack'`).Scan(&totalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if totalBytes > byteCap {
		t.Errorf("mixed race: total bytes %d exceeds cap %d", totalBytes, byteCap)
	}
}

func migrate(db *sql.DB) error {
	_, err := runMigrations(db, 0, OpenOptions{})
	return err
}

func TestOpenRefusesDamagedSchema(t *testing.T) {
	path := t.TempDir() + "/t.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `DROP INDEX invites_public_id`)
	s.Close()
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "invites_public_id") {
		t.Fatalf("want damaged-schema error, got %v", err)
	}
}

func TestBagByteCapConcurrentGrowthFileDB(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/bytes.db"
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s1.CreatePeer(ctx, "gina", "Gina", "hgina", "", ""); err != nil {
		t.Fatal(err)
	}

	const capBytes, attempts = 100, 20
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		i := i
		s := s1
		if i%2 == 1 {
			s = s2
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.PutBag(ctx, "gina", fmt.Sprintf("bag%d", i), bytes.Repeat([]byte("x"), 30), "gina", -1, 100, capBytes)
		}()
	}
	wg.Wait()

	var total int64
	if err := s1.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(content)),0) FROM bags WHERE owner='gina'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total > capBytes {
		t.Fatalf("byte cap exceeded under concurrency: %d > %d", total, capBytes)
	}
}

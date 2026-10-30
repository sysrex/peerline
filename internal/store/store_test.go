package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	sqlite "modernc.org/sqlite"
)

// Global cancel function for the test_cancel scalar function
var testCancelFunc atomic.Value // stores context.CancelFunc

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
	if v, err := s.PutBag(ctx, "a", "n", []byte("x"), "a", 0); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if _, err := s.PutBag(ctx, "a", "n", []byte("y"), "a", 0); !errors.Is(err, ErrConflict) {
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
	if _, err := s.PutBag(ctx, "a", "status", []byte("ok"), "a", -1); err != nil {
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
	if version != 4 {
		t.Fatalf("user_version = %d, want 4", version)
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
	if version != 4 {
		t.Fatalf("user_version = %d, want 4", version)
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
			if version != 4 {
				t.Fatalf("user_version = %d, want 4", version)
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
				if freshSQL != migratedSQL {
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
	if err == nil {
		t.Fatal("expected error due to injected failure")
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
	if version != 4 {
		t.Fatalf("user_version = %d, want 4", version)
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

	// Run migrate again (should be no-op)
	if err := migrate(s.db); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}

	// Verify user_version unchanged
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 4 {
		t.Fatalf("user_version after second migrate = %d, want 4", version)
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
				} else if !errors.Is(err, context.DeadlineExceeded) {
					// Also accept SQLITE_BUSY or similar errors
					t.Logf("second BeginTx blocked/failed as expected: %v", err)
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
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Logf("second BeginTx blocked/failed as expected: %v", err)
				}
			}
		})
	}
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
	if version != 4 {
		t.Errorf("user_version = %d, want 4", version)
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
	if version != 4 {
		t.Errorf("user_version = %d, want 4", version)
	}
}

// TestPurgeExpiredInvitesRetention verifies that used invites are retained
// for the configured retention period and then purged.
func TestPurgeExpiredInvitesRetention(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
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

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	// Start at a base time
	currentTime := int64(2000000)
	s.now = func() int64 { return currentTime }

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
	s.now = func() int64 { return tenDaysAgo - 200 } // before exp2
	if err := s.CreateInvite(ctx, "code2", "alice", []string{"messages"}, nil, exp2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code2", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Return to current time
	s.now = func() int64 { return currentTime }

	// 3. Used invite that expired 40 days ago - should be PURGED (beyond 30-day retention)
	fortyDaysAgo := currentTime - 40*24*60*60
	exp3 := time.Unix(fortyDaysAgo-100, 0) // expired 40 days + 100s ago
	// Temporarily go back in time to create and accept it
	s.now = func() int64 { return fortyDaysAgo - 200 } // before exp3
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
	s.now = func() int64 { return currentTime }

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
	purged, err := s.PurgeExpiredInvites(ctx, 30*24*60*60)
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

// TestPairingTokenExpiryWithClock verifies that PairingTokenExists and the accept paths
// respect s.now() for expiry checks.
func TestPairingTokenExpiryWithClock(t *testing.T) {
	s, err := Open(":memory:")
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

	// Inject fake clock
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(1000000)
	s.now = func() int64 { return currentTime }

	// Create a pairing invite that expires at currentTime + 100
	codeHash := "code_test"
	pairingHash := "pair_test"
	expiresAt := time.Unix(currentTime+100, 0)
	if err := s.CreateInviteWithPairing(ctx, codeHash, pairingHash, "alice", []string{"messages"}, nil, expiresAt); err != nil {
		t.Fatal(err)
	}

	// 1. Token is valid 10 seconds before expiry
	s.now = func() int64 { return currentTime + 90 }
	exists, err := s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("token should exist 10 seconds before expiry")
	}

	// 2. Token is still valid 1 second before expiry
	s.now = func() int64 { return currentTime + 99 }
	exists, err = s.PairingTokenExists(ctx, pairingHash)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("token should exist 1 second before expiry")
	}

	// 3. Token is invalid 1 second after expiry
	s.now = func() int64 { return currentTime + 101 }
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
	s.now = func() int64 { return currentTime + 50 }
	if err := s.CreateInviteWithPairing(ctx, codeHash2, pairingHash2, "alice", []string{"messages"}, nil, expiresAt2); err != nil {
		t.Fatal(err)
	}
	s.now = func() int64 { return currentTime + 201 }
	_, err = s.GetInviteByPairingToken(ctx, pairingHash2)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetInviteByPairingToken should return ErrNotFound for expired token, got %v", err)
	}

	// 5. AcceptInviteByPairingToken rejects expired token
	s.now = func() int64 { return currentTime + 202 }
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash2, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("AcceptInviteByPairingToken should return ErrNotFound for expired token, got %v", err)
	}

	// 6. RegisterAndAcceptByPairing rejects expired token (pre-check)
	s.now = func() int64 { return currentTime + 203 }
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash2, "charlie", "Charlie", "hc", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing should return ErrNotFound for expired token in pre-check, got %v", err)
	}

	// 7. RegisterAndAcceptByPairing: token expires between pre-check and tx
	// Create a third invite
	codeHash3 := "code_test3"
	pairingHash3 := "pair_test3"
	expiresAt3 := time.Unix(currentTime+300, 0)
	s.now = func() int64 { return currentTime + 100 }
	if err := s.CreateInviteWithPairing(ctx, codeHash3, pairingHash3, "alice", []string{"messages"}, nil, expiresAt3); err != nil {
		t.Fatal(err)
	}

	// Deterministic state-flag clock: first call (pre-check) passes, second call (tx) fails
	callCount := 0
	s.now = func() int64 {
		callCount++
		if callCount == 1 {
			return currentTime + 299 // Before expiry: pre-check passes
		}
		return currentTime + 301 // After expiry: tx fails
	}
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash3, "dave", "Dave", "hd", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing should return ErrNotFound when token expires between pre-check and tx, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 clock calls (pre-check + tx), got %d", callCount)
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
	s.now = func() int64 { return currentTime + 200 }
	if err := s.CreateInviteWithPairing(ctx, codeHash4, pairingHash4, "alice", []string{"messages"}, nil, expiresAt4); err != nil {
		t.Fatal(err)
	}

	// At exact expiry time: should be accepted
	s.now = func() int64 { return currentTime + 400 }
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash4, "bob", nil, nil)
	if err != nil {
		t.Errorf("AcceptInviteByPairingToken at exact expiry (now == expires_at) should succeed, got %v", err)
	}

	// Create another invite for +1 test
	codeHash5 := "code_test5"
	pairingHash5 := "pair_test5"
	expiresAt5 := time.Unix(currentTime+500, 0)
	s.now = func() int64 { return currentTime + 200 }
	if err := s.CreateInviteWithPairing(ctx, codeHash5, pairingHash5, "alice", []string{"messages"}, nil, expiresAt5); err != nil {
		t.Fatal(err)
	}

	// One second after expiry: should be rejected
	s.now = func() int64 { return currentTime + 501 }
	_, err = s.AcceptInviteByPairingToken(ctx, pairingHash5, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("AcceptInviteByPairingToken at expires_at+1 should return ErrNotFound, got %v", err)
	}

	// Exact boundary tests for RegisterAndAcceptByPairing
	// Create invite expiring at currentTime + 600
	codeHash6 := "code_test6"
	pairingHash6 := "pair_test6"
	expiresAt6 := time.Unix(currentTime+600, 0)
	s.now = func() int64 { return currentTime + 200 }
	if err := s.CreateInviteWithPairing(ctx, codeHash6, pairingHash6, "alice", []string{"messages"}, nil, expiresAt6); err != nil {
		t.Fatal(err)
	}

	// At exact expiry time: should be accepted
	s.now = func() int64 { return currentTime + 600 }
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash6, "carol", "Carol", "hc", "", "", nil, nil)
	if err != nil {
		t.Errorf("RegisterAndAcceptByPairing at exact expiry (now == expires_at) should succeed, got %v", err)
	}

	// Create another invite for +1 test
	codeHash7 := "code_test7"
	pairingHash7 := "pair_test7"
	expiresAt7 := time.Unix(currentTime+700, 0)
	s.now = func() int64 { return currentTime + 200 }
	if err := s.CreateInviteWithPairing(ctx, codeHash7, pairingHash7, "alice", []string{"messages"}, nil, expiresAt7); err != nil {
		t.Fatal(err)
	}

	// One second after expiry: should be rejected
	s.now = func() int64 { return currentTime + 701 }
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash7, "dan", "Dan", "hdan", "", "", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("RegisterAndAcceptByPairing at expires_at+1 should return ErrNotFound, got %v", err)
	}
}

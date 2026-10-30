package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var memDBCounter uint64

func uniqueMemoryDB(t *testing.T) string {
	id := atomic.AddUint64(&memDBCounter, 1)
	return fmt.Sprintf("file:memdb-%s-%d?mode=memory&cache=shared&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", t.Name(), id)
}

func TestStoreBasics(t *testing.T) {
	ctx := context.Background()
	s, err := Open(uniqueMemoryDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "a", "alice", "ha", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	s.CreatePeer(ctx, "b", "bob", "hb", "")
	if email, err := s.NotifyEmail(ctx, "a"); err != nil || email != "alice@example.com" {
		t.Fatal(email, err)
	}
	if email, err := s.NotifyEmail(ctx, "b"); err != nil || email != "" {
		t.Fatal(email, err)
	}
	if err := s.SetNotifyEmail(ctx, "a", ""); err != nil {
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
	s, err := Open(uniqueMemoryDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Stats(ctx)
	if err != nil || st != (Stats{}) {
		t.Fatalf("empty: %+v %v", st, err)
	}
	if err := s.CreatePeer(ctx, "a", "alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "b", "bob", "hb", ""); err != nil {
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
	if err := s.SetNotifyEmail(ctx, "p_old", "old@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNotifyEmail(ctx, "missing", "a@b.co"); !errors.Is(err, ErrNotFound) {
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
	if version != 2 {
		t.Fatalf("user_version = %d, want 2", version)
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
	if version != 2 {
		t.Fatalf("user_version = %d, want 2", version)
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
			if version != 2 {
				t.Fatalf("user_version = %d, want 2", version)
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
			if err := migratedStore.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
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
	if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
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
			_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash, id, name, kh, "", nil, nil)
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
	s, err := Open(uniqueMemoryDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}

	// Test 1: Expired pairing token
	expiredHash := "expired_hash"
	pastTime := time.Now().Add(-time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "code_expired", expiredHash, "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	_, err = s.RegisterAndAcceptByPairing(ctx, expiredHash, "bob", "Bob", "hb", "", nil, nil)
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
	if err := s.CreatePeer(ctx, "carol", "Carol", "hc", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInviteWithPairing(ctx, "code_used", usedHash, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AcceptInviteByPairingToken(ctx, usedHash, "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	_, err = s.RegisterAndAcceptByPairing(ctx, usedHash, "dave", "Dave", "hd", "", nil, nil)
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
	_, err = s.RegisterAndAcceptByPairing(ctx, "nonexistent_hash", "eve", "Eve", "he", "", nil, nil)
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
	s, err := Open(uniqueMemoryDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", ""); err != nil {
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

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}

	// Test 1: Duplicate peer ID causes rollback after peer insert
	pairingHash1 := "pair1"
	if err := s.CreateInviteWithPairing(ctx, "code1", pairingHash1, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// First redemption should succeed
	if _, err := s.RegisterAndAcceptByPairing(ctx, pairingHash1, "bob", "Bob", "hb", "", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Create another invite
	pairingHash2 := "pair2"
	if err := s.CreateInviteWithPairing(ctx, "code2", pairingHash2, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Try to register again with the same peer ID - should fail after peer insert
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingHash2, "bob", "Bob2", "hb2", "", nil, nil)
	if err == nil {
		t.Fatal("expected error for duplicate peer ID")
	}

	// Verify no orphan peer was created
	var peerCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='bob'`).Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 1 {
		t.Errorf("got %d bob peers, want 1", peerCount)
	}

	// Verify the invite is still unconsumed
	var used sql.NullString
	if err := s.db.QueryRow(`SELECT used_by FROM invites WHERE pairing_token_hash=?`, pairingHash2).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used.Valid {
		t.Errorf("invite was marked as used after failed redemption")
	}

	// Verify the invite can still be redeemed by a different peer
	if _, err := s.RegisterAndAcceptByPairing(ctx, pairingHash2, "carol", "Carol", "hc", "", nil, nil); err != nil {
		t.Fatalf("invite should still be redeemable: %v", err)
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
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
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
		_, err := s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", nil, nil)
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
	if err := s.CreatePeer(normalCtx, "carol", "Carol", "hc", ""); err != nil {
		t.Fatalf("DB wedged after cancel: %v", err)
	}

	// Original pairing token should still be redeemable
	_, err = s.RegisterAndAcceptByPairing(normalCtx, pairingHash, "dave", "Dave", "hd", "", nil, nil)
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
	// Save original hook and restore after test
	origHook := afterPeerInsertHook
	defer func() { afterPeerInsertHook = origHook }()

	path := t.TempDir() + "/cancel-mid-tx.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}

	pairingHash := "cancel_hash"
	exp := time.Now().Add(time.Hour)
	if err := s.CreateInviteWithPairing(ctx, "code1", pairingHash, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Set up hook to cancel context after peer INSERT
	cancelCtx, cancel := context.WithCancel(context.Background())
	afterPeerInsertHook = func() {
		cancel()
		// Give the cancellation a moment to propagate
		time.Sleep(10 * time.Millisecond)
	}

	// Try to register and accept - should fail due to cancellation after INSERT
	_, err = s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", nil, nil)
	if err == nil {
		t.Fatal("expected error after mid-transaction cancel")
	}
	if !errors.Is(err, context.Canceled) && err != context.Canceled {
		t.Logf("got error: %v (acceptable if transaction rolled back)", err)
	}

	// Clear the hook for subsequent operations
	afterPeerInsertHook = nil

	// Verify no orphan peer was created
	var bobCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE id='bob'`).Scan(&bobCount); err != nil {
		t.Fatal(err)
	}
	if bobCount != 0 {
		t.Error("orphan peer 'bob' created after mid-transaction cancel")
	}

	// Verify the invite was not consumed
	var used sql.NullString
	if err := s.db.QueryRow(`SELECT used_by FROM invites WHERE pairing_token_hash=?`, pairingHash).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used.Valid {
		t.Error("invite was consumed after mid-transaction cancel")
	}

	// Verify DB isn't wedged: next accept should succeed
	normalCtx := context.Background()
	if _, err := s.RegisterAndAcceptByPairing(normalCtx, pairingHash, "carol", "Carol", "hc", "", nil, nil); err != nil {
		t.Fatalf("DB wedged after mid-tx cancel: %v", err)
	}

	// Verify a plain write succeeds
	if err := s.CreatePeer(normalCtx, "dave", "Dave", "hd", ""); err != nil {
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
	if err := s.CreatePeer(ctx, "p_new", "new", "hn", ""); err != nil {
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
	if version != 2 {
		t.Fatalf("user_version = %d, want 2", version)
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
	if version != 2 {
		t.Fatalf("user_version after second migrate = %d, want 2", version)
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
		{"memory", uniqueMemoryDB(t)},
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
				// Only test with file DB (memory DB with single connection can't show this)
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
			}
		})
	}
}

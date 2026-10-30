package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestStoreBasics(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
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
	s, err := Open(":memory:")
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
	freshPath := t.TempDir() + "/fresh.db"
	freshStore, err := Open(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	defer freshStore.Close()

	migratedPath := t.TempDir() + "/migrated.db"
	db, err := sql.Open("sqlite", migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	// Create v0 schema with foreign key constraints so SQL matches fresh DB
	db.Exec(`PRAGMA foreign_keys=ON`)
	db.Exec(`CREATE TABLE peers (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)`)
	db.Exec(`CREATE TABLE invites (code_hash TEXT PRIMARY KEY, from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT)`)
	db.Exec(`CREATE TABLE grants (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee))`)
	db.Exec(`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, type TEXT NOT NULL, body TEXT NOT NULL, reply_to INTEGER, created_at INTEGER NOT NULL)`)
	db.Exec(`CREATE INDEX messages_inbox ON messages(recipient, id)`)
	db.Exec(`CREATE TABLE bags (owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE, name TEXT NOT NULL, content BLOB NOT NULL, version INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (owner, name))`)
	db.Close()

	migratedStore, err := Open(migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer migratedStore.Close()

	// Verify user_version is 2
	var version int
	migratedStore.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 2 {
		t.Fatalf("migrated user_version = %d, want 2", version)
	}

	// Verify both have notify_email and pairing_token_hash
	var freshNotify, migratedNotify, freshPairing, migratedPairing int
	freshStore.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&freshNotify)
	migratedStore.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&migratedNotify)
	freshStore.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&freshPairing)
	migratedStore.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&migratedPairing)

	if freshNotify != 1 || migratedNotify != 1 {
		t.Fatalf("notify_email: fresh=%d migrated=%d, want both 1", freshNotify, migratedNotify)
	}
	if freshPairing != 1 || migratedPairing != 1 {
		t.Fatalf("pairing_token_hash: fresh=%d migrated=%d, want both 1", freshPairing, migratedPairing)
	}

	// Verify both have the pairing_token_hash index
	var freshIdx, migratedIdx int
	freshStore.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&freshIdx)
	migratedStore.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&migratedIdx)
	if freshIdx != 1 || migratedIdx != 1 {
		t.Fatalf("index: fresh=%d migrated=%d, want both 1", freshIdx, migratedIdx)
	}

	// Verify both work with pairing invites
	if err := freshStore.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := migratedStore.CreatePeer(ctx, "bob", "Bob", "hb", ""); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := freshStore.CreateInviteWithPairing(ctx, "c1", "p1", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	if err := migratedStore.CreateInviteWithPairing(ctx, "c2", "p2", "bob", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
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
	s, err := Open(":memory:")
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

	// Test 4: Self-accept
	selfHash := "self_hash"
	if err := s.CreateInviteWithPairing(ctx, "code_self", selfHash, "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	_, err = s.RegisterAndAcceptByPairing(ctx, selfHash, "alice", "Alice2", "ha2", "", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for self-accept, got %v", err)
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

// TestContextCancellationMidAccept verifies the DB isn't wedged when context is cancelled.
func TestContextCancellationMidAccept(t *testing.T) {
	path := t.TempDir() + "/cancel.db"
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

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", nil, nil)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}

	normalCtx := context.Background()
	if err := s.CreatePeer(normalCtx, "carol", "Carol", "hc", ""); err != nil {
		t.Fatalf("DB wedged after cancel: %v", err)
	}

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

// Security hardening tests for store layer

func TestPurgeExpiredInvites(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create peer
	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}

	// Create an expired unused invite
	pastTime := time.Now().Add(-2 * time.Hour)
	if err := s.CreateInvite(ctx, "code_expired", "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	// Create a valid invite, accept it, then manually expire it (simulating a used but expired invite)
	futureTime := time.Now().Add(2 * time.Hour)
	if err := s.CreateInvite(ctx, "code_valid_then_used", "alice", []string{"messages"}, nil, futureTime); err != nil {
		t.Fatal(err)
	}
	// Create another peer to accept it
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}
	// Accept the invite (marks it as used)
	if _, err := s.AcceptInvite(ctx, "code_valid_then_used", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Now manually expire it
	if _, err := s.db.ExecContext(ctx, `UPDATE invites SET expires_at=? WHERE code_hash=?`, time.Now().Add(-1*time.Hour).Unix(), "code_valid_then_used"); err != nil {
		t.Fatal(err)
	}

	// Create a valid (non-expired) unused invite
	if err := s.CreateInvite(ctx, "code_valid", "alice", []string{"messages"}, nil, futureTime); err != nil {
		t.Fatal(err)
	}

	// Purge expired invites
	count, err := s.PurgeExpiredInvites(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should delete only the expired unused invite (1)
	if count != 1 {
		t.Errorf("PurgeExpiredInvites() = %d, want 1", count)
	}

	// Verify: expired but used invite should still exist (for audit)
	var checkUsed string
	err = s.db.QueryRowContext(ctx, `SELECT code_hash FROM invites WHERE code_hash=?`, "code_valid_then_used").Scan(&checkUsed)
	if err != nil {
		t.Error("expired but used invite was deleted (should be kept for audit)")
	}

	// Verify: valid invite should still exist
	var checkValid string
	err = s.db.QueryRowContext(ctx, `SELECT code_hash FROM invites WHERE code_hash=?`, "code_valid").Scan(&checkValid)
	if err != nil {
		t.Error("valid invite was deleted")
	}
}

func TestAtomicInviteCapEnforcement(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}

	// Create 2 invites (cap will be 3)
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 2; i++ {
		_, err := s.CreateInviteAtomic(ctx, fmt.Sprintf("code%d", i), "alice", []string{"messages"}, nil, exp, 3)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Try to create 2 more concurrently (only 1 should succeed)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = s.CreateInviteAtomic(ctx, fmt.Sprintf("code_concurrent%d", idx), "alice", []string{"messages"}, nil, exp, 3)
		}(i)
	}
	wg.Wait()

	// Exactly one should have succeeded, one should have ErrTooManyInvites
	successCount := 0
	tooManyCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, ErrTooManyInvites) {
			tooManyCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successCount != 1 || tooManyCount != 1 {
		t.Errorf("expected 1 success and 1 ErrTooManyInvites, got %d success and %d too-many", successCount, tooManyCount)
	}
}

func TestListInvitesByPeerPagination(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates 5 invites
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 5; i++ {
		if err := s.CreateInvite(ctx, fmt.Sprintf("alice_code%d", i), "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
	}

	// Bob creates 2 invites
	for i := 0; i < 2; i++ {
		if err := s.CreateInvite(ctx, fmt.Sprintf("bob_code%d", i), "bob", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
	}

	// List Alice's invites with limit=2
	invites, err := s.ListInvitesByPeer(ctx, "alice", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 {
		t.Errorf("expected 2 invites, got %d", len(invites))
	}

	// List Alice's invites with offset=2
	invites, err = s.ListInvitesByPeer(ctx, "alice", 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 3 {
		t.Errorf("expected 3 remaining invites, got %d", len(invites))
	}

	// Bob's list should only show his invites
	invites, err = s.ListInvitesByPeer(ctx, "bob", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 {
		t.Errorf("Bob should see 2 invites, got %d", len(invites))
	}
}

func TestDeleteInviteOwnership(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates an invite
	exp := time.Now().Add(time.Hour)
	inviteID, err := s.CreateInviteAtomic(ctx, "alice_code", "alice", []string{"messages"}, nil, exp, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Bob can't delete Alice's invite
	err = s.DeleteInvite(ctx, inviteID, "bob")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Alice can delete her own invite
	err = s.DeleteInvite(ctx, inviteID, "alice")
	if err != nil {
		t.Fatal(err)
	}

	// Repeat delete returns ErrNotFound
	err = s.DeleteInvite(ctx, inviteID, "alice")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on repeat delete, got %v", err)
	}
}
func TestContextCancellationMidAccept(t *testing.T) {
	path := t.TempDir() + "/cancel.db"
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

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = s.RegisterAndAcceptByPairing(cancelCtx, pairingHash, "bob", "Bob", "hb", "", nil, nil)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}

	normalCtx := context.Background()
	if err := s.CreatePeer(normalCtx, "carol", "Carol", "hc", ""); err != nil {
		t.Fatalf("DB wedged after cancel: %v", err)
	}

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

// Security hardening tests for store layer

func TestPurgeExpiredInvites(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	// Create peer
	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}

	// Create an expired unused invite
	pastTime := time.Now().Add(-2 * time.Hour)
	if err := s.CreateInvite(ctx, "code_expired", "alice", []string{"messages"}, nil, pastTime); err != nil {
		t.Fatal(err)
	}

	// Create a valid invite, accept it, then manually expire it (simulating a used but expired invite)
	futureTime := time.Now().Add(2 * time.Hour)
	if err := s.CreateInvite(ctx, "code_valid_then_used", "alice", []string{"messages"}, nil, futureTime); err != nil {
		t.Fatal(err)
	}
	// Create another peer to accept it
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}
	// Accept the invite (marks it as used)
	if _, err := s.AcceptInvite(ctx, "code_valid_then_used", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Now manually expire it
	if _, err := s.db.ExecContext(ctx, `UPDATE invites SET expires_at=? WHERE code_hash=?`, time.Now().Add(-1*time.Hour).Unix(), "code_valid_then_used"); err != nil {
		t.Fatal(err)
	}

	// Create a valid (non-expired) unused invite
	if err := s.CreateInvite(ctx, "code_valid", "alice", []string{"messages"}, nil, futureTime); err != nil {
		t.Fatal(err)
	}

	// Purge expired invites
	count, err := s.PurgeExpiredInvites(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should delete only the expired unused invite (1)
	if count != 1 {
		t.Errorf("PurgeExpiredInvites() = %d, want 1", count)
	}

	// Verify: expired but used invite should still exist (for audit)
	var checkUsed string
	err = s.db.QueryRowContext(ctx, `SELECT code_hash FROM invites WHERE code_hash=?`, "code_valid_then_used").Scan(&checkUsed)
	if err != nil {
		t.Error("expired but used invite was deleted (should be kept for audit)")
	}

	// Verify: valid invite should still exist
	var checkValid string
	err = s.db.QueryRowContext(ctx, `SELECT code_hash FROM invites WHERE code_hash=?`, "code_valid").Scan(&checkValid)
	if err != nil {
		t.Error("valid invite was deleted")
	}
}

func TestAtomicInviteCapEnforcement(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}

	// Create 2 invites (cap will be 3)
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 2; i++ {
		_, err := s.CreateInviteAtomic(ctx, fmt.Sprintf("code%d", i), "alice", []string{"messages"}, nil, exp, 3)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Try to create 2 more concurrently (only 1 should succeed)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = s.CreateInviteAtomic(ctx, fmt.Sprintf("code_concurrent%d", idx), "alice", []string{"messages"}, nil, exp, 3)
		}(i)
	}
	wg.Wait()

	// Exactly one should have succeeded, one should have ErrTooManyInvites
	successCount := 0
	tooManyCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, ErrTooManyInvites) {
			tooManyCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successCount != 1 || tooManyCount != 1 {
		t.Errorf("expected 1 success and 1 ErrTooManyInvites, got %d success and %d too-many", successCount, tooManyCount)
	}
}

func TestListInvitesByPeerPagination(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates 5 invites
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 5; i++ {
		if err := s.CreateInvite(ctx, fmt.Sprintf("alice_code%d", i), "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
	}

	// Bob creates 2 invites
	for i := 0; i < 2; i++ {
		if err := s.CreateInvite(ctx, fmt.Sprintf("bob_code%d", i), "bob", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
	}

	// List Alice's invites with limit=2
	invites, err := s.ListInvitesByPeer(ctx, "alice", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 {
		t.Errorf("expected 2 invites, got %d", len(invites))
	}

	// List Alice's invites with offset=2
	invites, err = s.ListInvitesByPeer(ctx, "alice", 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 3 {
		t.Errorf("expected 3 remaining invites, got %d", len(invites))
	}

	// Bob's list should only show his invites
	invites, err = s.ListInvitesByPeer(ctx, "bob", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 2 {
		t.Errorf("Bob should see 2 invites, got %d", len(invites))
	}
}

func TestDeleteInviteOwnership(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hash2", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates an invite
	exp := time.Now().Add(time.Hour)
	inviteID, err := s.CreateInviteAtomic(ctx, "alice_code", "alice", []string{"messages"}, nil, exp, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Bob can't delete Alice's invite
	err = s.DeleteInvite(ctx, inviteID, "bob")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Alice can delete her own invite
	err = s.DeleteInvite(ctx, inviteID, "alice")
	if err != nil {
		t.Fatal(err)
	}

	// Repeat delete returns ErrNotFound
	err = s.DeleteInvite(ctx, inviteID, "alice")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on repeat delete, got %v", err)
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
	if err := s.CreatePeer(ctx, "alice", "Alice", "hash1", ""); err != nil {
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
	if version != 3 {
		t.Errorf("user_version = %d, want 3", version)
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
	if version != 3 {

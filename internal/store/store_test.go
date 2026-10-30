package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
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
// PR #11 added pairing_token_hash column and index, but did not use PRAGMA user_version.
func TestPR11AlreadyMigrated(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/pr11.db"

	// Simulate a database that PR #11 already migrated (has both columns, user_version is 0)
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
			used_by TEXT,
			pairing_token_hash TEXT
		);
		CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash);
		CREATE TABLE grants (owner TEXT NOT NULL, grantee TEXT NOT NULL, scopes TEXT NOT NULL, bags TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (owner, grantee));
	`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES('alice','Alice','ha',1,'alice@example.com')`); err != nil {
		t.Fatal(err)
	}

	// user_version should be 0 (PR #11 didn't set it)
	var version int
	db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 0 {
		t.Fatalf("fixture user_version = %d, want 0", version)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with our migration code
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Verify user_version is now 2
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 2 {
		t.Fatalf("user_version = %d, want 2", version)
	}

	// Verify columns exist
	var notifyEmailCol, pairingCol int
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name='notify_email'`).Scan(&notifyEmailCol)
	s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name='pairing_token_hash'`).Scan(&pairingCol)
	if notifyEmailCol != 1 || pairingCol != 1 {
		t.Fatalf("columns missing: notify_email=%d, pairing_token_hash=%d", notifyEmailCol, pairingCol)
	}

	// Verify index exists
	var hasIndex int
	s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&hasIndex)
	if hasIndex != 1 {
		t.Fatal("invites_pairing_token_hash index missing")
	}

	// Verify old data intact
	email, err := s.NotifyEmail(ctx, "alice")
	if err != nil || email != "alice@example.com" {
		t.Fatalf("notify_email after PR #11 migration: %q %v", email, err)
	}

	// Verify pairing invites work
	if err := s.CreateInviteWithPairing(ctx, "code1", "pair1", "alice", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("pairing invite after PR #11 migration: %v", err)
	}
}

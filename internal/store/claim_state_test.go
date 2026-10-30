package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

const claimNow = int64(2_000_000)

func claimStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.now = func() int64 { return claimNow }
	for _, id := range []string{"alice", "bob", "carol"} {
		if err := s.CreatePeer(context.Background(), id, id, "h"+id, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s *Store) mustExec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// Every legacy accept entry point must refuse confirm-mode, claimed and declined invites
// with ErrNotFound and write no grant (#69).
func TestLegacyAcceptPathsGatedOnClaimState(t *testing.T) {
	ctx := context.Background()
	states := map[string]string{
		"confirm-mode": `require_confirm=1`,
		"claimed":      `claimed_by='carol', confirm_by=` + "9999999",
		"declined":     `claimed_by='carol', declined_at=1999999`,
	}
	for name, set := range states {
		t.Run(name, func(t *testing.T) {
			s := claimStore(t)
			exp := time.Unix(claimNow+3600, 0)
			if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
				t.Fatal(err)
			}
			s.mustExec(t, `UPDATE invites SET `+set)
			paths := map[string]func() error{
				"code": func() error { _, err := s.AcceptInvite(ctx, "code", "bob", []string{"messages"}, nil); return err },
				"pairing": func() error {
					_, err := s.AcceptInviteByPairingToken(ctx, "pair", "bob", []string{"messages"}, nil)
					return err
				},
				"register+pairing": func() error {
					_, err := s.RegisterAndAcceptByPairing(ctx, "pair", "newpeer", "n", "hnew", "", "", []string{"messages"}, nil)
					return err
				},
			}
			for pn, call := range paths {
				if err := call(); !errors.Is(err, ErrNotFound) {
					t.Errorf("%s: got %v, want ErrNotFound", pn, err)
				}
			}
			if ok, _ := s.PeerExists(ctx, "newpeer"); ok {
				t.Error("register+pairing left a peer behind")
			}
			var n int
			s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&n)
			if n != 0 {
				t.Errorf("%d grants written", n)
			}
		})
	}
}

func TestInviteChecksRejectBadStates(t *testing.T) {
	s := claimStore(t)
	if err := s.CreateInvite(context.Background(), "x", "alice", nil, nil, time.Unix(claimNow+60, 0)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`require_confirm=1, used_by='bob'`,
		`require_confirm=1, claimed_by='carol', used_by='bob'`,
		`claimed_by='carol', declined_at=1, used_by='carol'`,
		`confirm_by=5`,
		`declined_at=5`,
		`require_confirm=2`,
	} {
		if _, err := s.db.Exec(`UPDATE invites SET ` + bad); err == nil {
			t.Errorf("CHECK accepted: %s", bad)
		}
	}
	// confirm may set used_by only to the claimant
	s.mustExec(t, `UPDATE invites SET require_confirm=1, claimed_by='carol', confirm_by=?`, claimNow+86400)
	s.mustExec(t, `UPDATE invites SET used_by='carol'`)
}

// A claim made just before expires_at stays visible, counted and unpurged until confirm_by (#70).
func TestClaimedInviteLivesUntilConfirmBy(t *testing.T) {
	ctx := context.Background()
	s := claimStore(t)
	if err := s.CreateInvite(ctx, "x", "alice", []string{"messages"}, nil, time.Unix(claimNow+60, 0)); err != nil {
		t.Fatal(err)
	}
	confirmBy := claimNow + 60 + 86400
	s.mustExec(t, `UPDATE invites SET claimed_by='carol', confirm_by=?`, confirmBy)

	at := func(ts int64) { s.now = func() int64 { return ts } }
	state := func() (count, listed, purged int) {
		count, _ = s.CountOutstandingInvites(ctx, "alice")
		l, _ := s.ListInvitesByPeer(ctx, "alice", 50, 0)
		n, _, err := s.PurgeExpiredInvites(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		return count, len(l), n
	}

	at(claimNow + 2*3600) // past expires_at and its 5-minute purge grace
	if c, l, p := state(); c != 1 || l != 1 || p != 0 {
		t.Fatalf("claimed invite after expires_at: count=%d listed=%d purged=%d", c, l, p)
	}
	at(confirmBy + 1)
	if c, l, _ := state(); c != 0 || l != 0 {
		t.Fatalf("after confirm_by: count=%d listed=%d", c, l)
	}
	at(confirmBy + 301)
	if _, _, p := state(); p != 1 {
		t.Fatalf("claimed invite not purged after confirm_by+grace, purged=%d", p)
	}
}

// The invite cap counts claimed-unexpired invites (#70).
func TestInviteCapCountsClaimed(t *testing.T) {
	ctx := context.Background()
	s := claimStore(t)
	if _, err := s.CreateInviteAtomic(ctx, "x", "alice", nil, nil, time.Unix(claimNow+60, 0), 1); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET claimed_by='carol', confirm_by=?`, claimNow+86400)
	s.now = func() int64 { return claimNow + 120 }
	if _, err := s.CreateInviteAtomic(ctx, "y", "alice", nil, nil, time.Unix(claimNow+9999, 0), 1); !errors.Is(err, ErrTooManyInvites) {
		t.Fatalf("cap bypassed by claimed invite: %v", err)
	}
}

// Peers created by an unconfirmed claim are purged only while they own nothing (#74).
func TestPurgeOrphanClaimPeers(t *testing.T) {
	ctx := context.Background()
	s := claimStore(t)
	for _, id := range []string{"orphan", "granted", "messaged"} {
		s.mustExec(t, `INSERT INTO peers(id,name,key_hash,created_at,created_via_invite) VALUES(?,?,?,?,1)`, id, id, "h"+id, claimNow-3600)
	}
	s.mustExec(t, `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES('alice','granted','messages','',1)`)
	s.mustExec(t, `INSERT INTO messages(sender,recipient,type,body,created_at) VALUES('messaged','alice','t','b',1)`)
	if _, _, err := s.PurgeExpiredInvites(ctx, 0); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"orphan": false, "granted": true, "messaged": true, "bob": true} {
		if got, _ := s.PeerExists(ctx, id); got != want {
			t.Errorf("peer %s exists=%v want %v", id, got, want)
		}
	}
}

// v4 -> v5 keeps rows, backfills NULL public_id and applies the CHECKs (#77).
func TestMigrateV5FromV4(t *testing.T) {
	path := secureTempDir(t) + "/p.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		schema,
		`INSERT INTO peers(id,name,key_hash,created_at) VALUES('a','a','h',1),('b','b','h2',1)`,
		`INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,used_by,public_id) VALUES('open','a','m','',5,NULL,NULL),('used','a','m','',5,'b','pid')`,
		`PRAGMA user_version=4`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	for i := 0; i < 2; i++ { // second Open is a no-op
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var n, withID int
		s.db.QueryRow(`SELECT COUNT(*), COUNT(public_id) FROM invites WHERE require_confirm=0 AND claimed_by IS NULL`).Scan(&n, &withID)
		if n != 2 || withID != 2 {
			t.Fatalf("rows=%d with public_id=%d", n, withID)
		}
		if _, err := s.db.Exec(`UPDATE invites SET require_confirm=1 WHERE code_hash='used'`); err == nil {
			t.Fatal("CHECK allowed used confirm-mode invite without claim")
		}
		s.Close()
	}
}

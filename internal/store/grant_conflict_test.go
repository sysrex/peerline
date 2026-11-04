package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

// TestAcceptOverDifferentGrantReturnsConflict verifies that accepting an invite
// when a different grant already exists returns ErrConflict, leaves grants unchanged,
// and keeps the invite unused (#312).
func TestAcceptOverDifferentGrantReturnsConflict(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Setup: alice and bob are already paired with messages scope
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
		t.Fatal(err)
	}

	// Create initial grant: alice grants bob "messages"
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"alice", "bob", "messages", "", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Alice creates a new invite with different scope ("bags_read")
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept - should fail with ErrConflict
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInvite with different grant: got %v, want ErrConflict", err)
	}

	// Verify grant is unchanged
	g, err := s.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "messages" {
		t.Errorf("grant changed: got %v, want [messages]", g.Scopes)
	}

	// Verify invite is still unused
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != nil {
		t.Errorf("invite was consumed: used_by=%v", used)
	}

	// Revoke the grant and try again - should succeed
	if err := s.RevokeGrant(ctx, "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	g2, err := s.AcceptInvite(ctx, code, "bob", nil, nil)
	if err != nil {
		t.Fatalf("AcceptInvite after revoke: %v", err)
	}
	if len(g2.Scopes) != 1 || g2.Scopes[0] != "bags_read" {
		t.Errorf("new grant: got %v, want [bags_read]", g2.Scopes)
	}
}

// TestAcceptReorderedGrantSucceeds verifies that reordered identical grants are treated
// as equal and return 200 (idempotent), testing set semantics (#337 item 1).
func TestAcceptReorderedGrantSucceeds(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "a,b" with bags "x,y"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"a", "b"}, []string{"x", "y"}, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with reordered scopes and bags "b,a" and "y,x"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"b", "a"}, []string{"y", "x"}, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts - should succeed (reordered = identical)
	g, err := s.AcceptInvite(ctx, code, "bob", nil, nil)
	if err != nil {
		t.Fatalf("AcceptInvite with reordered grant: %v", err)
	}
	if g.Owner != "alice" || g.Grantee != "bob" {
		t.Errorf("grant: got owner=%s grantee=%s", g.Owner, g.Grantee)
	}

	// Verify invite is consumed
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != "bob" {
		t.Errorf("invite not consumed: used_by=%v, want bob", used)
	}
}

// TestAcceptDuplicatedGrantSucceeds verifies that duplicated scopes/bags are treated
// as equal and return 200 (idempotent), testing set semantics (#337 item 1).
func TestAcceptDuplicatedGrantSucceeds(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "a,b"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"a", "b"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with duplicated scopes "a,a,b"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"a", "a", "b"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts - should succeed (duplicates deduplicated to match)
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if err != nil {
		t.Fatalf("AcceptInvite with duplicated grant: %v", err)
	}
}

// TestAcceptSupersetGrantConflicts verifies that a superset of scopes or bags
// returns ErrConflict (409), testing set semantics (#337 item 1).
func TestAcceptSupersetGrantConflicts(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "a"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"a"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with superset "a,b"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"a", "b"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept - should fail with ErrConflict
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInvite with superset grant: got %v, want ErrConflict", err)
	}

	// Verify invite is still unused
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != nil {
		t.Errorf("invite was consumed: used_by=%v", used)
	}
}

// TestAcceptSubsetGrantConflicts verifies that a subset of scopes or bags
// returns ErrConflict (409), testing set semantics (#337 item 1).
func TestAcceptSubsetGrantConflicts(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "a,b"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"a", "b"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with subset "a"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"a"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept - should fail with ErrConflict
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInvite with subset grant: got %v, want ErrConflict", err)
	}

	// Verify invite is still unused
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != nil {
		t.Errorf("invite was consumed: used_by=%v", used)
	}
}

// TestAcceptChangedBagsConflicts verifies that a changed bag list
// returns ErrConflict (409), testing set semantics (#337 item 1).
func TestAcceptChangedBagsConflicts(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "a" with bags "x"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"a"}, []string{"x"}, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with same scopes but different bags "y"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"a"}, []string{"y"}, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept - should fail with ErrConflict
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInvite with changed bags: got %v, want ErrConflict", err)
	}

	// Verify invite is still unused
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != nil {
		t.Errorf("invite was consumed: used_by=%v", used)
	}
}

// TestAcceptOverIdenticalGrantSucceeds verifies idempotent behavior: accepting
// an invite with identical scopes and bags as an existing grant succeeds (#312).
func TestAcceptOverIdenticalGrantSucceeds(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grant: alice grants bob "messages,bags_read" with bags "b1,b2"
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"alice", "bob", "messages,bags_read", "b1,b2", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Alice creates an invite with same scopes and bags (order-insensitive)
	exp := clk.Now().Add(time.Hour)
	code := "code2"
	if err := s.CreateInvite(ctx, code, "alice", []string{"bags_read", "messages"}, []string{"b2", "b1"}, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts - should succeed (idempotent)
	g, err := s.AcceptInvite(ctx, code, "bob", nil, nil)
	if err != nil {
		t.Fatalf("AcceptInvite with identical grant: %v", err)
	}
	if len(g.Scopes) != 2 {
		t.Errorf("grant scopes: got %v, want 2 scopes", g.Scopes)
	}

	// Verify invite is consumed
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != "bob" {
		t.Errorf("invite not consumed: used_by=%v, want bob", used)
	}
}

// TestAcceptWithDifferentReverseGrantConflicts verifies that when back scopes
// are present and the reverse grant differs, ErrConflict is returned (#312).
func TestAcceptWithDifferentReverseGrantConflicts(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create initial grants: alice->bob and bob->alice with "messages"
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"alice", "bob", "messages", "", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"bob", "alice", "messages", "", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with same forward scope but different back scope
	exp := clk.Now().Add(time.Hour)
	code := "code3"
	if err := s.CreateInvite(ctx, code, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts with different back scopes - should fail
	_, err = s.AcceptInvite(ctx, code, "bob", []string{"bags_read"}, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInvite with different reverse grant: got %v, want ErrConflict", err)
	}

	// Verify both grants are unchanged
	g1, err := s.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(g1.Scopes) != 1 || g1.Scopes[0] != "messages" {
		t.Errorf("forward grant changed: got %v", g1.Scopes)
	}

	g2, err := s.GetGrant(ctx, "bob", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(g2.Scopes) != 1 || g2.Scopes[0] != "messages" {
		t.Errorf("reverse grant changed: got %v", g2.Scopes)
	}
}

// TestFirstTimeAcceptStillWorks verifies that the fix doesn't break first-time
// pairing when no grants exist yet (#312).
func TestFirstTimeAcceptStillWorks(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Alice creates invite
	exp := clk.Now().Add(time.Hour)
	code := "code4"
	if err := s.CreateInvite(ctx, code, "alice", []string{"messages"}, []string{"bag1"}, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts for the first time - should succeed
	g, err := s.AcceptInvite(ctx, code, "bob", []string{"bags_read"}, nil)
	if err != nil {
		t.Fatalf("first-time accept: %v", err)
	}
	if g.Owner != "alice" || g.Grantee != "bob" {
		t.Errorf("grant: got owner=%s grantee=%s", g.Owner, g.Grantee)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "messages" {
		t.Errorf("grant scopes: got %v, want [messages]", g.Scopes)
	}

	// Verify both grants were created
	_, err = s.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Errorf("forward grant not created: %v", err)
	}
	_, err = s.GetGrant(ctx, "bob", "alice")
	if err != nil {
		t.Errorf("reverse grant not created: %v", err)
	}
}

// TestPairingTokenAcceptWithGrantConflict verifies that the pairing token path
// also checks for grant conflicts (#312).
func TestPairingTokenAcceptWithGrantConflict(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create existing grant
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"alice", "bob", "messages", "", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite with different scope
	exp := clk.Now().Add(time.Hour)
	code := "code5"
	pairingToken := "pair5"
	if err := s.CreateInviteWithPairing(ctx, code, pairingToken, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts via pairing token - should fail
	_, err = s.AcceptInviteByPairingToken(ctx, pairingToken, "bob", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("AcceptInviteByPairingToken with different grant: got %v, want ErrConflict", err)
	}

	// Verify invite still unused
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != nil {
		t.Errorf("invite was consumed: used_by=%v", used)
	}
}

// TestRegisterAndAcceptNewPeerIgnoresOtherPeersGrant verifies that RegisterAndAcceptByPairing
// succeeds for a new peer even when a different peer has a grant from the inviter.
func TestRegisterAndAcceptNewPeerIgnoresOtherPeersGrant(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	// Pre-create a peer "newpeer" with a grant from alice
	if err := s.CreatePeer(ctx, "newpeer", "NewPeer", "hnew", "", ""); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)`,
		"alice", "newpeer", "messages", "", clk.Now().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite with different scope
	exp := clk.Now().Add(time.Hour)
	code := "code6"
	pairingToken := "pair6"
	if err := s.CreateInviteWithPairing(ctx, code, pairingToken, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// A different new peer accepts - should succeed (otherpeer has no existing grant)
	_, err = s.RegisterAndAcceptByPairing(ctx, pairingToken, "otherpeer", "Other", "hother", "", "", nil, nil)
	if err != nil {
		t.Fatalf("RegisterAndAcceptByPairing for new peer: %v", err)
	}
}

// TestInTxUsedFilterReturns404 verifies that the in-tx SELECT filter in acceptInviteInTx
// refuses a used invite before checking grant conflicts, returning ErrNotFound not ErrConflict.
// This test fails if the SELECT's `used_by IS NULL AND expires_at>=?` filter is removed,
// because the grant conflict check would run first and return ErrConflict (#330 P3-2).
func TestInTxUsedFilterReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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
	if err := s.CreatePeer(ctx, "carol", "Carol", "hc", "", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates an invite with "messages" and Bob accepts it
	exp := clk.Now().Add(time.Hour)
	code := "code_used"
	if err := s.CreateInvite(ctx, code, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Now Alice creates a second invite with DIFFERENT grant "bags_read"
	code2 := "code_used2"
	if err := s.CreateInvite(ctx, code2, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code2, "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Carol now has a different grant than what code offers
	// If Carol tries to accept the used code, it should return ErrNotFound (404) not ErrConflict (409)
	// because the SELECT filter catches it before the grant conflict check
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	_, err = acceptInviteInTx(ctx, tx, code, "carol", nil, nil, clk.Now().Unix())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("acceptInviteInTx on used invite with different grant: got %v, want ErrNotFound (not ErrConflict)", err)
	}
}

// TestInTxExpiredFilterReturns404 verifies that the in-tx SELECT filter in acceptInviteInTx
// refuses an expired invite before checking grant conflicts, returning ErrNotFound not ErrConflict.
// This test fails if the SELECT's `used_by IS NULL AND expires_at>=?` filter is removed,
// because the grant conflict check would run first and return ErrConflict (#330 P3-2).
func TestInTxExpiredFilterReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Bob already has a grant from alice with "messages"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates an invite with DIFFERENT grant "bags_read" that expires soon
	exp := clk.Now().Add(time.Hour)
	code := "code_expired"
	if err := s.CreateInvite(ctx, code, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Advance clock past expiry
	clk.Advance(2 * time.Hour)

	// Bob tries to accept the expired invite
	// It should return ErrNotFound (404) not ErrConflict (409)
	// because the SELECT filter catches it before the grant conflict check
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	_, err = acceptInviteInTx(ctx, tx, code, "bob", nil, nil, clk.Now().Unix())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("acceptInviteInTx on expired invite with different grant: got %v, want ErrNotFound (not ErrConflict)", err)
	}
}

// TestIdenticalReAcceptKeepsCreatedAt verifies that accepting an invite with identical
// grants does not update created_at, keeping grant row order stable (#330 P3-4).
func TestIdenticalReAcceptKeepsCreatedAt(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Alice creates first invite and Bob accepts it
	exp1 := clk.Now().Add(time.Hour)
	code1 := "code1"
	if err := s.CreateInvite(ctx, code1, "alice", []string{"messages", "bags_read"}, []string{"b1"}, exp1); err != nil {
		t.Fatal(err)
	}
	firstAcceptTime := clk.Now().Unix()
	if _, err := s.AcceptInvite(ctx, code1, "bob", []string{"bags_write"}, []string{"b2"}); err != nil {
		t.Fatal(err)
	}

	// Read the created_at for both grants
	var forwardCreatedAt, reverseCreatedAt int64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&forwardCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "bob", "alice").Scan(&reverseCreatedAt)
	if err != nil {
		t.Fatal(err)
	}

	if forwardCreatedAt != firstAcceptTime {
		t.Errorf("forward grant created_at: got %d, want %d", forwardCreatedAt, firstAcceptTime)
	}
	if reverseCreatedAt != firstAcceptTime {
		t.Errorf("reverse grant created_at: got %d, want %d", reverseCreatedAt, firstAcceptTime)
	}

	// Advance clock to make the timestamp difference visible
	clk.Advance(10 * time.Minute)
	secondAcceptTime := clk.Now().Unix()
	if secondAcceptTime == firstAcceptTime {
		t.Fatal("clock did not advance")
	}

	// Alice creates second invite with identical grants (reordered to test set semantics)
	exp2 := clk.Now().Add(time.Hour)
	code2 := "code2"
	if err := s.CreateInvite(ctx, code2, "alice", []string{"bags_read", "messages"}, []string{"b1"}, exp2); err != nil {
		t.Fatal(err)
	}

	// Bob accepts again with identical back grants
	if _, err := s.AcceptInvite(ctx, code2, "bob", []string{"bags_write"}, []string{"b2"}); err != nil {
		t.Fatal(err)
	}

	// Read created_at again - should be unchanged
	var newForwardCreatedAt, newReverseCreatedAt int64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&newForwardCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "bob", "alice").Scan(&newReverseCreatedAt)
	if err != nil {
		t.Fatal(err)
	}

	if newForwardCreatedAt != firstAcceptTime {
		t.Errorf("identical re-accept changed forward created_at: got %d, want %d (not %d)",
			newForwardCreatedAt, firstAcceptTime, secondAcceptTime)
	}
	if newReverseCreatedAt != firstAcceptTime {
		t.Errorf("identical re-accept changed reverse created_at: got %d, want %d (not %d)",
			newReverseCreatedAt, firstAcceptTime, secondAcceptTime)
	}

	// Verify invite was consumed
	var used interface{}
	err = s.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code2).Scan(&used)
	if err != nil {
		t.Fatal(err)
	}
	if used != "bob" {
		t.Errorf("second invite not consumed: used_by=%v, want bob", used)
	}

	// P3-a: Add a third grant and assert the list order explicitly.
	// Advance clock again to create a third grant with distinct timestamp.
	clk.Advance(10 * time.Minute)
	thirdAcceptTime := clk.Now().Unix()

	if err := s.CreatePeer(ctx, "charlie", "Charlie", "hc", "", ""); err != nil {
		t.Fatal(err)
	}

	code3 := "code3"
	exp3 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code3, "alice", []string{"messages"}, nil, exp3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code3, "charlie", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Query all alice's grants ordered by created_at
	rows, err := s.db.Query(`SELECT grantee, created_at FROM grants WHERE owner=? ORDER BY created_at`, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type grantRow struct {
		grantee   string
		createdAt int64
	}
	var grants []grantRow
	for rows.Next() {
		var gr grantRow
		if err := rows.Scan(&gr.grantee, &gr.createdAt); err != nil {
			t.Fatal(err)
		}
		grants = append(grants, gr)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Assert the list order: bob (firstAcceptTime), charlie (thirdAcceptTime)
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants from alice, got %d", len(grants))
	}
	if grants[0].grantee != "bob" || grants[0].createdAt != firstAcceptTime {
		t.Errorf("first grant: got grantee=%s created_at=%d, want grantee=bob created_at=%d",
			grants[0].grantee, grants[0].createdAt, firstAcceptTime)
	}
	if grants[1].grantee != "charlie" || grants[1].createdAt != thirdAcceptTime {
		t.Errorf("second grant: got grantee=%s created_at=%d, want grantee=charlie created_at=%d",
			grants[1].grantee, grants[1].createdAt, thirdAcceptTime)
	}
}

// TestSelfPairingStillReturnsError verifies that the self-pairing check
// still works and returns ErrSelfPairing (not ErrConflict).
func TestSelfPairingStillReturnsError(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite
	exp := time.Now().Add(time.Hour)
	code := "selfcode"
	if err := s.CreateInvite(ctx, code, "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Alice tries to accept her own invite - should fail with ErrSelfPairing
	_, err = s.AcceptInvite(ctx, code, "alice", nil, nil)
	if !errors.Is(err, ErrSelfPairing) {
		t.Fatalf("self-pairing: got %v, want ErrSelfPairing", err)
	}
}

// TestExpiredInviteWithDifferentGrantReturns404 verifies that an expired invite
// returns ErrNotFound (404), not ErrConflict (409), even when grants differ (#312).
func TestExpiredInviteWithDifferentGrantReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create existing grant alice->bob with "messages"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with different scope that expires in 1 hour
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Advance clock past expiry
	clk.Advance(2 * time.Hour)

	// Bob tries to accept expired invite - should get ErrNotFound, not ErrConflict
	_, err = s.AcceptInvite(ctx, code, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite with different grant: got %v, want ErrNotFound", err)
	}
}

// TestUsedInviteWithDifferentGrantReturns404 verifies that a used invite
// returns ErrNotFound (404), not ErrConflict (409), even when grants differ (#312).
func TestUsedInviteWithDifferentGrantReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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
	if err := s.CreatePeer(ctx, "carol", "Carol", "hc", "", ""); err != nil {
		t.Fatal(err)
	}

	// Carol accepts first, getting grant with "messages"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite for Bob with "bags_read"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	if err := s.CreateInvite(ctx, code, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts it
	if _, err := s.AcceptInvite(ctx, code, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Carol (who has different grant "messages") tries to accept the now-used invite
	// Should get ErrNotFound, not ErrConflict
	_, err = s.AcceptInvite(ctx, code, "carol", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("used invite with different grant: got %v, want ErrNotFound", err)
	}
}

// TestExpiredPairingTokenWithDifferentGrantReturns404 verifies that an expired
// pairing token returns ErrNotFound (404), not ErrConflict (409), even when grants differ.
func TestExpiredPairingTokenWithDifferentGrantReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Create existing grant alice->bob with "messages"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite with different scope that expires in 1 hour
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	pairingToken := "pair1"
	if err := s.CreateInviteWithPairing(ctx, code, pairingToken, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Advance clock past expiry
	clk.Advance(2 * time.Hour)

	// Bob tries to accept expired pairing token - should get ErrNotFound, not ErrConflict
	_, err = s.AcceptInviteByPairingToken(ctx, pairingToken, "bob", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pairing token with different grant: got %v, want ErrNotFound", err)
	}
}

// TestUsedPairingTokenWithDifferentGrantReturns404 verifies that a used pairing
// token returns ErrNotFound (404), not ErrConflict (409), even when grants differ.
func TestUsedPairingTokenWithDifferentGrantReturns404(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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
	if err := s.CreatePeer(ctx, "carol", "Carol", "hc", "", ""); err != nil {
		t.Fatal(err)
	}

	// Carol accepts first, getting grant with "messages"
	code0 := "code0"
	exp0 := clk.Now().Add(time.Hour)
	if err := s.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code0, "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite for Bob with "bags_read"
	exp := clk.Now().Add(time.Hour)
	code := "code1"
	pairingToken := "pair1"
	if err := s.CreateInviteWithPairing(ctx, code, pairingToken, "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts it
	if _, err := s.AcceptInviteByPairingToken(ctx, pairingToken, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Carol (who has different grant "messages") tries to accept the now-used pairing token
	// Should get ErrNotFound, not ErrConflict
	_, err = s.AcceptInviteByPairingToken(ctx, pairingToken, "carol", nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("used pairing token with different grant: got %v, want ErrNotFound", err)
	}
}

// TestConcurrentAcceptSameInvite verifies that when two goroutines race to accept the same
// invite, exactly one succeeds and the other gets ErrNotFound (#330 P3-3).
func TestConcurrentAcceptSameInvite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))

	for iter := 0; iter < 50; iter++ {
		dbPath := t.TempDir() + "/test.db"
		s1, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}

		if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "carol", "Carol", "hc", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		exp := clk.Now().Add(time.Hour)
		code := "code_race"
		if err := s1.CreateInvite(ctx, code, "alice", []string{"messages"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		s2, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			s1.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		results := make(chan error, 2)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s1.AcceptInvite(ctx, code, "bob", nil, nil)
			results <- err
		}()
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s2.AcceptInvite(ctx, code, "carol", nil, nil)
			results <- err
		}()

		close(barrier)
		wg.Wait()
		close(results)

		var errs []error
		for e := range results {
			errs = append(errs, e)
		}

		// Exactly one should succeed, one should fail with ErrNotFound
		successes := 0
		notFounds := 0
		for _, e := range errs {
			if e == nil {
				successes++
			} else if errors.Is(e, ErrNotFound) {
				notFounds++
			} else {
				t.Errorf("iter %d: unexpected error: %v", iter, e)
			}
		}

		if successes != 1 || notFounds != 1 {
			t.Errorf("iter %d: got %d successes, %d notFounds; want 1, 1", iter, successes, notFounds)
		}

		// Verify exactly one invite is used
		var used interface{}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used); err != nil {
			s1.Close()
			s2.Close()
			t.Fatal(err)
		}
		if used == nil {
			t.Errorf("iter %d: invite not consumed", iter)
		}

		s1.Close()
		s2.Close()
	}
}

// TestConcurrentAcceptVsRevoke races a legacy accept against RevokeGrant to ensure
// no mixed state occurs: the invite is either consumed with the grant written, or
// left unused when the grant is missing (#337 item 4).
func TestConcurrentAcceptVsRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))

	for iter := 0; iter < 50; iter++ {
		dbPath := t.TempDir() + "/test.db"
		s1, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}

		if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Create initial grant
		code0 := "code0"
		exp0 := clk.Now().Add(time.Hour)
		if err := s1.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if _, err := s1.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Create second invite with identical grant
		exp := clk.Now().Add(time.Hour)
		code := "code_race"
		if err := s1.CreateInvite(ctx, code, "alice", []string{"messages"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		s2, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			s1.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		acceptErr := make(chan error, 1)
		revokeErr := make(chan error, 1)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s1.AcceptInvite(ctx, code, "bob", nil, nil)
			acceptErr <- err
		}()
		go func() {
			defer wg.Done()
			<-barrier
			err := s2.RevokeGrant(ctx, "alice", "bob")
			revokeErr <- err
		}()

		close(barrier)
		wg.Wait()

		aErr := <-acceptErr
		rErr := <-revokeErr

		var grantExists bool
		gErr := s1.db.QueryRow(`SELECT 1 FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(new(int))
		if gErr == nil {
			grantExists = true
		} else if !errors.Is(gErr, sql.ErrNoRows) {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: grant check error: %v", iter, gErr)
		}

		var used interface{}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite check error: %v", iter, err)
		}

		inviteUsed := (used != nil)

		// Accept both valid serial outcomes: (1) accept-then-revoke → no grant, or
		// (2) revoke-then-accept → grant exists. Both invites carry the same grant,
		// so accept never returns ErrConflict (it takes the skip path).
		if aErr == nil && rErr == nil {
			// Both succeeded. Valid outcomes: grant exists (revoke-then-accept) or not (accept-then-revoke).
			// In both cases, invite must be consumed.
			if !inviteUsed {
				t.Errorf("iter %d: accept succeeded but invite not consumed (grantExists=%v)", iter, grantExists)
			}
		} else if aErr != nil && !errors.Is(aErr, ErrConflict) {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: unexpected accept error: %v", iter, aErr)
		} else if rErr != nil && !errors.Is(rErr, ErrNotFound) {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: unexpected revoke error: %v", iter, rErr)
		}

		s1.Close()
		s2.Close()
	}
}

// TestConcurrentAcceptVsRevokeDifferentGrant races accept (with a different grant)
// against RevokeGrant. The accept should return ErrConflict and leave the invite unused.
func TestConcurrentAcceptVsRevokeDifferentGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))

	for iter := 0; iter < 50; iter++ {
		dbPath := t.TempDir() + "/test.db"
		s1, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}

		if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Create initial grant with "messages"
		code0 := "code0"
		exp0 := clk.Now().Add(time.Hour)
		if err := s1.CreateInvite(ctx, code0, "alice", []string{"messages"}, nil, exp0); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if _, err := s1.AcceptInvite(ctx, code0, "bob", nil, nil); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Create second invite with DIFFERENT grant ("bags_read")
		exp := clk.Now().Add(time.Hour)
		code := "code_race"
		if err := s1.CreateInvite(ctx, code, "alice", []string{"bags_read"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		s2, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			s1.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		acceptErr := make(chan error, 1)
		revokeErr := make(chan error, 1)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s1.AcceptInvite(ctx, code, "bob", nil, nil)
			acceptErr <- err
		}()
		go func() {
			defer wg.Done()
			<-barrier
			err := s2.RevokeGrant(ctx, "alice", "bob")
			revokeErr <- err
		}()

		close(barrier)
		wg.Wait()

		aErr := <-acceptErr
		rErr := <-revokeErr

		var grantExists bool
		var grantScopes string
		gErr := s1.db.QueryRow(`SELECT scopes FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&grantScopes)
		if gErr == nil {
			grantExists = true
		} else if !errors.Is(gErr, sql.ErrNoRows) {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: grant check error: %v", iter, gErr)
		}

		var used interface{}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code).Scan(&used); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite check error: %v", iter, err)
		}

		inviteUsed := (used != nil)

		// Two valid orderings with different grants:
		// (1) accept-then-revoke: accept returns ErrConflict, invite unused, grant may or may not exist
		// (2) revoke-then-accept: revoke succeeds, accept succeeds with new grant, invite used
		if aErr == nil {
			// Accept succeeded: revoke must have gone first. New grant must exist and invite used.
			if !grantExists {
				s1.Close()
				s2.Close()
				t.Errorf("iter %d: accept succeeded but grant missing", iter)
			}
			if grantScopes != "bags_read" {
				s1.Close()
				s2.Close()
				t.Errorf("iter %d: accept succeeded but grant is %q, want bags_read", iter, grantScopes)
			}
			if !inviteUsed {
				s1.Close()
				s2.Close()
				t.Errorf("iter %d: accept succeeded but invite not consumed", iter)
			}
			if rErr != nil && !errors.Is(rErr, ErrNotFound) {
				s1.Close()
				s2.Close()
				t.Errorf("iter %d: unexpected revoke error: %v", iter, rErr)
			}
		} else if errors.Is(aErr, ErrConflict) {
			// Accept conflicted: old grant was still there. Invite must be unused.
			if inviteUsed {
				s1.Close()
				s2.Close()
				t.Errorf("iter %d: accept returned ErrConflict but invite was consumed", iter)
			}
		} else {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: unexpected accept error: %v", iter, aErr)
		}

		s1.Close()
		s2.Close()
	}
}

// TestConcurrentAcceptDifferentInvites races two accepts of different invites between
// the same pair with identical grants. Both should succeed (second takes skip path),
// both invites consumed, exactly one grant row with unchanged created_at (#340).
func TestConcurrentAcceptDifferentInvites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))

	for iter := 0; iter < 50; iter++ {
		dbPath := t.TempDir() + "/test.db"
		s1, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}

		if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Capture the time before creating invites
		createdAtBefore := clk.Now().Unix()

		// Create two invites with identical grants
		exp := clk.Now().Add(time.Hour)
		code1 := "code1"
		code2 := "code2"
		if err := s1.CreateInvite(ctx, code1, "alice", []string{"messages"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreateInvite(ctx, code2, "alice", []string{"messages"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		s2, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			s1.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		results := make(chan error, 2)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s1.AcceptInvite(ctx, code1, "bob", nil, nil)
			results <- err
		}()
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s2.AcceptInvite(ctx, code2, "bob", nil, nil)
			results <- err
		}()

		close(barrier)
		wg.Wait()
		close(results)

		var errs []error
		for e := range results {
			errs = append(errs, e)
		}

		// Assert exactly 2 successes (both invites carry identical grants)
		successes := 0
		for _, e := range errs {
			if e == nil {
				successes++
			} else if !errors.Is(e, ErrConflict) && !errors.Is(e, ErrNotFound) {
				s1.Close()
				s2.Close()
				t.Fatalf("iter %d: unexpected error: %v", iter, e)
			}
		}

		if successes != 2 {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: expected exactly 2 successes with identical grants, got %d (errs: %v)", iter, successes, errs)
		}

		// Verify exactly one alice→bob grant row
		var grantCount int
		if err := s1.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&grantCount); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: grant count error: %v", iter, err)
		}
		if grantCount != 1 {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: expected exactly 1 grant row, got %d", iter, grantCount)
		}

		// Verify grant created_at is unchanged (skip path preserves it)
		var grantCreatedAt int64
		if err := s1.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&grantCreatedAt); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: grant created_at query error: %v", iter, err)
		}
		if grantCreatedAt != createdAtBefore {
			s1.Close()
			s2.Close()
			t.Errorf("iter %d: grant created_at changed from %d to %d", iter, createdAtBefore, grantCreatedAt)
		}

		// Verify both invites are used
		var used1, used2 interface{}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code1).Scan(&used1); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite1 check error: %v", iter, err)
		}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code2).Scan(&used2); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite2 check error: %v", iter, err)
		}

		if used1 == nil {
			s1.Close()
			s2.Close()
			t.Errorf("iter %d: invite1 not consumed", iter)
		}
		if used2 == nil {
			s1.Close()
			s2.Close()
			t.Errorf("iter %d: invite2 not consumed", iter)
		}

		s1.Close()
		s2.Close()
	}
}

// TestConcurrentAcceptDifferentInvitesDifferentGrants races two accepts of different
// invites with DIFFERENT grants. Exactly one should succeed, the other gets ErrConflict,
// and the loser's invite is left unused (#340).
func TestConcurrentAcceptDifferentInvitesDifferentGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))

	for iter := 0; iter < 50; iter++ {
		dbPath := t.TempDir() + "/test.db"
		s1, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			t.Fatal(err)
		}

		if err := s1.CreatePeer(ctx, "alice", "Alice", "ha", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreatePeer(ctx, "bob", "Bob", "hb", "", ""); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		// Create two invites with DIFFERENT grants
		exp := clk.Now().Add(time.Hour)
		code1 := "code1"
		code2 := "code2"
		if err := s1.CreateInvite(ctx, code1, "alice", []string{"messages"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}
		if err := s1.CreateInvite(ctx, code2, "alice", []string{"bags_read"}, nil, exp); err != nil {
			s1.Close()
			t.Fatal(err)
		}

		s2, err := OpenWithOptions(dbPath, OpenOptions{Clock: clk})
		if err != nil {
			s1.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		results := make(chan error, 2)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s1.AcceptInvite(ctx, code1, "bob", nil, nil)
			results <- err
		}()
		go func() {
			defer wg.Done()
			<-barrier
			_, err := s2.AcceptInvite(ctx, code2, "bob", nil, nil)
			results <- err
		}()

		close(barrier)
		wg.Wait()
		close(results)

		var errs []error
		for e := range results {
			errs = append(errs, e)
		}

		// Assert exactly 1 success and 1 ErrConflict
		successes := 0
		conflicts := 0
		for _, e := range errs {
			if e == nil {
				successes++
			} else if errors.Is(e, ErrConflict) {
				conflicts++
			} else {
				s1.Close()
				s2.Close()
				t.Fatalf("iter %d: unexpected error: %v", iter, e)
			}
		}

		if successes != 1 || conflicts != 1 {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: expected 1 success and 1 conflict with different grants, got %d successes, %d conflicts (errs: %v)", iter, successes, conflicts, errs)
		}

		// Verify exactly one alice→bob grant row
		var grantCount int
		if err := s1.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&grantCount); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: grant count error: %v", iter, err)
		}
		if grantCount != 1 {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: expected exactly 1 grant row, got %d", iter, grantCount)
		}

		// Verify exactly one invite is used (the winner's), one unused (the loser's)
		var used1, used2 interface{}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code1).Scan(&used1); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite1 check error: %v", iter, err)
		}
		if err := s1.db.QueryRow(`SELECT used_by FROM invites WHERE code_hash=?`, code2).Scan(&used2); err != nil {
			s1.Close()
			s2.Close()
			t.Fatalf("iter %d: invite2 check error: %v", iter, err)
		}

		usedCount := 0
		if used1 != nil {
			usedCount++
		}
		if used2 != nil {
			usedCount++
		}

		if usedCount != 1 {
			s1.Close()
			s2.Close()
			t.Errorf("iter %d: expected exactly 1 invite consumed, got %d (used1=%v, used2=%v)", iter, usedCount, used1, used2)
		}

		s1.Close()
		s2.Close()
	}
}

// TestForwardGrantBumpedWhenReverseChanges verifies that when an invite carries
// a forward grant equal to the existing one, but a NEW reverse grant (or changes
// the reverse grant), the forward created_at is bumped. This is intended behavior:
// the accept transaction writes both grants atomically, and the forward grant's
// timestamp reflects the transaction that last touched the pair's grant relationship,
// even if the forward grant content didn't change (#340 P3-b).
func TestForwardGrantBumpedWhenReverseChanges(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(time.Unix(1000000, 0))
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

	// Alice creates first invite with forward grant "messages", no reverse grant from Bob
	exp1 := clk.Now().Add(time.Hour)
	code1 := "code1"
	if err := s.CreateInvite(ctx, code1, "alice", []string{"messages"}, nil, exp1); err != nil {
		t.Fatal(err)
	}
	firstAcceptTime := clk.Now().Unix()
	if _, err := s.AcceptInvite(ctx, code1, "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Read forward grant created_at
	var forwardCreatedAt int64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&forwardCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if forwardCreatedAt != firstAcceptTime {
		t.Fatalf("initial forward grant created_at: got %d, want %d", forwardCreatedAt, firstAcceptTime)
	}

	// Verify no reverse grant exists yet
	var reverseCreatedAt sql.NullInt64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "bob", "alice").Scan(&reverseCreatedAt)
	if err != sql.ErrNoRows {
		t.Fatalf("expected no reverse grant initially, got created_at=%v err=%v", reverseCreatedAt, err)
	}

	// Advance clock
	clk.Advance(10 * time.Minute)
	secondAcceptTime := clk.Now().Unix()

	// Alice creates second invite with SAME forward grant but Bob now sends a reverse grant
	exp2 := clk.Now().Add(time.Hour)
	code2 := "code2"
	if err := s.CreateInvite(ctx, code2, "alice", []string{"messages"}, nil, exp2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, code2, "bob", []string{"bags_write"}, nil); err != nil {
		t.Fatal(err)
	}

	// Read forward grant created_at again - it SHOULD be bumped to secondAcceptTime
	// even though the forward grant content is identical, because the reverse grant is new.
	var newForwardCreatedAt int64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "alice", "bob").Scan(&newForwardCreatedAt)
	if err != nil {
		t.Fatal(err)
	}

	// This is the intended behavior: forward created_at bumps when reverse grant changes.
	if newForwardCreatedAt != secondAcceptTime {
		t.Errorf("forward grant created_at after new reverse grant: got %d, want %d (bumped, not preserved at %d)",
			newForwardCreatedAt, secondAcceptTime, firstAcceptTime)
	}

	// Verify reverse grant now exists with secondAcceptTime
	var reverseCreatedAtAfter int64
	err = s.db.QueryRow(`SELECT created_at FROM grants WHERE owner=? AND grantee=?`, "bob", "alice").Scan(&reverseCreatedAtAfter)
	if err != nil {
		t.Fatalf("reverse grant check error: %v", err)
	}
	if reverseCreatedAtAfter != secondAcceptTime {
		t.Errorf("reverse grant created_at: got %d, want %d", reverseCreatedAtAfter, secondAcceptTime)
	}
}

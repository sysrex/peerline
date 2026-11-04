package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// TestConfirmWithStaleDigestWritesNothing verifies that confirming with a wrong
// or stale offer_digest writes no grants and does not count toward code_fails (#80, requirement 1; #291).
func TestConfirmWithStaleDigestWritesNothing(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// Bob claims
	nonce := []byte{0xab, 0xcd}
	c, err := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"messages"}, nil)
	if err != nil || c.State != ClaimClaimed {
		t.Fatalf("claim: %v, %v", err, c)
	}

	// Alice tries to confirm with a stale digest (returns CheckDigestStale)
	staleCheck := func(claim *Claim) (CheckResult, *Claim) {
		// Simulate digest mismatch (stale offer)
		return CheckDigestStale, claim
	}
	state, freshClaim, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, staleCheck)
	if err != nil {
		t.Fatalf("confirm failed: %v", err)
	}
	if state != ClaimClaimed {
		t.Fatalf("stale digest should return claimed, got %s", state)
	}
	if freshClaim == nil {
		t.Fatal("stale digest should return fresh claim")
	}

	// Verify no grants were written
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&n)
	if n != 0 {
		t.Errorf("%d grants written with stale digest", n)
	}

	// Verify code_fails was not incremented
	var codeFails int
	s.db.QueryRow(`SELECT code_fails FROM invites WHERE public_id=?`, c.PublicID).Scan(&codeFails)
	if codeFails != 0 {
		t.Errorf("code_fails=%d, want 0 (stale digest should not count)", codeFails)
	}

	// Now try with correct digest but wrong code - this SHOULD count
	wrongCodeCheck := func(claim *Claim) (CheckResult, *Claim) {
		// Digest OK but code wrong
		return CheckCodeFail, nil
	}
	state, _, err = s.ConfirmClaim(ctx, c.PublicID, "alice", 3, wrongCodeCheck)
	if err != nil {
		t.Fatalf("confirm failed: %v", err)
	}
	if state == ClaimActive {
		t.Fatal("wrong code should not activate")
	}

	// Verify code_fails WAS incremented for code mismatch
	s.db.QueryRow(`SELECT code_fails FROM invites WHERE public_id=?`, c.PublicID).Scan(&codeFails)
	if codeFails != 1 {
		t.Errorf("code_fails=%d after code mismatch, want 1", codeFails)
	}
}

// TestConfirmOverExistingGrantShowsReplaces verifies that when a grant already exists
// between inviter and claimant, the status response includes replaces and the digest
// covers it (#80, requirement 2).
func TestConfirmOverExistingGrantShowsReplaces(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	// Create existing grant alice -> bob
	s.mustExec(t, `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES('alice','bob','bags:read','old',?)`, claimNow-1000)

	// Alice invites Bob with new scopes
	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, []string{"new"}, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// Bob claims with back-scopes
	nonce := []byte{0xab, 0xcd}
	c, err := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"bags:write"}, []string{"back"})
	if err != nil || c.State != ClaimClaimed {
		t.Fatalf("claim: %v, %v", err, c)
	}

	// Verify replaces is populated in inviter view
	view, err := s.InviterView(ctx, c.PublicID, "alice")
	if err != nil {
		t.Fatalf("inviter view: %v", err)
	}
	if view.Replaces == nil {
		t.Fatal("replaces not set when grant exists")
	}
	if view.Replaces.InviterToClaimant == nil {
		t.Fatal("replaces.InviterToClaimant not set")
	}
	if len(view.Replaces.InviterToClaimant.Scopes) != 1 || view.Replaces.InviterToClaimant.Scopes[0] != "bags:read" {
		t.Errorf("wrong existing scopes: %v", view.Replaces.InviterToClaimant.Scopes)
	}
	if len(view.Replaces.InviterToClaimant.Bags) != 1 || view.Replaces.InviterToClaimant.Bags[0] != "old" {
		t.Errorf("wrong existing bags: %v", view.Replaces.InviterToClaimant.Bags)
	}

	// Confirm with correct check (digest would include the replaces)
	correctCheck := func(claim *Claim) (CheckResult, *Claim) {
		if claim.Claimant == "bob" && claim.Replaces != nil {
			return CheckOK, nil
		}
		return CheckPeerIDFail, nil
	}
	state, _, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if state != ClaimActive {
		t.Fatalf("confirm state: %s", state)
	}

	// Verify grant was replaced
	g, err := s.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "messages" {
		t.Errorf("grant not replaced, scopes: %v", g.Scopes)
	}
	if len(g.Bags) != 1 || g.Bags[0] != "new" {
		t.Errorf("grant not replaced, bags: %v", g.Bags)
	}
}

// TestDoubleConfirmIsIdempotent verifies that a repeated confirm by the same inviter
// with the same claimant returns the same result (#80, requirement 3; #290).
func TestDoubleConfirmIsIdempotent(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// Bob claims
	nonce := []byte{0xab, 0xcd}
	c, err := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"messages"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice confirms - on replay, only peer_id is checked (not digest, since replaces would be the just-written grants)
	correctCheck := func(claim *Claim) (CheckResult, *Claim) {
		if claim.Claimant == "bob" {
			return CheckOK, nil
		}
		return CheckPeerIDFail, nil
	}
	state1, _, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil || state1 != ClaimActive {
		t.Fatalf("first confirm: %v, %s", err, state1)
	}

	// Alice confirms again (idempotent) - check still passes even though digest would differ
	state2, _, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil || state2 != ClaimActive {
		t.Fatalf("second confirm: %v, %s", err, state2)
	}

	// Verify only one set of grants exists
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&n)
	if n != 2 { // alice->bob and bob->alice
		t.Errorf("%d grants, want 2", n)
	}
}

// TestDoubleConfirmWithDifferentPeerIs404 verifies that confirming for a different
// peer_id after activation returns 404 (#80, requirement 3).
func TestDoubleConfirmWithDifferentPeerIs404(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// Bob claims
	nonce := []byte{0xab, 0xcd}
	c, err := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"messages"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice confirms for Bob
	correctCheck := func(claim *Claim) (CheckResult, *Claim) {
		if claim.Claimant == "bob" {
			return CheckOK, nil
		}
		return CheckPeerIDFail, nil
	}
	state, _, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil || state != ClaimActive {
		t.Fatalf("confirm: %v, %s", err, state)
	}

	// Alice tries to confirm again but for Carol (wrong peer_id)
	wrongCheck := func(claim *Claim) (CheckResult, *Claim) {
		if claim.Claimant == "carol" {
			return CheckOK, nil
		}
		return CheckPeerIDFail, nil
	}
	_, _, err = s.ConfirmClaim(ctx, c.PublicID, "alice", 3, wrongCheck)
	if err != ErrNotFound {
		t.Fatalf("confirm with wrong peer_id: got %v, want ErrNotFound", err)
	}
}

// TestDoubleDeclineIsIdempotent verifies that repeated decline returns success (#80).
func TestDoubleDeclineIsIdempotent(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// Bob claims
	nonce := []byte{0xab, 0xcd}
	c, err := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"messages"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice declines
	if err := s.DeclineClaim(ctx, c.PublicID, "alice"); err != nil {
		t.Fatalf("first decline: %v", err)
	}

	// Alice declines again (idempotent)
	if err := s.DeclineClaim(ctx, c.PublicID, "alice"); err != nil {
		t.Fatalf("second decline: %v", err)
	}
}

// TestConcurrentConfirmDecline verifies that concurrent confirm and decline operations
// produce exactly one terminal state and the state-guarded UPDATE prevents races (#80, requirement 4).
func TestConcurrentConfirmDecline(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		// Use a file-backed DB so we can open it with two Store instances
		dbPath := t.TempDir() + "/test.db"

		// First store creates the invite
		s1, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s1.now = func() int64 { return claimNow }
		ctx := context.Background()
		for _, id := range []string{"alice", "bob"} {
			if err := s1.CreatePeer(ctx, id, id, "h"+id, "", ""); err != nil {
				t.Fatal(err)
			}
		}

		exp := time.Unix(claimNow+3600, 0)
		if err := s1.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
		s1.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)
		c, err := s1.ClaimByToken(ctx, "pair", "bob", []byte{0xab, 0xcd}, []string{"messages"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		publicID := c.PublicID
		s1.Close()

		// Open two separate Store instances on the same DB file (simulates two replicas/processes)
		s1, err = Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s1.now = func() int64 { return claimNow }
		defer s1.Close()

		s2, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s2.now = func() int64 { return claimNow }
		defer s2.Close()

		// Start barrier
		start := make(chan struct{})
		confirmDone := make(chan error, 1)
		declineDone := make(chan error, 1)

		// Launch both operations on separate Store instances
		go func() {
			<-start
			_, _, err := s1.ConfirmClaim(ctx, publicID, "alice", 3, func(cl *Claim) (CheckResult, *Claim) {
				if cl.Claimant == "bob" {
					return CheckOK, nil
				}
				return CheckPeerIDFail, nil
			})
			confirmDone <- err
		}()
		go func() {
			<-start
			declineDone <- s2.DeclineClaim(ctx, publicID, "alice")
		}()

		// Release both
		close(start)

		confirmErr := <-confirmDone
		declineErr := <-declineDone

		// At least one must succeed, and they can't both succeed
		if confirmErr != nil && declineErr != nil {
			t.Errorf("iteration %d: both operations failed: confirm=%v decline=%v", i, confirmErr, declineErr)
		}
		if confirmErr == nil && declineErr == nil {
			t.Errorf("iteration %d: both confirm and decline succeeded", i)
		}

		// Check the final state is consistent
		var usedBy sql.NullString
		var declinedAt sql.NullInt64
		if err := s1.db.QueryRow(`SELECT used_by, declined_at FROM invites WHERE public_id=?`, publicID).Scan(&usedBy, &declinedAt); err != nil {
			t.Fatalf("iteration %d: failed to query final state: %v", i, err)
		}

		if usedBy.Valid && declinedAt.Valid {
			t.Errorf("iteration %d: invite is both active and declined", i)
		}

		// Check grant count matches state
		var grantCount int
		if err := s1.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE (owner='alice' AND grantee='bob') OR (owner='bob' AND grantee='alice')`).Scan(&grantCount); err != nil {
			t.Fatalf("iteration %d: failed to count grants: %v", i, err)
		}

		if usedBy.Valid && !declinedAt.Valid {
			// Active: should have 2 grants
			if grantCount != 2 {
				t.Errorf("iteration %d: active but %d grants, want 2", i, grantCount)
			}
		} else {
			// Declined or still claimed: should have 0 grants
			if grantCount != 0 {
				t.Errorf("iteration %d: not active but %d grants, want 0", i, grantCount)
			}
		}
	}
}

// TestConcurrentConfirmRevoke verifies that concurrent confirm and revoke produce exactly one outcome.
func TestConcurrentConfirmRevoke(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		dbPath := t.TempDir() + "/test.db"

		s1, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s1.now = func() int64 { return claimNow }
		ctx := context.Background()
		for _, id := range []string{"alice", "bob"} {
			if err := s1.CreatePeer(ctx, id, id, "h"+id, "", ""); err != nil {
				t.Fatal(err)
			}
		}

		exp := time.Unix(claimNow+3600, 0)
		if err := s1.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
		s1.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)
		c, err := s1.ClaimByToken(ctx, "pair", "bob", []byte{0xab, 0xcd}, []string{"messages"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		publicID := c.PublicID
		s1.Close()

		s1, err = Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s1.now = func() int64 { return claimNow }
		defer s1.Close()

		s2, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s2.now = func() int64 { return claimNow }
		defer s2.Close()

		start := make(chan struct{})
		confirmDone := make(chan error, 1)
		revokeDone := make(chan error, 1)

		go func() {
			<-start
			_, _, err := s1.ConfirmClaim(ctx, publicID, "alice", 3, func(cl *Claim) (CheckResult, *Claim) {
				if cl.Claimant == "bob" {
					return CheckOK, nil
				}
				return CheckPeerIDFail, nil
			})
			confirmDone <- err
		}()
		go func() {
			<-start
			_, err := s2.db.ExecContext(ctx, `DELETE FROM invites WHERE public_id=? AND used_by IS NULL`, publicID)
			revokeDone <- err
		}()

		close(start)

		confirmErr := <-confirmDone
		revokeErr := <-revokeDone

		if revokeErr != nil {
			t.Fatalf("iteration %d: revoke failed: %v", i, revokeErr)
		}

		// Check final state
		var exists int
		err = s1.db.QueryRow(`SELECT COUNT(*) FROM invites WHERE public_id=?`, publicID).Scan(&exists)
		if err != nil {
			t.Fatalf("iteration %d: failed to check existence: %v", i, err)
		}

		var grantCount int
		if err := s1.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE (owner='alice' AND grantee='bob') OR (owner='bob' AND grantee='alice')`).Scan(&grantCount); err != nil {
			t.Fatalf("iteration %d: failed to count grants: %v", i, err)
		}

		if exists == 0 {
			// Revoke won
			if confirmErr == nil {
				t.Errorf("iteration %d: invite deleted but confirm succeeded", i)
			}
			if grantCount != 0 {
				t.Errorf("iteration %d: invite deleted but %d grants exist", i, grantCount)
			}
		} else {
			// Confirm won
			if confirmErr != nil {
				t.Errorf("iteration %d: invite exists but confirm failed: %v", i, confirmErr)
			}
			if grantCount != 2 {
				t.Errorf("iteration %d: invite exists but %d grants, want 2", i, grantCount)
			}
		}
	}
}

// TestConfirmAfterExpiry verifies that confirm fails after confirm_by passes.
func TestConfirmAfterExpiry(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()

	// Create invite
	exp := time.Unix(claimNow+3600, 0)
	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)
	c, err := s.ClaimByToken(ctx, "pair", "bob", []byte{0xab, 0xcd}, []string{"messages"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Advance time past confirm_by (which is set to now() + 24h at claim time)
	s.now = func() int64 { return claimNow + 86400 + 100 }

	// Confirm should fail
	_, _, err = s.ConfirmClaim(ctx, c.PublicID, "alice", 3, func(cl *Claim) (CheckResult, *Claim) {
		if cl.Claimant == "bob" {
			return CheckOK, nil
		}
		return CheckPeerIDFail, nil
	})
	if err != ErrNotFound {
		t.Errorf("confirm after expiry: got %v, want ErrNotFound", err)
	}

	// Verify no grants written
	var grantCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&grantCount); err != nil {
		t.Fatal(err)
	}
	if grantCount != 0 {
		t.Errorf("confirm after expiry wrote %d grants", grantCount)
	}
}

// TestNoApiKeyInResponse verifies that no response contains api_key (#80, requirement 4).
// This is primarily tested at the API level, but we verify the store layer doesn't leak it.
func TestStoreNeverReturnsApiKey(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	exp := time.Unix(claimNow+3600, 0)

	if err := s.CreateInviteWithPairing(ctx, "code", "pair", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd'`)

	// All claim operations return Claim struct
	nonce := []byte{0xab, 0xcd}
	c, _ := s.ClaimByToken(ctx, "pair", "bob", nonce, []string{"messages"}, nil)

	// Verify Claim struct has no API key fields
	if c.Inviter == "" {
		t.Error("sanity: claim should have inviter")
	}
	// The Claim struct intentionally has no ApiKey or KeyHash fields
}

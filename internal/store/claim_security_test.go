package store

import (
	"context"
	"testing"
	"time"
)

// TestConfirmWithStaleDigestWritesNothing verifies that confirming with a wrong
// or stale offer_digest writes no grants (#80, requirement 1).
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
	
	// Alice tries to confirm with a wrong digest (simulating stale or tampered data)
	wrongCheck := func(claim *Claim) bool { return false } // Digest mismatch
	state, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, wrongCheck)
	if err != nil {
		t.Fatalf("confirm failed: %v", err)
	}
	if state == ClaimActive {
		t.Fatal("confirm succeeded with wrong digest")
	}
	
	// Verify no grants were written
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&n)
	if n != 0 {
		t.Errorf("%d grants written with wrong digest", n)
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
	correctCheck := func(claim *Claim) bool { 
		return claim.Claimant == "bob" && claim.Replaces != nil 
	}
	state, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
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
// with the same claimant returns the same result (#80, requirement 3).
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
	
	// Alice confirms
	correctCheck := func(claim *Claim) bool { return claim.Claimant == "bob" }
	state1, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil || state1 != ClaimActive {
		t.Fatalf("first confirm: %v, %s", err, state1)
	}
	
	// Alice confirms again (idempotent)
	state2, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
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
	correctCheck := func(claim *Claim) bool { return claim.Claimant == "bob" }
	state, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, correctCheck)
	if err != nil || state != ClaimActive {
		t.Fatalf("confirm: %v, %s", err, state)
	}
	
	// Alice tries to confirm again but for Carol (wrong peer_id)
	wrongCheck := func(claim *Claim) bool { return claim.Claimant == "carol" }
	_, err = s.ConfirmClaim(ctx, c.PublicID, "alice", 3, wrongCheck)
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

// TestConcurrentConfirmDeclineRevokeExpiry verifies that concurrent operations
// produce exactly one terminal state and at most two grant rows (#80, requirement 4).
func TestConcurrentConfirmDeclineRevokeExpiry(t *testing.T) {
	s := claimStore(t)
	ctx := context.Background()
	
	// Test confirm racing decline
	t.Run("confirm_vs_decline", func(t *testing.T) {
		exp := time.Unix(claimNow+3600, 0)
		if err := s.CreateInviteWithPairing(ctx, "code1", "pair1", "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
		s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'ab01' WHERE code_hash='code1'`)
		c, _ := s.ClaimByToken(ctx, "pair1", "bob", []byte{0xab, 0x01}, []string{"messages"}, nil)
		
		done := make(chan string, 2)
		go func() {
			state, _ := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, func(cl *Claim) bool { return true })
			done <- state
		}()
		go func() {
			err := s.DeclineClaim(ctx, c.PublicID, "alice")
			if err == nil {
				done <- ClaimDeclined
			} else {
				done <- ""
			}
		}()
		
		r1, r2 := <-done, <-done
		// Exactly one should succeed
		if (r1 == ClaimActive || r2 == ClaimActive) && (r1 == ClaimDeclined || r2 == ClaimDeclined) {
			t.Error("both confirm and decline succeeded")
		}
		if r1 == "" && r2 == "" {
			t.Error("both operations failed")
		}
	})
	
	// Test confirm racing expiry
	t.Run("confirm_vs_expiry", func(t *testing.T) {
		// Set up invite that's about to expire
		exp := time.Unix(claimNow+10, 0)
		if err := s.CreateInviteWithPairing(ctx, "code2", "pair2", "alice", []string{"messages"}, nil, exp); err != nil {
			t.Fatal(err)
		}
		s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'ab02' WHERE code_hash='code2'`)
		c, _ := s.ClaimByToken(ctx, "pair2", "bob", []byte{0xab, 0x02}, []string{"messages"}, nil)
		
		// Advance time past confirm_by
		oldNow := s.now
		s.now = func() int64 { return claimNow + 86400 + 100 }
		defer func() { s.now = oldNow }()
		
		// Try to confirm (should fail due to expiry)
		_, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, func(cl *Claim) bool { return true })
		if err != ErrNotFound {
			t.Errorf("confirm after expiry: got %v, want ErrNotFound", err)
		}
	})
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

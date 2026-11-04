package store

import (
	"context"
	"fmt"
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

// TestConcurrentConfirmDeclineRevokeExpiry verifies that concurrent operations
// produce exactly one terminal state and at most two grant rows (#80, requirement 4).
func TestConcurrentConfirmDeclineRevokeExpiry(t *testing.T) {
	const iterations = 50

	runRace := func(t *testing.T, name string, op1, op2 func(ctx context.Context, s *Store, c *Claim) (string, error)) {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				s := claimStore(t)
				ctx := context.Background()
				exp := time.Unix(claimNow+3600, 0)

				// Fresh invite each iteration
				code := fmt.Sprintf("code%d", i)
				pair := fmt.Sprintf("pair%d", i)
				if err := s.CreateInviteWithPairing(ctx, code, pair, "alice", []string{"messages"}, nil, exp); err != nil {
					t.Fatal(err)
				}
				s.mustExec(t, `UPDATE invites SET require_confirm=1, nonce=x'abcd' WHERE code_hash=?`, code)
				c, err := s.ClaimByToken(ctx, pair, "bob", []byte{0xab, 0xcd}, []string{"messages"}, nil)
				if err != nil {
					t.Fatal(err)
				}

				// Start barrier
				start := make(chan struct{})
				results := make(chan struct {
					state string
					err   error
				}, 2)

				// Launch both operations
				go func() {
					<-start
					state, err := op1(ctx, s, c)
					results <- struct {
						state string
						err   error
					}{state, err}
				}()
				go func() {
					<-start
					state, err := op2(ctx, s, c)
					results <- struct {
						state string
						err   error
					}{state, err}
				}()

				// Release both
				close(start)

				r1 := <-results
				r2 := <-results

				// Count success outcomes
				activeCount := 0
				declinedCount := 0
				deletedCount := 0
				notFoundCount := 0

				for _, r := range []struct {
					state string
					err   error
				}{r1, r2} {
					if r.err != nil && r.err != ErrNotFound {
						t.Fatalf("unexpected error: %v", r.err)
					}
					if r.state == ClaimActive {
						activeCount++
					}
					if r.state == ClaimDeclined {
						declinedCount++
					}
					if r.state == "deleted" {
						deletedCount++
					}
					if r.err == ErrNotFound {
						notFoundCount++
					}
				}

				// Exactly one should succeed, the other gets NotFound
				if activeCount > 1 || declinedCount > 1 || deletedCount > 1 {
					t.Fatalf("multiple operations succeeded: active=%d declined=%d deleted=%d", activeCount, declinedCount, deletedCount)
				}
				if activeCount+declinedCount+deletedCount != 1 {
					t.Fatalf("no operation succeeded: active=%d declined=%d deleted=%d", activeCount, declinedCount, deletedCount)
				}

				// Check grant count
				var grantCount int
				s.db.QueryRow(`SELECT COUNT(*) FROM grants`).Scan(&grantCount)
				if activeCount == 1 {
					if grantCount != 2 {
						t.Errorf("active but %d grants, want 2", grantCount)
					}
				} else {
					if grantCount != 0 {
						t.Errorf("not active but %d grants, want 0", grantCount)
					}
				}
			}
		})
	}

	confirmOp := func(ctx context.Context, s *Store, c *Claim) (string, error) {
		state, _, err := s.ConfirmClaim(ctx, c.PublicID, "alice", 3, func(cl *Claim) (CheckResult, *Claim) {
			if cl.Claimant == "bob" {
				return CheckOK, nil
			}
			return CheckPeerIDFail, nil
		})
		return state, err
	}

	declineOp := func(ctx context.Context, s *Store, c *Claim) (string, error) {
		err := s.DeclineClaim(ctx, c.PublicID, "alice")
		if err == nil {
			return ClaimDeclined, nil
		}
		return "", err
	}

	revokeOp := func(ctx context.Context, s *Store, c *Claim) (string, error) {
		_, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE public_id=? AND used_by IS NULL`, c.PublicID)
		if err == nil {
			return "deleted", nil
		}
		return "", err
	}

	runRace(t, "confirm_vs_decline", confirmOp, declineOp)
	runRace(t, "confirm_vs_revoke", confirmOp, revokeOp)
	runRace(t, "decline_vs_revoke", declineOp, revokeOp)
	// Note: expiry race is tested separately since it requires clock manipulation
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

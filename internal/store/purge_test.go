package store

import (
	"context"
	"testing"
	"time"
)

// TestPurgeExpiredInvites_GrantsAndPeersSurvive verifies that grants and peers
// are not affected by purging invites.
func TestPurgeExpiredInvites_GrantsAndPeersSurvive(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create peers
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", ""); err != nil {
		t.Fatal(err)
	}

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(2000000)
	
	// Create and accept an invite in the past, with an expiry that's now beyond retention
	// Used invites are purged when expires_at < now - retention (30 days default)
	// So we need expires_at to be at least 31 days ago
	thirtyOneDaysAgo := currentTime - 31*24*60*60
	
	// Go back in time to create and accept the invite
	s.now = func() int64 { return thirtyOneDaysAgo - 100 }
	
	// Create invite that expires at thirtyOneDaysAgo
	exp := time.Unix(thirtyOneDaysAgo, 0)
	if err := s.CreateInvite(ctx, "code1", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	grant, err := s.AcceptInvite(ctx, "code1", "bob", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Move to current time (invite is now expired and beyond retention)
	s.now = func() int64 { return currentTime }

	// Purge expired invites with default retention (30 days)
	count, err := s.PurgeExpiredInvites(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged invite, got %d", count)
	}

	// Verify peers still exist
	var peerCount int
	row := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM peers")
	if err := row.Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 2 {
		t.Errorf("expected 2 peers, got %d", peerCount)
	}

	// Verify grant still exists
	if grant != nil {
		var exists bool
		row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM grants WHERE owner = ? AND grantee = ?)", grant.Owner, grant.Grantee)
		if err := row.Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("grant from %s to %s was deleted during purge", grant.Owner, grant.Grantee)
		}
	}
}

// TestPurgeExpiredInvites_RetentionDefault verifies that retentionSeconds <= 0
// uses the 30-day default.
func TestPurgeExpiredInvites_RetentionDefault(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create peers
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", ""); err != nil {
		t.Fatal(err)
	}

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(3000000)

	// Create a used invite that expired 29 days ago (within 30-day default)
	twentyNineDaysAgo := currentTime - 29*24*60*60
	exp := time.Unix(twentyNineDaysAgo, 0)
	s.now = func() int64 { return twentyNineDaysAgo - 100 }
	if err := s.CreateInvite(ctx, "code1", "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code1", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Create a used invite that expired 31 days ago (beyond 30-day default)
	thirtyOneDaysAgo := currentTime - 31*24*60*60
	exp2 := time.Unix(thirtyOneDaysAgo, 0)
	s.now = func() int64 { return thirtyOneDaysAgo - 100 }
	if err := s.CreateInvite(ctx, "code2", "alice", []string{"messages"}, nil, exp2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "code2", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	
	// Move to current time
	s.now = func() int64 { return currentTime }

	// Purge with retentionSeconds = 0 (should use 30-day default)
	count, err := s.PurgeExpiredInvites(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged invite, got %d", count)
	}

	// Verify the 29-day-old invite still exists
	var exists bool
	row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invites WHERE code_hash = ?)", "code1")
	if err := row.Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("29-day-old invite was purged but should be kept")
	}
}

// TestPurgeExpiredInvites_ExactCutoffBoundary verifies that the purge correctly
// handles invites exactly at the cutoff boundaries.
func TestPurgeExpiredInvites_ExactCutoffBoundary(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create peers
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "bob", "Bob", "hb", ""); err != nil {
		t.Fatal(err)
	}

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(4000000)
	s.now = func() int64 { return currentTime }

	// Test unused invites with 5-minute (300s) grace window
	// Grace cutoff is currentTime - 300
	// Unused invites are purged if expires_at < graceCutoff (strict <, not <=)

	// Expired exactly 300s ago (at grace boundary) - should NOT be purged (< not <=)
	expAtGrace := time.Unix(currentTime-300, 0)
	if err := s.CreateInvite(ctx, "grace-at", "alice", []string{"messages"}, nil, expAtGrace); err != nil {
		t.Fatal(err)
	}

	// Expired 299s ago (within grace, not purged yet)
	expWithinGrace := time.Unix(currentTime-299, 0)
	if err := s.CreateInvite(ctx, "grace-within", "alice", []string{"messages"}, nil, expWithinGrace); err != nil {
		t.Fatal(err)
	}

	// Expired 301s ago (beyond grace) - should be purged
	expBeyondGrace := time.Unix(currentTime-301, 0)
	if err := s.CreateInvite(ctx, "grace-beyond", "alice", []string{"messages"}, nil, expBeyondGrace); err != nil {
		t.Fatal(err)
	}

	// Test used invites with retention boundary (7 days for this test)
	retention := int64(7 * 24 * 60 * 60)

	// Used invite expired exactly retention ago (at boundary) - should NOT be purged (< not <=)
	sevenDaysAgo := currentTime - retention
	expAtRetention := time.Unix(sevenDaysAgo, 0)
	s.now = func() int64 { return sevenDaysAgo - 100 }
	if err := s.CreateInvite(ctx, "ret-at", "alice", []string{"messages"}, nil, expAtRetention); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "ret-at", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Used invite expired (retention - 1) ago (within retention) - should be kept
	expWithinRetention := time.Unix(currentTime-retention+1, 0)
	s.now = func() int64 { return currentTime - retention - 100 }
	if err := s.CreateInvite(ctx, "ret-within", "alice", []string{"messages"}, nil, expWithinRetention); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "ret-within", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	
	// Used invite expired (retention + 1) ago (beyond retention) - should be purged
	expBeyondRetention := time.Unix(currentTime-retention-1, 0)
	s.now = func() int64 { return currentTime - retention - 200 }
	if err := s.CreateInvite(ctx, "ret-beyond", "alice", []string{"messages"}, nil, expBeyondRetention); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "ret-beyond", "bob", nil, nil); err != nil {
		t.Fatal(err)
	}
	
	// Return to current time
	s.now = func() int64 { return currentTime }

	// Debug: check what we have before purge
	var inviteCount int
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM invites").Scan(&inviteCount)
	t.Logf("Before purge: %d invites", inviteCount)

	// Purge with 7-day retention
	count, err := s.PurgeExpiredInvites(ctx, retention)
	if err != nil {
		t.Fatal(err)
	}
	
	// Debug: check what remains after purge
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM invites").Scan(&inviteCount)
	t.Logf("After purge: %d invites remain, %d were purged", inviteCount, count)
	
	// Should purge: grace-beyond, ret-beyond = 2 invites
	if count != 2 {
		t.Errorf("expected 2 purged invites, got %d", count)
	}

	// Verify the invites at and within boundaries still exist
	var exists bool
	
	// grace-at should exist (at boundary, not purged)
	row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invites WHERE code_hash = ?)", "grace-at")
	if err := row.Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("invite at grace boundary was purged")
	}
	
	// grace-within should exist
	row = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invites WHERE code_hash = ?)", "grace-within")
	if err := row.Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("invite within grace was purged")
	}

	// ret-at should exist (at boundary, not purged)
	row = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invites WHERE code_hash = ?)", "ret-at")
	if err := row.Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("invite at retention boundary was purged")
	}

	// ret-within should exist
	row = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invites WHERE code_hash = ?)", "ret-within")
	if err := row.Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("invite within retention was purged")
	}
}

// TestPurgeExpiredInvites_MultiBatch verifies that the purge handles
// more than 500 rows correctly across multiple batches.
func TestPurgeExpiredInvites_MultiBatch(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create a peer
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(5000000)
	s.now = func() int64 { return currentTime }

	// Create 1000 expired invites (expired more than 5 minutes ago to exceed grace)
	expiredTime := time.Unix(currentTime-1000, 0)
	for i := 0; i < 1000; i++ {
		code := []byte("expired-code-")
		code = append(code, byte('a'+i%26), byte('0'+i/26%10), byte('0'+i/260))
		if err := s.CreateInvite(ctx, string(code), "alice", []string{"messages"}, nil, expiredTime); err != nil {
			t.Fatal(err)
		}
	}

	// Create 10 unexpired invites (should not be purged)
	unexpiredTime := time.Unix(currentTime+1000, 0)
	for i := 0; i < 10; i++ {
		code := []byte("future-code-")
		code = append(code, byte('a'+i%26))
		if err := s.CreateInvite(ctx, string(code), "alice", []string{"messages"}, nil, unexpiredTime); err != nil {
			t.Fatal(err)
		}
	}

	// Purge
	count, err := s.PurgeExpiredInvites(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1000 {
		t.Errorf("expected 1000 purged invites, got %d", count)
	}

	// Verify unexpired invites still exist
	var remaining int
	row := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM invites")
	if err := row.Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 10 {
		t.Errorf("expected 10 remaining invites, got %d", remaining)
	}
}

// TestPurgeExpiredInvites_CancelledContext verifies that the purge stops
// cleanly when the context is cancelled.
func TestPurgeExpiredInvites_CancelledContext(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create a peer
	ctx := context.Background()
	if err := s.CreatePeer(ctx, "alice", "Alice", "ha", ""); err != nil {
		t.Fatal(err)
	}

	// Mock time
	origNow := s.now
	defer func() { s.now = origNow }()

	currentTime := int64(6000000)
	s.now = func() int64 { return currentTime }

	// Create many expired invites
	expiredTime := time.Unix(currentTime-1000, 0)
	for i := 0; i < 1000; i++ {
		code := []byte("cancel-code-")
		code = append(code, byte('a'+i%26), byte('0'+i/26%10), byte('0'+i/260))
		if err := s.CreateInvite(ctx, string(code), "alice", []string{"messages"}, nil, expiredTime); err != nil {
			t.Fatal(err)
		}
	}

	// Create a context that's already cancelled
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to purge with cancelled context
	count, err := s.PurgeExpiredInvites(cancelledCtx, 0)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}

	// The count might be 0 or some partial amount depending on when the check happens
	if count > 500 {
		t.Errorf("expected partial purge (0-500), got %d", count)
	}
}

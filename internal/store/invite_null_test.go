package store

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/auth"
)

// TestNullPublicIDRowSkipped verifies that ListInvitesByPeer skips invite
// rows with public_id NULL (created by an older binary after the v3 migration,
// or during a blue/green deployment overlap). This closes the gap from issue #66.
func TestNullPublicIDRowSkipped(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()

	// Register a peer
	peerID := "p_testpeer123"
	keyHash := auth.Hash("test-key")
	if err := st.CreatePeer(ctx, peerID, "TestPeer", keyHash, "", ""); err != nil {
		t.Fatal(err)
	}

	// Create a normal invite (with public_id)
	normalCode := auth.NewSecret("inv_")
	scopes := []string{"messages"}
	bags := []string{}
	expires := time.Now().Add(1 * time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(normalCode), peerID, scopes, bags, expires); err != nil {
		t.Fatal(err)
	}

	// Insert an invite with NULL public_id via raw SQL (simulating old binary)
	nullInviteCode := auth.Hash(auth.NewSecret("inv_"))
	_, err = st.db.ExecContext(ctx,
		`INSERT INTO invites(code_hash, from_peer, scopes, bags, expires_at, public_id) VALUES(?, ?, ?, ?, ?, NULL)`,
		nullInviteCode, peerID, "messages", "", expires.Unix())
	if err != nil {
		t.Fatal(err)
	}

	// Verify that ListInvitesByPeer skips the NULL row and returns the normal one
	invites, err := st.ListInvitesByPeer(ctx, peerID, 50, 0)
	if err != nil {
		t.Fatalf("ListInvitesByPeer failed: %v", err)
	}

	// Should return only the normal invite (NULL row is skipped)
	if len(invites) != 1 {
		t.Errorf("expected 1 invite (NULL skipped), got %d", len(invites))
	}

	// Verify the returned invite has a non-empty public_id
	if len(invites) > 0 && invites[0].PublicID == "" {
		t.Errorf("invite has empty public_id")
	}
}

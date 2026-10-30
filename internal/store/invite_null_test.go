package store

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/auth"
)

// TestPublicIDNotNull verifies that v5 makes public_id NOT NULL with a default, so an older
// binary's insert (no public_id column) still gets an id and an explicit NULL is refused (#66, #77).
func TestPublicIDNotNull(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	peerID := "p_testpeer123"
	if err := st.CreatePeer(ctx, peerID, "TestPeer", auth.Hash("test-key"), "", ""); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO invites(code_hash, from_peer, scopes, bags, expires_at, public_id) VALUES('h1', ?, 'messages', '', ?, NULL)`,
		peerID, exp); err == nil {
		t.Fatal("NULL public_id accepted")
	}
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO invites(code_hash, from_peer, scopes, bags, expires_at) VALUES('h2', ?, 'messages', '', ?)`,
		peerID, exp); err != nil {
		t.Fatal(err)
	}
	invites, err := st.ListInvitesByPeer(ctx, peerID, 50, 0)
	if err != nil || len(invites) != 1 || invites[0].PublicID == "" {
		t.Fatalf("want one invite with default public_id, got %v %v", invites, err)
	}
}

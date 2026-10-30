package store

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/auth"
)

// A NULL public_id row (older binary after the v3 step) gets an id on the next Open,
// so it is listed and can be revoked (#66, #67).
func TestNullPublicIDBackfilledOnOpen(t *testing.T) {
	path := t.TempDir() + "/test.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.CreatePeer(ctx, "p_testpeer123", "TestPeer", auth.Hash("k"), "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO invites(code_hash, from_peer, scopes, bags, expires_at, public_id) VALUES('h', 'p_testpeer123', 'messages', '', ?, NULL)`,
		time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	invites, err := st.ListInvitesByPeer(ctx, "p_testpeer123", 50, 0)
	if err != nil || len(invites) != 1 || invites[0].PublicID == "" {
		t.Fatalf("list after reopen: %v %+v", err, invites)
	}
	if err := st.DeleteInvite(ctx, invites[0].PublicID, "p_testpeer123"); err != nil {
		t.Fatalf("revoke backfilled invite: %v", err)
	}
}

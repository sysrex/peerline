package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestAuditHooksOneRecordAndRollback(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := openSignedAudit(t, priv)
	ctx := t.Context()
	if err := s.CreatePeer(ctx, "p_alice", "alice", "hash-alice", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "p_bob", "bob", "hash-bob", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{From: "p_alice", To: "p_bob", Type: "note", Body: "hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBag(ctx, "p_alice", "secret-bag", []byte("bytes"), "p_alice", -1, 10, 1<<20); err != nil {
		t.Fatal(err)
	}
	exp := time.Unix(1_800_000_000, 0)
	id, err := s.CreateInviteAtomic(ctx, "code-hash", "p_alice", []string{"messages"}, []string{"secret-bag"}, exp, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteInvite(ctx, id, "p_alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES('p_alice','p_bob','messages','',1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeGrant(ctx, "p_alice", "p_bob"); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateKey(ctx, "p_alice", "newhashvalue"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer(ctx, "p_bob"); err != nil {
		t.Fatal(err)
	}

	rows, err := s.db.Query(`SELECT event_type FROM audit_records ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	want := []string{"message.sent", "bag.put", "invite.created", "invite.revoked", "grant.revoked", "key.rotated", "peer.deleted"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v", got)
	}

	leaf, err := messageLeaf(&Message{From: "p_alice", To: "p_bob", Type: "note", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(leaf, []byte("p_alice")) || bytes.Contains(leaf, []byte("secret-bag")) {
		t.Fatalf("leaf leaked an id: %s", leaf)
	}
	bag, err := bagLeaf(2, []byte("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bag, []byte("secret-bag")) || bytes.Contains(bag, []byte("p_alice")) {
		t.Fatalf("bag leaf leaked: %s", bag)
	}

	s.auditFail = func() error { return errors.New("injected") }
	before := len(got)
	err = s.InsertMessage(ctx, &Message{From: "p_alice", To: "p_alice", Type: "note", Body: "nope"})
	if err == nil {
		t.Fatal("expected fail-closed")
	}
	var messages, records int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE body='nope'`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if messages != 0 || records != before {
		t.Fatalf("rollback messages=%d records=%d", messages, records)
	}
}

func TestAuditHooksDisabledSkip(t *testing.T) {
	s := openAuditStore(t, false, clocktest.New(time.Unix(1_700_000_000, 0)))
	if err := s.CreatePeer(t.Context(), "p1", "a", "h", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(t.Context(), &Message{From: "p1", To: "p1", Type: "note", Body: "x"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("disabled wrote %d", n)
	}
}

func openSignedAudit(t *testing.T, priv ed25519.PrivateKey) *Store {
	t.Helper()
	s, err := OpenWithOptions(":memory:", OpenOptions{
		Clock:         clocktest.New(time.Unix(1_700_000_000, 0)),
		AuditEnabled:  true,
		AuditSigner:   priv,
		AuditInstance: "peerline.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

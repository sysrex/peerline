package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStoreBasics(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePeer(ctx, "a", "alice", "ha"); err != nil {
		t.Fatal(err)
	}
	s.CreatePeer(ctx, "b", "bob", "hb")
	if p, err := s.PeerByKeyHash(ctx, "ha"); err != nil || p.ID != "a" {
		t.Fatal(p, err)
	}
	if _, err := s.GetGrant(ctx, "a", "b"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected deny")
	}
	s.CreateInvite(ctx, "c1", "a", []string{"messages"}, nil, time.Now().Add(-time.Minute))
	if _, err := s.AcceptInvite(ctx, "c1", "b", nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invite accepted")
	}
	if v, err := s.PutBag(ctx, "a", "n", []byte("x"), "a", 0); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if _, err := s.PutBag(ctx, "a", "n", []byte("y"), "a", 0); !errors.Is(err, ErrConflict) {
		t.Fatal("expected conflict")
	}
}

func TestStats(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Stats(ctx)
	if err != nil || st != (Stats{}) {
		t.Fatalf("empty: %+v %v", st, err)
	}
	if err := s.CreatePeer(ctx, "a", "alice", "ha"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePeer(ctx, "b", "bob", "hb"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvite(ctx, "c2", "a", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptInvite(ctx, "c2", "b", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertMessage(ctx, &Message{From: "b", To: "a", Type: "note", Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBag(ctx, "a", "status", []byte("ok"), "a", -1); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Peers != 2 || st.Messages != 1 || st.Grants != 1 || st.Bags != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

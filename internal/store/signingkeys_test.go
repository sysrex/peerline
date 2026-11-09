package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestSigningKeyWindowCapAndChain(t *testing.T) {
	clk := clocktest.New(time.Unix(1_700_000_000, 0))
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pub := bytes.Repeat([]byte{7}, 32)
	from := clk.Now().Unix()
	if err := s.RegisterSigningKey(t.Context(), "p1", "k1", pub, from, from+100); err != nil {
		t.Fatal(err)
	}
	ok, err := s.SigningKeyUsable(t.Context(), "p1", "k1", from-1)
	if err != nil || ok {
		t.Fatalf("before window: ok=%v err=%v", ok, err)
	}
	ok, err = s.SigningKeyUsable(t.Context(), "p1", "k1", from)
	if err != nil || !ok {
		t.Fatalf("inside window: ok=%v err=%v", ok, err)
	}
	ok, err = s.SigningKeyUsable(t.Context(), "p1", "k1", from+100)
	if err != nil || ok {
		t.Fatalf("at valid_to: ok=%v err=%v", ok, err)
	}
	for i := 0; i < 4; i++ {
		kid := "k" + string(rune('2'+i))
		if err := s.RegisterSigningKey(t.Context(), "p1", kid, bytes.Repeat([]byte{byte(8 + i)}, 32), from, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RegisterSigningKey(t.Context(), "p1", "overflow", bytes.Repeat([]byte{9}, 32), from, 0); err != ErrTooManySigningKeys {
		t.Fatalf("cap: %v", err)
	}
	if err := s.RevokeSigningKey(t.Context(), "p1", "k1", from+1); err != nil {
		t.Fatal(err)
	}
	ok, err = s.SigningKeyUsable(t.Context(), "p1", "k1", from+1)
	if err != nil || ok {
		t.Fatalf("revoked: ok=%v err=%v", ok, err)
	}
	log, err := s.SigningKeyAuditLog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 6 {
		t.Fatalf("audit rows: %d", len(log))
	}
	var prev []byte
	for i, row := range log {
		if i == 0 {
			prev = make([]byte, 32)
		}
		if !bytes.Equal(row.PrevHash, prev) {
			t.Fatalf("row %d prev hash", i)
		}
		want := signingKeyRecordHash(row.PrevHash, row.EventType, row.PeerID, row.KID, row.PubkeyHash, row.CreatedAt)
		if !bytes.Equal(row.RecordHash, want) {
			t.Fatalf("row %d record hash", i)
		}
		prev = row.RecordHash
	}
	if log[0].EventType != signingKeyRegistered || log[len(log)-1].EventType != signingKeyRevoked {
		t.Fatalf("events: %s .. %s", log[0].EventType, log[len(log)-1].EventType)
	}
}

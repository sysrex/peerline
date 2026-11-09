package store

import (
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestAuditRetentionDaysFloor(t *testing.T) {
	if n, err := AuditRetentionDays(""); err != nil || n != 183 {
		t.Fatalf("default %d %v", n, err)
	}
	if _, err := AuditRetentionDays("182"); err == nil {
		t.Fatal("182 accepted")
	}
	if n, err := AuditRetentionDays("183"); err != nil || n != 183 {
		t.Fatalf("183 %d %v", n, err)
	}
}

func TestAuditRetentionKeepsUnanchoredAndHeld(t *testing.T) {
	clk := clocktest.New(time.Unix(1_800_000_000, 0))
	s := openAuditStore(t, true, clk)
	old := clk.Now().Add(-200 * 24 * time.Hour).UnixMilli()
	keep := func(label string, batch, anchored any) string {
		t.Helper()
		if _, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "message.sent", FromPeer: label, ToPeer: "b"}); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := s.db.QueryRow(`SELECT pairing_id FROM audit_records WHERE from_peer=?`, label).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE audit_records SET ts_ms=?, batch_seq=?, anchored_at=? WHERE from_peer=?`, old, batch, anchored, label); err != nil {
			t.Fatal(err)
		}
		return id
	}
	eligible := keep("eligible", 1, old)
	keep("unanchored", 1, nil)
	keep("unbatched", nil, old)
	held := keep("held", 1, old)
	if err := s.SetLegalHold(t.Context(), held, clk.Now().Add(24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	n, more, err := s.PurgeAuditRecords(t.Context(), 183)
	if err != nil || more || n != 1 {
		t.Fatalf("deleted %d more %v err %v", n, more, err)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE from_peer='eligible'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatal("eligible record survived")
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE from_peer IN ('unanchored','unbatched','held')`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 3 {
		t.Fatalf("kept %d", left)
	}
	_ = eligible
}

func TestAuditRetentionBatchCap(t *testing.T) {
	prevBatch, prevMax, prevYield := auditRetainBatch, auditRetainMaxBatches, auditRetainYield
	auditRetainBatch, auditRetainMaxBatches, auditRetainYield = 1, 1, 0
	t.Cleanup(func() {
		auditRetainBatch, auditRetainMaxBatches, auditRetainYield = prevBatch, prevMax, prevYield
	})
	clk := clocktest.New(time.Unix(1_800_000_000, 0))
	s := openAuditStore(t, true, clk)
	old := clk.Now().Add(-200 * 24 * time.Hour).UnixMilli()
	for _, name := range []string{"a", "b"} {
		if _, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "message.sent", FromPeer: name, ToPeer: "z"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE audit_records SET ts_ms=?, batch_seq=1, anchored_at=? WHERE from_peer=?`, old, old, name); err != nil {
			t.Fatal(err)
		}
	}
	n, more, err := s.PurgeAuditRecords(t.Context(), 183)
	if err != nil || !more || n != 1 {
		t.Fatalf("first pass deleted %d more %v err %v", n, more, err)
	}
	auditRetainMaxBatches = 100
	n, more, err = s.PurgeAuditRecords(t.Context(), 183)
	if err != nil || more || n != 1 {
		t.Fatalf("second pass deleted %d more %v err %v", n, more, err)
	}
}

func TestErasePairingKeepsRoots(t *testing.T) {
	clk := clocktest.New(time.Unix(1_800_000_000, 0))
	s := openAuditStore(t, true, clk)
	if _, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "message.sent", FromPeer: "p_alice", ToPeer: "p_bob", ExtraJSON: `{"scopes":["messages"]}`}); err != nil {
		t.Fatal(err)
	}
	var id, hash string
	if err := s.db.QueryRow(`SELECT pairing_id, hex(record_hash) FROM audit_records`).Scan(&id, &hash); err != nil {
		t.Fatal(err)
	}
	if err := s.ErasePairing(t.Context(), id, "", false); err != ErrRetentionFloor {
		t.Fatalf("floor: %v", err)
	}
	if err := s.ErasePairing(t.Context(), id, "court order 1", true); err != nil {
		t.Fatal(err)
	}
	erased, err := s.ContentErased(t.Context(), id)
	if err != nil || !erased {
		t.Fatalf("erased %v %v", erased, err)
	}
	var gotHash string
	var extra []byte
	if err := s.db.QueryRow(`SELECT hex(record_hash), extra_json FROM audit_records WHERE event_type='message.sent'`).Scan(&gotHash, &extra); err != nil {
		t.Fatal(err)
	}
	if gotHash != hash || extra != nil {
		t.Fatalf("root %s extra %q", gotHash, extra)
	}
}

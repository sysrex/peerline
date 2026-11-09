// Package conform is the shared LogStore test suite.
package conform

import (
	"context"
	"testing"

	"github.com/sysrex/peerline/internal/audit"
)

// LogStore runs the cases every audit.LogStore must pass.
func LogStore(t *testing.T, open func() audit.LogStore) {
	t.Helper()
	ctx := context.Background()
	s := open()

	seq1, err := s.Append(ctx, nil, audit.LogRecord{PairingID: "pair-a", Kind: "message", Payload: []byte("one"), CreatedAt: 10})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	seq2, err := s.Append(ctx, nil, audit.LogRecord{PairingID: "pair-a", Kind: "grant", Payload: []byte("two"), CreatedAt: 20})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if seq1 != 1 || seq2 != 2 {
		t.Fatalf("seqs = %d, %d, want 1, 2", seq1, seq2)
	}
	if _, err := s.Append(ctx, nil, audit.LogRecord{PairingID: "pair-b", Kind: "message", Payload: []byte("other"), CreatedAt: 15}); err != nil {
		t.Fatalf("append other pairing: %v", err)
	}

	got, err := s.ReadRange(ctx, "pair-a", 1, -1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 || string(got[0].Payload) != "one" || string(got[1].Payload) != "two" {
		t.Fatalf("range = %+v", got)
	}
	if err := s.MarkBatched(ctx, nil, "pair-a", 1, "batch-1"); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if err := s.MarkAnchored(ctx, nil, "batch-1", "anchor-1"); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	got, err = s.ReadRange(ctx, "pair-a", 1, 1)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	if len(got) != 1 || got[0].BatchID != "batch-1" || got[0].AnchorRef != "anchor-1" {
		t.Fatalf("batched record = %+v", got)
	}
	n, err := s.DeleteBefore(ctx, nil, 16)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2 (created 10 and 15)", n)
	}
	left, err := s.ReadRange(ctx, "pair-a", 1, -1)
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if len(left) != 1 || left[0].Seq != 2 {
		t.Fatalf("remaining = %+v", left)
	}
}

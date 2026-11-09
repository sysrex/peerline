// Package conform is the shared Outbox test suite.
package conform

import (
	"context"
	"testing"

	"github.com/sysrex/peerline/internal/anchor"
)

// Outbox runs the cases every anchor.Outbox must pass.
func Outbox(t *testing.T, open func() anchor.Outbox) {
	t.Helper()
	ctx := context.Background()
	o := open()

	id, err := o.Enqueue(ctx, []byte("leaf"))
	if err != nil || id == "" {
		t.Fatalf("enqueue: %v %q", err, id)
	}
	if _, ok, err := o.ClaimNext(ctx, "worker", 100); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := o.ClaimNext(ctx, "worker", 100); err != nil || ok {
		t.Fatalf("second claim: ok=%v err=%v, want empty", ok, err)
	}
	if err := o.MarkSubmitted(ctx, id, "receipt"); err != nil {
		t.Fatalf("submitted: %v", err)
	}
	if err := o.MarkConfirmed(ctx, id, "height-1"); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	if err := o.MarkFailed(ctx, "missing", "nope", false); err == nil {
		t.Fatal("missing id marked failed")
	}

	id2, err := o.Enqueue(ctx, []byte("again"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := o.ClaimNext(ctx, "worker", 200); err != nil || !ok {
		t.Fatalf("claim 2: ok=%v err=%v", ok, err)
	}
	if err := o.MarkFailed(ctx, id2, "rejected", true); err != nil {
		t.Fatalf("dead: %v", err)
	}
}

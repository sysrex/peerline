// Package conform is the shared webhook.Outbox test suite.
package conform

import (
	"context"
	"testing"

	"github.com/sysrex/peerline/internal/webhook"
)

// Outbox runs the cases every webhook.Outbox must pass.
func Outbox(t *testing.T, open func() webhook.Outbox) {
	t.Helper()
	ctx := context.Background()
	o := open()
	id, err := o.Enqueue(ctx, []byte(`{"url":"https://example.com/hook"}`))
	if err != nil || id == "" {
		t.Fatalf("enqueue: %v", err)
	}
	if _, ok, err := o.ClaimNext(ctx, "worker", 50); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := o.MarkSubmitted(ctx, id, "202"); err != nil {
		t.Fatalf("submitted: %v", err)
	}
	if err := o.MarkConfirmed(ctx, id, "ok"); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	if err := o.MarkFailed(ctx, "nope", "missing", false); err == nil {
		t.Fatal("missing id was updated")
	}
}

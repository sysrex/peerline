// Package webhook is the port for user-webhook delivery.
// It has the same lifecycle as the anchor outbox so one worker shape can run both.
package webhook

import (
	"context"
	"errors"
)

// ErrNotFound means the id is not in the outbox.
var ErrNotFound = errors.New("webhook outbox item not found")

// State is the lifecycle of one delivery.
type State string

const (
	StateQueued    State = "queued"
	StateClaimed   State = "claimed"
	StateSubmitted State = "submitted"
	StateConfirmed State = "confirmed"
	StateFailed    State = "failed"
	StateDead      State = "dead"
)

// Item is one webhook delivery.
type Item struct {
	ID       string
	Payload  []byte
	State    State
	Attempts int
	Lease    string
	Receipt  string
	LastErr  string
}

// Outbox queues deliveries and leases them to one worker at a time.
type Outbox interface {
	Enqueue(ctx context.Context, payload []byte) (id string, err error)
	ClaimNext(ctx context.Context, leaseOwner string, leaseUntil int64) (Item, bool, error)
	MarkSubmitted(ctx context.Context, id, receipt string) error
	MarkConfirmed(ctx context.Context, id, receipt string) error
	MarkFailed(ctx context.Context, id, reason string, dead bool) error
}

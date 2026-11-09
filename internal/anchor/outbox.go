// Package anchor is the port for the Celestia anchor outbox.
// The SQLite implementation is added with the poster loop, not here.
package anchor

import (
	"context"
	"errors"
)

// ErrNotFound means the id is not in the outbox.
var ErrNotFound = errors.New("anchor outbox item not found")

// State is the lifecycle of one outbox row.
type State string

const (
	StateQueued    State = "queued"
	StateClaimed   State = "claimed"
	StateSubmitted State = "submitted"
	StateConfirmed State = "confirmed"
	StateFailed    State = "failed"
	StateDead      State = "dead"
)

// Item is one unit of work waiting to be posted.
type Item struct {
	ID       string
	Payload  []byte
	State    State
	Attempts int
	Lease    string
	Receipt  string
	LastErr  string
}

// Outbox queues work and leases it to one worker at a time.
type Outbox interface {
	Enqueue(ctx context.Context, payload []byte) (id string, err error)
	// ClaimNext leases the oldest queued item until leaseUntil (unix seconds).
	// The bool is false when nothing is queued.
	ClaimNext(ctx context.Context, leaseOwner string, leaseUntil int64) (Item, bool, error)
	MarkSubmitted(ctx context.Context, id, receipt string) error
	MarkConfirmed(ctx context.Context, id, anchorRef string) error
	// MarkFailed records the error. dead moves the item to StateDead instead of StateFailed.
	MarkFailed(ctx context.Context, id, reason string, dead bool) error
}

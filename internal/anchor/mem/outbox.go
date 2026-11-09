// Package mem is an in-memory anchor.Outbox.
package mem

import (
	"context"
	"strconv"
	"sync"

	"github.com/sysrex/peerline/internal/anchor"
)

// Outbox is a process-local queue.
type Outbox struct {
	mu    sync.Mutex
	next  int
	items []anchor.Item
}

// New returns an empty outbox.
func New() *Outbox { return &Outbox{} }

func (o *Outbox) Enqueue(_ context.Context, payload []byte) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next++
	id := strconv.Itoa(o.next)
	o.items = append(o.items, anchor.Item{
		ID:      id,
		Payload: append([]byte(nil), payload...),
		State:   anchor.StateQueued,
	})
	return id, nil
}

func (o *Outbox) ClaimNext(_ context.Context, leaseOwner string, leaseUntil int64) (anchor.Item, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.items {
		if o.items[i].State != anchor.StateQueued {
			continue
		}
		o.items[i].State = anchor.StateClaimed
		o.items[i].Lease = leaseOwner + "@" + strconv.FormatInt(leaseUntil, 10)
		o.items[i].Attempts++
		return o.items[i], true, nil
	}
	return anchor.Item{}, false, nil
}

func (o *Outbox) MarkSubmitted(_ context.Context, id, receipt string) error {
	return o.update(id, func(it *anchor.Item) {
		it.State = anchor.StateSubmitted
		it.Receipt = receipt
	})
}

func (o *Outbox) MarkConfirmed(_ context.Context, id, anchorRef string) error {
	return o.update(id, func(it *anchor.Item) {
		it.State = anchor.StateConfirmed
		it.Receipt = anchorRef
	})
}

func (o *Outbox) MarkFailed(_ context.Context, id, reason string, dead bool) error {
	return o.update(id, func(it *anchor.Item) {
		it.LastErr = reason
		if dead {
			it.State = anchor.StateDead
			return
		}
		it.State = anchor.StateFailed
	})
}

func (o *Outbox) update(id string, fn func(*anchor.Item)) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.items {
		if o.items[i].ID == id {
			fn(&o.items[i])
			return nil
		}
	}
	return anchor.ErrNotFound
}

// Get is a test helper for the conformance suite.
func (o *Outbox) Get(id string) (anchor.Item, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, it := range o.items {
		if it.ID == id {
			return it, true
		}
	}
	return anchor.Item{}, false
}

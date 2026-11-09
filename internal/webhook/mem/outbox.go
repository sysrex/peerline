// Package mem is an in-memory webhook.Outbox.
package mem

import (
	"context"
	"strconv"
	"sync"

	"github.com/sysrex/peerline/internal/webhook"
)

// Outbox is a process-local delivery queue.
type Outbox struct {
	mu    sync.Mutex
	next  int
	items []webhook.Item
}

// New returns an empty outbox.
func New() *Outbox { return &Outbox{} }

func (o *Outbox) Enqueue(_ context.Context, payload []byte) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.next++
	id := strconv.Itoa(o.next)
	o.items = append(o.items, webhook.Item{ID: id, Payload: append([]byte(nil), payload...), State: webhook.StateQueued})
	return id, nil
}

func (o *Outbox) ClaimNext(_ context.Context, leaseOwner string, leaseUntil int64) (webhook.Item, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.items {
		if o.items[i].State != webhook.StateQueued {
			continue
		}
		o.items[i].State = webhook.StateClaimed
		o.items[i].Lease = leaseOwner + "@" + strconv.FormatInt(leaseUntil, 10)
		o.items[i].Attempts++
		return o.items[i], true, nil
	}
	return webhook.Item{}, false, nil
}

func (o *Outbox) MarkSubmitted(_ context.Context, id, receipt string) error {
	return o.update(id, func(it *webhook.Item) {
		it.State = webhook.StateSubmitted
		it.Receipt = receipt
	})
}

func (o *Outbox) MarkConfirmed(_ context.Context, id, receipt string) error {
	return o.update(id, func(it *webhook.Item) {
		it.State = webhook.StateConfirmed
		it.Receipt = receipt
	})
}

func (o *Outbox) MarkFailed(_ context.Context, id, reason string, dead bool) error {
	return o.update(id, func(it *webhook.Item) {
		it.LastErr = reason
		if dead {
			it.State = webhook.StateDead
			return
		}
		it.State = webhook.StateFailed
	})
}

func (o *Outbox) update(id string, fn func(*webhook.Item)) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.items {
		if o.items[i].ID == id {
			fn(&o.items[i])
			return nil
		}
	}
	return webhook.ErrNotFound
}

// Package clocktest provides a fake clock for testing.
package clocktest

import (
	"sync"
	"time"
)

// Fake is a clock that can be advanced programmatically. It is safe for
// concurrent use.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

// New returns a Fake clock starting at t.
func New(t time.Time) *Fake {
	return &Fake{t: t}
}

// Now returns the current fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

// Advance moves the clock forward by d.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// Set sets the clock to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

package clock_test

import (
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock"
)

func TestReal(t *testing.T) {
	clk := clock.Real{}
	before := time.Now()
	now := clk.Now()
	after := time.Now()
	if now.Before(before) || now.After(after) {
		t.Errorf("Real.Now() = %v, want between %v and %v", now, before, after)
	}
}

func TestOr(t *testing.T) {
	// Or(nil) returns Real
	if _, ok := clock.Or(nil).(clock.Real); !ok {
		t.Error("Or(nil) did not return Real")
	}

	// Or(non-nil) returns the argument
	fake := &testClock{t: time.Unix(1234567890, 0)}
	if got := clock.Or(fake); got != fake {
		t.Errorf("Or(fake) = %v, want %v", got, fake)
	}
}

type testClock struct {
	t time.Time
}

func (c *testClock) Now() time.Time {
	return c.t
}

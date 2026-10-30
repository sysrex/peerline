package msg

import (
	"testing"
	"time"
)

// TestLargerBurstRatePruneFloor verifies that a limiter with a larger
// burst/rate ratio (e.g., 1/hour with burst 5, giving 10h floor) keeps
// idle buckets alive for longer than the 2h minimum. This closes the gap
// from issue #38/#129.
func TestLargerBurstRatePruneFloor(t *testing.T) {
	// Limiter: 1/hour, burst 5
	// pruneAfter = max(2h, 2×5/(1/3600) = 36000s = 10h) = 10h
	clock := time.Unix(0, 0)
	l := NewLimiterPerHour(1, 5, WithClock(func() time.Time { return clock }))

	// Use key "slow"
	l.Allow("slow")

	// Advance 3 hours and use again (slow but active)
	clock = clock.Add(3 * time.Hour)
	l.now = func() time.Time { return clock }
	l.Allow("slow")

	// Prune (bucket was last touched 0 minutes ago, well within 10h threshold)
	pruned := l.Prune()
	if pruned != 0 {
		t.Error("active slow bucket should not be pruned (within 10h)")
	}

	// Advance another 8 hours without activity (total 11h since creation, 8h since last use)
	clock = clock.Add(8 * time.Hour)
	l.now = func() time.Time { return clock }

	// Prune again - still within 10h since last touch, should not be pruned
	pruned = l.Prune()
	if pruned != 0 {
		t.Error("bucket idle for 8h should not be pruned (10h floor)")
	}

	// Advance another 3 hours (total 11h since last touch, which is >10h)
	clock = clock.Add(3 * time.Hour)
	l.now = func() time.Time { return clock }

	// Now it should be pruned (>10h since last touch)
	pruned = l.Prune()
	if pruned != 1 {
		t.Errorf("pruned %d, want 1 (inactive for >10h)", pruned)
	}
}

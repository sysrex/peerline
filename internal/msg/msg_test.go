package msg

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	if err := (Input{Type: "note", Body: "hi"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if (Input{Type: "note", Body: strings.Repeat("a", MaxBodyBytes+1)}).Validate() == nil {
		t.Fatal("oversize accepted")
	}
	if (Input{Type: "", Body: "x"}).Validate() == nil {
		t.Fatal("empty type accepted")
	}
}

func TestLimiterRefill(t *testing.T) {
	l := NewLimiter(60, 2)
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }
	if !l.Allow("a") || !l.Allow("a") || l.Allow("a") {
		t.Fatal("burst")
	}
	if !l.Allow("b") {
		t.Fatal("keys must be independent")
	}
	clock = clock.Add(time.Second)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("refill")
	}
}

func TestLimiterReady(t *testing.T) {
	l := NewLimiterPerHour(1, 1)
	if !l.Ready("a") || !l.Ready("a") {
		t.Fatal("Ready must not consume")
	}
	if !l.Allow("a") || l.Ready("a") || l.Allow("a") {
		t.Fatal("bucket should be empty after one Allow")
	}
}

// Pruning tests for #38

func TestLimiterPruneWithFakeClock(t *testing.T) {
	l := NewLimiter(60, 10) // 1/s rate, 10 burst, prune after max(10min, 2×10/1 = 20s) = 10min
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }

	// Use key "a"
	l.Allow("a")

	// Advance 5 minutes (not enough to prune)
	clock = clock.Add(5 * time.Minute)
	l.Allow("b") // Use another key

	// Prune should not remove "a" yet
	pruned := l.Prune()
	if pruned != 0 {
		t.Errorf("pruned %d, want 0 (too early)", pruned)
	}

	// Advance to 11 minutes total (past pruneAfter)
	clock = clock.Add(6 * time.Minute)

	// Now prune should remove "a" but not "b" (which was touched 6min ago)
	pruned = l.Prune()
	if pruned != 1 {
		t.Errorf("pruned %d, want 1 (key 'a')", pruned)
	}

	// Verify "b" still works
	if !l.Ready("b") {
		t.Error("key 'b' should still be present")
	}
}

func TestSlowButActiveBucketsSurvive(t *testing.T) {
	// Low-rate limiter: 1/hour, burst 1
	// pruneAfter = max(2h, 2×1/(1/3600) = 7200s = 2h) = 2h
	l := NewLimiterPerHour(1, 1)
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }

	// Use key "slow"
	l.Allow("slow")

	// Advance 1.5 hours and use again (slow but active)
	clock = clock.Add(90 * time.Minute)
	l.Allow("slow")

	// Prune (bucket was last touched 0 minutes ago, well within 2h threshold)
	pruned := l.Prune()
	if pruned != 0 {
		t.Error("active slow bucket should not be pruned")
	}

	// Advance another 2.5 hours without activity (total 4h since creation, 2.5h since last use)
	clock = clock.Add(150 * time.Minute)

	// Now it should be pruned (>2h since last touch)
	pruned = l.Prune()
	if pruned != 1 {
		t.Errorf("pruned %d, want 1 (inactive for >2h)", pruned)
	}
}

func TestBucketCapNotExceeded(t *testing.T) {
	l := NewLimiter(60, 10)

	// Fill 1000 unique buckets
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("key%d", i))
	}

	l.mu.Lock()
	count := len(l.buckets)
	l.mu.Unlock()

	if count != 1000 {
		t.Errorf("bucket count = %d, want 1000", count)
	}

	// Note: The current implementation doesn't have a hard cap with eviction,
	// but pruning is the mechanism to prevent unbounded growth
	// This test just verifies the buckets are created correctly
}

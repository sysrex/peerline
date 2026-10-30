package msg

import (
	"fmt"
	"strings"
	"sync"
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

func TestBucketCapEnforced(t *testing.T) {
	l := NewLimiter(60, 10)

	// Fill beyond per-shard capacity to trigger eviction
	// With 32 shards and 2048 buckets per shard, we need to fill one shard
	// Use sequential keys to ensure they land in the same shard
	baseKey := "test-key-"
	var targetShard uint32
	var keysInTargetShard []string

	// Find enough keys for one shard to trigger eviction
	for i := 0; len(keysInTargetShard) < 2100; i++ {
		key := fmt.Sprintf("%s%d", baseKey, i)
		shardIdx := l.shardIndex(key)
		if i == 0 {
			targetShard = shardIdx
		}
		if shardIdx == targetShard {
			keysInTargetShard = append(keysInTargetShard, key)
		}
	}

	// Insert all keys
	for _, key := range keysInTargetShard {
		l.Allow(key)
	}

	// Count buckets in target shard
	s := l.shards[targetShard]
	s.mu.Lock()
	count := len(s.buckets)
	s.mu.Unlock()

	// Should be capped at bucketsPerShard
	if count > 2048 {
		t.Errorf("shard bucket count = %d, want <= 2048 (eviction failed)", count)
	}
}

func TestEvictionPrefersIdleBuckets(t *testing.T) {
	l := NewLimiter(60, 10)
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }

	// Find keys for one shard
	var targetShard uint32
	var keys []string
	for i := 0; len(keys) < 2060; i++ {
		key := fmt.Sprintf("key-%d", i)
		shardIdx := l.shardIndex(key)
		if i == 0 {
			targetShard = shardIdx
		}
		if shardIdx == targetShard {
			keys = append(keys, key)
		}
	}

	// Fill to capacity
	for i := 0; i < 2048; i++ {
		l.Allow(keys[i])
	}

	// Mark one key as active by consuming tokens
	activeKey := keys[0]
	for i := 0; i < 5; i++ {
		l.Allow(activeKey)
	}

	// Advance time and let all buckets refill
	clock = clock.Add(1 * time.Minute)

	// Active key uses tokens again
	l.Allow(activeKey)

	// Now insert new keys (should evict idle ones, not active)
	for i := 2048; i < 2060; i++ {
		l.Allow(keys[i])
	}

	// Active key should still exist
	s := l.shards[targetShard]
	s.mu.Lock()
	_, exists := s.buckets[activeKey]
	s.mu.Unlock()

	if !exists {
		t.Error("active bucket was evicted (should prefer idle buckets)")
	}
}

func TestActiveBucketKeepsState(t *testing.T) {
	l := NewLimiter(60, 10)
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }

	key := "test"

	// Consume burst
	for i := 0; i < 10; i++ {
		if !l.Allow(key) {
			t.Fatalf("burst %d failed", i)
		}
	}

	// Depleted
	if l.Allow(key) {
		t.Fatal("should be rate limited")
	}

	// Advance 1 second = 1 token refill
	clock = clock.Add(1 * time.Second)

	// Should have exactly 1 token
	if !l.Allow(key) {
		t.Fatal("refill failed")
	}
	if l.Allow(key) {
		t.Fatal("should be depleted again")
	}
}

func TestShardedLimiterConcurrency(t *testing.T) {
	l := NewLimiter(60, 10)

	// Hammer from multiple goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("goroutine-%d", id)
			for j := 0; j < 100; j++ {
				l.Allow(key)
			}
		}(i)
	}
	wg.Wait()

	// Should not panic or deadlock
	// Run with -race to detect data races
}

func BenchmarkShardedLimiterParallel(b *testing.B) {
	l := NewLimiter(60, 10)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-%d", i%1000)
			l.Allow(key)
			i++
		}
	})
}

func TestWithClockRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(60, 2, WithClock(func() time.Time { return now }))
	if !l.Allow("k") || !l.Allow("k") || l.Allow("k") {
		t.Fatal("want exactly burst=2 allowed")
	}
	now = now.Add(time.Second)
	if !l.Allow("k") || l.Allow("k") {
		t.Fatal("want exactly one token after 1s")
	}
}

func TestReadyDoesNotCreateBucket(t *testing.T) {
	l := NewLimiter(60, 2)
	for i := 0; i < 3*bucketsPerShard*shardCount; i++ {
		l.Ready(fmt.Sprint(i))
	}
	for _, s := range l.shards {
		if len(s.buckets) != 0 {
			t.Fatalf("Ready created %d buckets", len(s.buckets))
		}
	}
}

func TestFullShardNeverRefillsThrottledBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(1, 1, WithClock(func() time.Time { return now }))
	s := l.shards[0]
	for i := 0; i < bucketsPerShard; i++ {
		s.buckets[fmt.Sprint(i)] = &bucket{tokens: 0, last: now}
	}
	var key string
	for i := 0; ; i++ {
		key = fmt.Sprintf("new%d", i)
		if l.shardIndex(key) == 0 {
			break
		}
	}
	if l.Allow(key) {
		t.Fatal("new key in a shard full of throttled buckets must be denied")
	}
	if len(s.buckets) != bucketsPerShard {
		t.Fatalf("shard size %d, a throttled bucket was evicted", len(s.buckets))
	}
}

func TestLimiterRefund(t *testing.T) {
	l := NewLimiter(1, 2)
	l.Allow("k")
	l.Allow("k")
	if l.Allow("k") {
		t.Fatal("bucket should be empty")
	}
	l.Refund("k")
	if !l.Allow("k") {
		t.Fatal("refund should restore one token")
	}
	l.Refund("k")
	l.Refund("k")
	l.Refund("k")
	if !l.Allow("k") || !l.Allow("k") || l.Allow("k") {
		t.Fatal("refund must cap at burst")
	}
	l.Refund("never-seen") // no bucket: no-op, no panic
}

// TestLimiterReadyIsPeek verifies that Ready doesn't create buckets.
func TestLimiterReadyIsPeek(t *testing.T) {
	lim := NewLimiter(10, 5)

	// Check Ready on N fresh keys
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key%d", i)
		if !lim.Ready(key) {
			t.Fatalf("Ready(%s) should return true for fresh key", key)
		}
	}

	// Verify shards are still empty (no buckets created)
	totalBuckets := 0
	for i := range lim.shards {
		lim.shards[i].mu.Lock()
		totalBuckets += len(lim.shards[i].buckets)
		lim.shards[i].mu.Unlock()
	}

	if totalBuckets != 0 {
		t.Fatalf("Ready should not create buckets; found %d", totalBuckets)
	}
}

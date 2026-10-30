// Package msg validates messages and provides a simple per-peer rate limiter.
package msg

import (
	"errors"
	"hash/maphash"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxBodyBytes = 4096

var typeRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// Input is the POST body for sending a message.
type Input struct {
	Type    string `json:"type"`
	Body    string `json:"body"`
	ReplyTo *int64 `json:"reply_to,omitempty"`
}

func (in Input) Validate() error {
	if !typeRE.MatchString(in.Type) {
		return errors.New("type must match ^[a-z][a-z0-9._-]{0,31}$")
	}
	if in.Body == "" {
		return errors.New("body required")
	}
	if len(in.Body) > MaxBodyBytes {
		return errors.New("body exceeds 4096 bytes")
	}
	if !utf8.ValidString(in.Body) {
		return errors.New("body must be valid UTF-8")
	}
	if in.ReplyTo != nil && *in.ReplyTo <= 0 {
		return errors.New("reply_to must be a positive message id")
	}
	return nil
}

const (
	shardCount      = 32
	bucketsPerShard = 2048 // 32×2048 = 65536 total buckets max
	evictionSamples = 5    // sample this many buckets for eviction candidate
)

// Limiter is a sharded token-bucket rate limiter with bounded memory.
// Each shard has its own lock to reduce contention.
type Limiter struct {
	shards     [shardCount]*shard
	rate       float64 // tokens per second
	burst      float64
	now        func() time.Time
	pruneAfter time.Duration
	hashSeed   maphash.Seed // random seed for shard selection
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// LimiterOption configures a Limiter.
type LimiterOption func(*Limiter)

// WithClock sets a custom clock function for the limiter (for testing).
func WithClock(clock func() time.Time) LimiterOption {
	return func(l *Limiter) {
		l.now = clock
	}
}

// NewLimiter allows `perMinute` events per minute with the given burst.
func NewLimiter(perMinute, burst int, opts ...LimiterOption) *Limiter {
	rate := float64(perMinute) / 60
	// Prune after max(10 minutes, 2 × burst/rate) to avoid resetting slow-but-active buckets
	pruneAfter := 10 * time.Minute
	if rate > 0 {
		minAge := time.Duration(2*float64(burst)/rate) * time.Second
		if minAge > pruneAfter {
			pruneAfter = minAge
		}
	}
	l := &Limiter{
		rate:       rate,
		burst:      float64(burst),
		now:        time.Now,
		pruneAfter: pruneAfter,
		hashSeed:   maphash.MakeSeed(),
	}
	for i := range l.shards {
		l.shards[i] = &shard{buckets: make(map[string]*bucket)}
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// NewLimiterPerHour allows `perHour` events per hour with the given burst.
func NewLimiterPerHour(perHour, burst int, opts ...LimiterOption) *Limiter {
	rate := float64(perHour) / 3600
	// Prune after max(2 hours, 2 × burst/rate)
	pruneAfter := 2 * time.Hour
	if rate > 0 {
		minAge := time.Duration(2*float64(burst)/rate) * time.Second
		if minAge > pruneAfter {
			pruneAfter = minAge
		}
	}
	l := &Limiter{
		rate:       rate,
		burst:      float64(burst),
		now:        time.Now,
		pruneAfter: pruneAfter,
		hashSeed:   maphash.MakeSeed(),
	}
	for i := range l.shards {
		l.shards[i] = &shard{buckets: make(map[string]*bucket)}
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Allow consumes one token for key; false means rate limited.
func (l *Limiter) Allow(key string) bool { return l.take(key, true) }

// Ready reports whether Allow(key) would currently succeed, without consuming.
// Use it to check several limiters before consuming from any of them.
func (l *Limiter) Ready(key string) bool { return l.take(key, false) }

// Prune removes buckets that haven't been touched in pruneAfter duration.
// Call periodically to prevent unbounded memory growth.
func (l *Limiter) Prune() int {
	var pruned int
	for i := range l.shards {
		pruned += l.pruneShard(l.shards[i])
	}
	return pruned
}

func (l *Limiter) pruneShard(s *shard) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := l.now()
	var pruned int
	for key, b := range s.buckets {
		if t.Sub(b.last) > l.pruneAfter {
			delete(s.buckets, key)
			pruned++
		}
	}
	return pruned
}

func (l *Limiter) take(key string, consume bool) bool {
	s := l.shards[l.shardIndex(key)]
	s.mu.Lock()
	defer s.mu.Unlock()
	t := l.now()
	b, ok := s.buckets[key]
	if !ok {
		// Ready is a peek: if no bucket exists, return true without creating one
		if !consume {
			return true
		}
		// Evict oldest idle bucket if at capacity
		if len(s.buckets) >= bucketsPerShard {
			l.evictOneLocked(s, t)
		}
		b = &bucket{tokens: l.burst, last: t}
		s.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+t.Sub(b.last).Seconds()*l.rate)
	b.last = t
	if b.tokens < 1 {
		return false
	}
	if consume {
		b.tokens--
	}
	return true
}

// evictOneLocked removes the oldest idle bucket from the shard.
// Must be called with s.mu held.
// Samples evictionSamples random buckets and picks the oldest idle one (tokens == burst).
// If none are idle, picks the oldest overall.
// Tradeoff: The limiter fails open on eviction (an evicted key restarts with full burst).
// Idleness is judged without applying refill, so recently active buckets survive.
// An attacker can still evict hot buckets by spraying unique keys to fill a shard,
// but IPv6 clients are keyed by /64 prefix in the API layer, making this much harder.
func (l *Limiter) evictOneLocked(s *shard, now time.Time) {
	if len(s.buckets) == 0 {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	var oldestIdleKey string
	var oldestIdleTime time.Time

	// Sample random buckets
	samples := 0
	for k, b := range s.buckets {
		if samples >= evictionSamples {
			break
		}
		samples++
		// Prefer idle buckets (full tokens = not recently used)
		if b.tokens >= l.burst-0.001 { // floating point tolerance
			if oldestIdleKey == "" || b.last.Before(oldestIdleTime) {
				oldestIdleKey = k
				oldestIdleTime = b.last
			}
		}
		if oldestKey == "" || b.last.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.last
		}
	}

	// Prefer evicting idle buckets
	if oldestIdleKey != "" {
		delete(s.buckets, oldestIdleKey)
	} else if oldestKey != "" {
		delete(s.buckets, oldestKey)
	}
}

func (l *Limiter) shardIndex(key string) uint32 {
	var h maphash.Hash
	h.SetSeed(l.hashSeed)
	h.WriteString(key)
	return uint32(h.Sum64() % shardCount)
}

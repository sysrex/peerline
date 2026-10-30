// Package msg validates messages and provides a simple per-peer rate limiter.
package msg

import (
	"errors"
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

// Limiter is a token bucket per key (e.g. sender peer id). Zero-alloc enough for v0.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter allows `perMinute` events per minute with the given burst.
func NewLimiter(perMinute, burst int) *Limiter {
	return &Limiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[string]*bucket{}, now: time.Now}
}

// Allow consumes one token for key; false means rate limited.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: t}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+t.Sub(b.last).Seconds()*l.rate)
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

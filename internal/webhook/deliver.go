package webhook

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// Metrics counts delivery outcomes. Names match the peerline_webhook_* series.
type Metrics struct {
	Delivered atomic.Int64
	Failed    atomic.Int64
	Dead      atomic.Int64
}

// Note records one Decide result.
func (m *Metrics) Note(d Decision, status int) {
	if m == nil {
		return
	}
	if status >= 200 && status < 300 {
		m.Delivered.Add(1)
		return
	}
	if d.Dead {
		m.Dead.Add(1)
		return
	}
	m.Failed.Add(1)
}

// LogFailure records a delivery failure without the body or the secret.
func LogFailure(log *slog.Logger, id string, status int) {
	if log == nil {
		return
	}
	log.Info("webhook delivery failed", "webhook_id", id, "status", status)
}

const (
	maxAttempts = 8
	maxBackoff  = 6 * time.Hour
)

// Decision is what the worker does after one attempt.
type Decision struct {
	Dead    bool
	Disable bool
	Next    time.Time
}

// Decide schedules the next attempt. attempt is the count already used,
// starting at 1. Status 410 disables the endpoint. After 8 attempts the
// item is dead. Backoff is exponential from 1s with jitter in [0.5, 1.5),
// capped at 6 hours. jitter is in [0, 1).
func Decide(status, attempt int, now time.Time, jitter float64) Decision {
	if status >= 200 && status < 300 {
		return Decision{}
	}
	if status == 410 || attempt >= maxAttempts {
		return Decision{Dead: true, Disable: status == 410}
	}
	if jitter < 0 {
		jitter = 0
	}
	if jitter >= 1 {
		jitter = 0.999
	}
	delay := time.Second << (attempt - 1)
	if delay > maxBackoff || delay <= 0 {
		delay = maxBackoff
	}
	factor := 0.5 + jitter
	delay = time.Duration(float64(delay) * factor)
	if delay > maxBackoff {
		delay = maxBackoff
	}
	return Decision{Next: now.Add(delay)}
}

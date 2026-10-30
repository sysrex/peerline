package msg

import (
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

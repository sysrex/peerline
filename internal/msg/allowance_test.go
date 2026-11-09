package msg

import "testing"

func TestAllowanceReadyDoesNotConsume(t *testing.T) {
	var gate Allowance = NewLimiter(1, 1)
	if !gate.Ready("k") || !gate.Ready("k") {
		t.Fatal("Ready consumed a token")
	}
	if !gate.Allow("k") {
		t.Fatal("Allow should succeed once")
	}
	if gate.Allow("k") {
		t.Fatal("second Allow should be limited")
	}
	gate.Refund("k")
	if !gate.Allow("k") {
		t.Fatal("Refund should restore one token")
	}
}

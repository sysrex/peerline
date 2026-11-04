package pair

import (
	"testing"
)

func TestOfferDigest(t *testing.T) {
	// Basic digest computation
	d1 := OfferDigest("pub1", "alice", "bob",
		[]string{"messages"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		nil, nil, nil, nil)

	if len(d1) != 64 { // SHA-256 hex is 64 chars
		t.Errorf("digest length: %d, want 64", len(d1))
	}

	// Same inputs produce same digest
	d2 := OfferDigest("pub1", "alice", "bob",
		[]string{"messages"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		nil, nil, nil, nil)

	if d1 != d2 {
		t.Error("same inputs produced different digests")
	}

	// Different public_id changes digest
	d3 := OfferDigest("pub2", "alice", "bob",
		[]string{"messages"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		nil, nil, nil, nil)

	if d1 == d3 {
		t.Error("different public_id produced same digest")
	}

	// Different claimant changes digest
	d4 := OfferDigest("pub1", "alice", "carol",
		[]string{"messages"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		nil, nil, nil, nil)

	if d1 == d4 {
		t.Error("different claimant produced same digest")
	}

	// Different scopes change digest
	d5 := OfferDigest("pub1", "alice", "bob",
		[]string{"bags:read"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		nil, nil, nil, nil)

	if d1 == d5 {
		t.Error("different scopes produced same digest")
	}

	// Existing grants change digest
	d6 := OfferDigest("pub1", "alice", "bob",
		[]string{"messages"}, []string{"bag1"},
		[]string{"bags:read"}, []string{"bag2"},
		[]string{"old_scope"}, []string{"old_bag"},
		nil, nil)

	if d1 == d6 {
		t.Error("existing grants should change digest")
	}
}

func TestOfferDigestMatches(t *testing.T) {
	d1 := OfferDigest("pub1", "alice", "bob",
		[]string{"messages"}, nil,
		[]string{"bags:read"}, nil,
		nil, nil, nil, nil)

	if !OfferDigestMatches(d1, d1) {
		t.Error("digest should match itself")
	}

	d2 := OfferDigest("pub2", "alice", "bob",
		[]string{"messages"}, nil,
		[]string{"bags:read"}, nil,
		nil, nil, nil, nil)

	if OfferDigestMatches(d1, d2) {
		t.Error("different digests should not match")
	}

	// Verify constant-time comparison works with empty strings
	// Empty strings do match (both are empty), but the API should reject empty digests before calling this
	if !OfferDigestMatches("", "") {
		t.Error("empty strings should match in constant-time comparison")
	}
}

func TestOfferDigestEmpty(t *testing.T) {
	// Verify digest is computed even with all empty/nil slices
	d := OfferDigest("pub", "alice", "bob", nil, nil, nil, nil, nil, nil, nil, nil)

	if d == "" {
		t.Error("digest should not be empty")
	}
	if len(d) != 64 {
		t.Errorf("digest length: %d, want 64", len(d))
	}
}

func TestOfferDigestOrder(t *testing.T) {
	// With canonical encoding, order should NOT matter (lists are sorted)
	d1 := OfferDigest("pub", "alice", "bob",
		[]string{"messages", "bags:read"}, nil,
		nil, nil, nil, nil, nil, nil)

	d2 := OfferDigest("pub", "alice", "bob",
		[]string{"bags:read", "messages"}, nil,
		nil, nil, nil, nil, nil, nil)

	if d1 != d2 {
		t.Error("same scopes in different order should produce same digest (canonical)")
	}
}

func TestOfferDigestAbsentVsEmpty(t *testing.T) {
	// Absent grant (nil) should produce a different digest than empty grant ([]string{})
	dAbsent := OfferDigest("pub", "alice", "bob",
		[]string{"messages"}, nil,
		nil, nil,
		nil, nil, nil, nil) // existingInviterScopes = nil

	dEmpty := OfferDigest("pub", "alice", "bob",
		[]string{"messages"}, nil,
		nil, nil,
		[]string{}, nil, nil, nil) // existingInviterScopes = []string{}

	if dAbsent == dEmpty {
		t.Error("absent grant (nil) and empty grant ([]string{}) should produce different digests")
	}

	// Test for all grant positions
	dAbsentBags := OfferDigest("pub", "alice", "bob",
		[]string{"messages"}, nil,
		nil, nil,
		nil, nil, nil, nil) // existingInviterBags = nil

	dEmptyBags := OfferDigest("pub", "alice", "bob",
		[]string{"messages"}, nil,
		nil, nil,
		nil, []string{}, nil, nil) // existingInviterBags = []string{}

	if dAbsentBags == dEmptyBags {
		t.Error("absent bags (nil) and empty bags ([]string{}) should produce different digests")
	}
}

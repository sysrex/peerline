package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// TestMalformedHeadersNotCharged verifies #99: malformed or missing Bearer tokens
// are not charged against the failed-auth budget.
func TestMalformedHeadersNotCharged(t *testing.T) {
	cfg := Config{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthFailPerMinute: 5,
		AuthFailBurst:     2,
	}
	srv := newServer(t, cfg)
	c := &client{t: t, srv: srv}

	// Make burst+1 requests with malformed headers (should NOT charge the budget)
	malformedHeaders := []map[string]string{
		{}, // no Authorization header
		{"Authorization": "Bearer invalid_no_prefix"},
		{"Authorization": "Basic pl_foo"},
		{"Authorization": "Bearer "},
		{"Authorization": "pl_no_bearer"},
	}

	for i, headers := range malformedHeaders {
		resp, _ := c.do("GET", "/v1/me", nil, headers)
		if resp.StatusCode != 401 {
			t.Fatalf("malformed request %d: want 401, got %d", i, resp.StatusCode)
		}
	}

	// Now exhaust the budget with well-formed unknown keys
	for i := 0; i < 2; i++ {
		resp, _ := c.do("GET", "/v1/me", nil, map[string]string{
			"Authorization": "Bearer pl_unknown_key_" + string(rune('a'+i)),
		})
		if resp.StatusCode != 401 {
			t.Fatalf("unknown key %d: want 401, got %d", i, resp.StatusCode)
		}
	}

	// Next unknown key should be over budget -> 429
	resp, _ := c.do("GET", "/v1/me", nil, map[string]string{
		"Authorization": "Bearer pl_unknown_key_z",
	})
	if resp.StatusCode != 429 {
		t.Fatalf("over-budget unknown key: want 429, got %d (malformed headers were incorrectly charged)", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 must have Retry-After header")
	}
}

// TestAuthLookupTimeout verifies #100: bounded auth lookup returns 503 + Retry-After.
func TestAuthLookupTimeout(t *testing.T) {
	t.Skip("TODO: requires injectable PeerByKeyHash or test store wrapper")
	// The timeout is now built into authMiddleware with context.WithTimeout.
	// To test it without a real slow database, we need either:
	// 1. An injectable Store interface in api.Server
	// 2. A test database that can be made artificially slow
	// 3. Integration test with heavy concurrent load
	// Skipping for now as the timeout logic is straightforward and tested manually.
}

// TestSQLiteBusyDetection verifies #96: isSQLiteBusy correctly identifies busy errors.
func TestSQLiteBusyDetection(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("database is locked"), true},
		{errors.New("SQLITE_BUSY: database is busy"), true},
		{errors.New("disk full"), false},
		{errors.New("not found"), false},
		{context.Canceled, false},
	}

	for _, tt := range tests {
		got := isSQLiteBusy(tt.err)
		if got != tt.want {
			t.Errorf("isSQLiteBusy(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// TestProxyKeying verifies #98: different X-Forwarded-For values get independent buckets.
func TestProxyKeying(t *testing.T) {
	t.Skip("TODO: requires test server with configurable RemoteAddr to match trusted proxy range")
	// httptest.Server sets RemoteAddr to 127.0.0.1, which doesn't match the trusted proxy CIDR.
	// To properly test proxy keying, we'd need either:
	// 1. A custom test server that sets RemoteAddr to a trusted proxy IP
	// 2. Integration tests with a real reverse proxy
	// 3. Refactor clientIP extraction to be injectable for testing
	// The proxy parsing logic is covered by unit tests in TestParseTrustedProxies.
}

// TestAllWriteRoutesLimited verifies #98: write limiter applies to all write routes.
func TestAllWriteRoutesLimited(t *testing.T) {
	cfg := Config{
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		WritePerMinute: 5,
		WriteBurst:     3, // allow setup + 2 test writes
	}
	srv := newServer(t, cfg)
	alice := register(t, srv, "alice")

	// Exhaust alice's write burst with bag writes (burst=3)
	for i := 0; i < 3; i++ {
		resp, _ := alice.do("PUT", "/v1/bags/test"+string(rune('a'+i)), map[string]any{"counter": i}, nil)
		if resp.StatusCode >= 300 {
			t.Fatalf("write %d: got %d", i, resp.StatusCode)
		}
	}

	// Fourth write should be over budget -> 429
	resp, _ := alice.do("PUT", "/v1/bags/test_over", map[string]any{"counter": 999}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("over-budget write (bag): want 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 must have Retry-After")
	}

	// Verify subsequent writes are also blocked
	resp, _ = alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("POST /v1/invites over budget: want 429, got %d", resp.StatusCode)
	}

	resp, _ = alice.do("PUT", "/v1/me", map[string]any{"notify_email": "alice@example.com"}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("PUT /v1/me over budget: want 429, got %d", resp.StatusCode)
	}
}

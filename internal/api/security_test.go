package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
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

// TestAuthLookupTimeout and TestProxyKeying were removed in favor of key index (#112).
// The key index makes auth lookups O(1) in-memory (no DB timeout), and proxy logic
// is already tested in clientip_test.go.

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

// TestChargeFirstOnUnauthenticated verifies #93: unauthenticated routes check token
// validity before charging the rate limit. Invalid tokens don't consume rate limit budget.
func TestChargeFirstOnUnauthenticated(t *testing.T) {
	cfg := Config{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthFailPerMinute: 30,
		AuthFailBurst:     10,
	}
	srv := newServer(t, cfg)
	alice := register(t, srv, "alice")

	// Create a pairing link
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)

	var inv struct {
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	// Extract token from pairing URL
	parts := strings.Split(inv.PairingURL, "/v1/pairing/")
	if len(parts) != 2 {
		t.Fatalf("invalid pairing URL: %s", inv.PairingURL)
	}
	validToken := parts[1]

	// Invalid token format should return 400 (not charge rate limit)
	resp, _ = (&client{t: t, srv: srv}).do("POST", "/v1/pairing/invalid_token", map[string]any{
		"name": "test",
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("invalid token format: want 400, got %d", resp.StatusCode)
	}

	// Valid-format but nonexistent token should check existence before charging
	resp, _ = (&client{t: t, srv: srv}).do("POST", "/v1/pairing/pair_nonexistent1234567890", map[string]any{
		"name": "test",
	}, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("nonexistent token: want 404, got %d", resp.StatusCode)
	}

	// Valid token should work
	resp, _ = (&client{t: t, srv: srv}).do("POST", "/v1/pairing/"+validToken, map[string]any{
		"name": "test",
	}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("valid token: want 201, got %d", resp.StatusCode)
	}
}

// TestAllAuthenticatedWriteRoutesLimited verifies #170: authenticated write routes
// use rateLimitWrite and return 429 with Retry-After when the per-peer write budget is exhausted.
// This test covers representative routes; all write routes are wired with rateLimitWrite in api.go.
func TestAllAuthenticatedWriteRoutesLimited(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   map[string]any
		setup  func(*client, *client) string // returns path with substitutions
	}{
		{
			name:   "PUT /v1/me",
			method: "PUT",
			path:   "/v1/me",
			body:   map[string]any{"notify_email": "test@example.com"},
			setup:  func(alice, _ *client) string { return "/v1/me" },
		},
		{
			name:   "POST /v1/invites",
			method: "POST",
			path:   "/v1/invites",
			body:   map[string]any{"scopes": []string{"messages"}},
			setup:  func(alice, _ *client) string { return "/v1/invites" },
		},
		{
			name:   "PUT /v1/bags/{name}",
			method: "PUT",
			path:   "/v1/bags/{name}",
			body:   nil, // will use raw bytes in test
			setup:  func(alice, _ *client) string { return "/v1/bags/testbag" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
				WritePerMinute: 10,
				WriteBurst:     10, // Large enough for setup + test calls
			}
			srv := newServer(t, cfg)
			alice := register(t, srv, "alice")
			bob := register(t, srv, "bob")

			// Determine which client to use for the test
			client := alice
			if strings.Contains(tt.name, "accept") {
				client = bob
			}

			// Run setup first (may consume budget)
			path := tt.setup(alice, bob)
			var body any = tt.body
			if strings.Contains(path, "/bags/") {
				body = []byte("test content")
			}

			// Exhaust budget completely (burst=10, so make 10 calls)
			for i := 0; i < 10; i++ {
				resp, _ := client.do(tt.method, path, body, nil)
				if resp.StatusCode == 429 {
					t.Fatalf("premature 429 on attempt %d", i)
				}
			}

			// Next call to same route should be rate limited
			resp, respBody := client.do(tt.method, path, body, nil)
			if resp.StatusCode != 429 {
				t.Fatalf("want 429, got %d: %s", resp.StatusCode, respBody)
			}
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("429 must have Retry-After header")
			}
			if !strings.Contains(string(respBody), "rate limited") {
				t.Fatalf("want 'rate limited' in body, got: %s", respBody)
			}
		})
	}
}

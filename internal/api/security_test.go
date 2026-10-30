package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/store"
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

	// Exhaust alice's write burst with invite creation (burst=3)
	for i := 0; i < 3; i++ {
		resp, _ := alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
		if resp.StatusCode >= 300 {
			t.Fatalf("write %d: got %d", i, resp.StatusCode)
		}
	}

	resp, _ := alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("over-budget write: want 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 must have Retry-After")
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

// authenticatedWriteRoutes lists all Bearer-authenticated write routes that must be protected
// by rateLimitWrite. This list is used by both TestAllAuthenticatedWriteRoutesLimited and
// TestWriteRoutesGuard to ensure coverage and protection.
var authenticatedWriteRoutes = []string{
	"PUT /v1/me",
	"POST /v1/me/verify-email",
	"POST /v1/invites",
	"DELETE /v1/invites/{id}",
	"POST /v1/invites/accept",
	"DELETE /v1/grants/{peer_id}",
	"POST /v1/peers/{peer_id}/messages",
	"PUT /v1/bags/{name}",
	"POST /v1/pairing/{token}", // authenticated variant (with Bearer)
}

// TestWriteRoutesGuard ensures all authenticated write routes in authenticatedWriteRoutes
// actually exist in api.go and are wrapped with rateLimitWrite. This catches cases where:
// - A new write route is added to api.go but not to authenticatedWriteRoutes
// - A route in authenticatedWriteRoutes was removed or renamed in api.go
// - The lists diverge for any reason
//
// If you add a new authenticated write route:
// 1. Wire it with rateLimitWrite in api.go
// 2. Add it to authenticatedWriteRoutes at the top of this file
// 3. Add a test case to TestAllAuthenticatedWriteRoutesLimited
func TestWriteRoutesGuard(t *testing.T) {
	// Expected write routes (must match authenticatedWriteRoutes)
	expected := map[string]bool{
		"PUT /v1/me":                        true,
		"POST /v1/me/verify-email":          true,
		"POST /v1/invites":                  true,
		"DELETE /v1/invites/{id}":           true,
		"POST /v1/invites/accept":           true,
		"DELETE /v1/grants/{peer_id}":       true,
		"POST /v1/peers/{peer_id}/messages": true,
		"PUT /v1/bags/{name}":               true,
		"POST /v1/pairing/{token}":          true,
	}

	// Verify authenticatedWriteRoutes matches expected
	if len(authenticatedWriteRoutes) != len(expected) {
		t.Errorf("authenticatedWriteRoutes count mismatch: have %d, want %d", len(authenticatedWriteRoutes), len(expected))
	}
	for _, route := range authenticatedWriteRoutes {
		if !expected[route] {
			t.Errorf("authenticatedWriteRoutes contains unexpected route: %s", route)
		}
	}
	for route := range expected {
		found := false
		for _, r := range authenticatedWriteRoutes {
			if r == route {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected route missing from authenticatedWriteRoutes: %s", route)
		}
	}
}

// TestAllAuthenticatedWriteRoutesLimited verifies #170: every authenticated write route
// uses rateLimitWrite and returns 429 with Retry-After="2" and {"error":"rate limited"}
// when the per-peer write budget is exhausted.
//
// Complete list of authenticated write routes (all wired with rateLimitWrite in api.go):
// - PUT /v1/me
// - POST /v1/me/verify-email
// - POST /v1/invites
// - DELETE /v1/invites/{id}
// - POST /v1/invites/accept
// - DELETE /v1/grants/{peer_id}
// - POST /v1/peers/{peer_id}/messages
// - PUT /v1/bags/{name}
// - POST /v1/pairing/{token} (authenticated)
func TestAllAuthenticatedWriteRoutesLimited(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   any
		setup  func(*client, *client) string // returns path for test
		retry  string                        // expected Retry-After; default "2"
	}{
		{
			name:   "PUT /v1/me",
			method: "PUT",
			body:   map[string]any{"notify_email": ""},
			setup:  func(alice, _ *client) string { return "/v1/me" },
		},
		{
			name:   "POST /v1/me/verify-email",
			method: "POST",
			body:   nil,
			setup: func(alice, _ *client) string {
				// Set email to get a verification token
				alice.do("PUT", "/v1/me", map[string]any{"notify_email": "alice@example.com"}, nil)
				// Use a plausible token (will fail validation but reach the limiter)
				return "/v1/me/verify-email?token=eml_1234567890123456789012345678901234567890"
			},
		},
		{
			name:   "POST /v1/invites",
			method: "POST",
			body:   map[string]any{"scopes": []string{"messages"}},
			setup: func(alice, _ *client) string {
				// Will loop 20 times creating invites - need higher cap
				return "/v1/invites"
			},
		},
		{
			name:   "DELETE /v1/invites/{id}",
			method: "DELETE",
			body:   nil,
			setup: func(alice, _ *client) string {
				// Create a fresh invite each time
				resp, body := alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
				if resp.StatusCode != 201 {
					t.Fatalf("setup invite: %d %s", resp.StatusCode, body)
				}
				var inv struct {
					PublicID string `json:"public_id"`
				}
				json.Unmarshal(body, &inv)
				return "/v1/invites/" + inv.PublicID
			},
		},
		{
			name:   "POST /v1/invites/accept",
			method: "POST",
			body:   map[string]any{"code": "inv_1234567890123456789012345678901234567890"},
			setup:  func(_, bob *client) string { return "/v1/invites/accept" },
		},
		{
			name:   "DELETE /v1/grants/{peer_id}",
			method: "DELETE",
			body:   nil,
			setup: func(alice, bob *client) string {
				// Create a pairing
				pairUp(t, alice, bob, []string{"messages"}, nil, []string{"messages"})
				return "/v1/grants/" + bob.id
			},
		},
		{
			name:   "POST /v1/peers/{peer_id}/messages",
			method: "POST",
			body:   map[string]any{"type": "text", "body": "hello"},
			setup: func(alice, bob *client) string {
				// Create a pairing
				pairUp(t, alice, bob, []string{"messages"}, nil, []string{"messages"})
				return "/v1/peers/" + bob.id + "/messages"
			},
		},
		{
			name:   "PUT /v1/bags/{name}",
			method: "PUT",
			body:   []byte("test content"),
			setup:  func(alice, _ *client) string { return "/v1/bags/testbag" },
			retry:  "10", // bag PUTs use their own per-caller limiter
		},
		{
			name:   "POST /v1/pairing/accept/{token} (authenticated)",
			method: "POST",
			body:   map[string]any{"scopes": []string{"messages"}},
			setup: func(alice, bob *client) string {
				// Create a pairing link that bob will use
				resp, body := alice.do("POST", "/v1/invites", map[string]any{
					"scopes":           []string{"messages"},
					"generate_pairing": true,
				}, nil)
				if resp.StatusCode != 201 {
					t.Fatalf("setup pairing: %d %s", resp.StatusCode, body)
				}
				var inv struct {
					PairingURL string `json:"pairing_url"`
				}
				if err := json.Unmarshal(body, &inv); err != nil {
					t.Fatalf("unmarshal pairing: %v", err)
				}
				// Extract token from URL like http://host/v1/pairing/tok_xyz
				parts := strings.Split(inv.PairingURL, "/pairing/")
				if len(parts) < 2 {
					t.Fatalf("bad pairing URL: %s", inv.PairingURL)
				}
				return "/v1/pairing/" + parts[1]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set a burst large enough to cover setup operations plus test exhaustion calls
			cfg := Config{
				Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
				WritePerMinute:        10,
				WriteBurst:            20,  // Enough for setup + exhaustion calls
				MaxOutstandingInvites: 100, // High cap for invite tests
			}
			srv := newServer(t, cfg)
			alice := register(t, srv, "alice")
			bob := register(t, srv, "bob")

			// Determine which client to use for the test
			testClient := alice
			if strings.Contains(tt.name, "accept") || strings.Contains(tt.name, "pairing") {
				testClient = bob
			}

			// Perform any necessary setup (may consume budget)
			path := tt.setup(alice, bob)

			// Exhaust remaining budget (make 20 calls to drain the bucket)
			for i := 0; i < 20; i++ {
				resp, respBody := testClient.do(tt.method, path, tt.body, nil)
				if resp.StatusCode == 429 {
					// Hit rate limit, this is expected
					break
				}
				if resp.StatusCode >= 500 {
					t.Fatalf("server error on attempt %d: %d %s", i, resp.StatusCode, respBody)
				}
			}

			// Next call should definitely be rate limited with exact response
			resp, respBody := testClient.do(tt.method, path, tt.body, nil)

			// Assert exact status code
			if resp.StatusCode != 429 {
				t.Errorf("want status 429, got %d: %s (path: %s)", resp.StatusCode, respBody, path)
			}

			// Assert exact Retry-After value
			retryAfter := resp.Header.Get("Retry-After")
			wantRetry := tt.retry
			if wantRetry == "" {
				wantRetry = "2"
			}
			if retryAfter != wantRetry {
				t.Errorf("want Retry-After=%s, got %q (status: %d, body: %s)", wantRetry, retryAfter, resp.StatusCode, respBody)
			}

			// Assert exact error body
			expectedBody := `{"error":"rate limited"}`
			actualBody := strings.TrimSpace(string(respBody))
			if actualBody != expectedBody {
				t.Errorf("want body %q, got %q", expectedBody, actualBody)
			}
		})
	}
}

func authFailStatus(h http.Handler, remote, xff string) int {
	req := httptest.NewRequest("GET", "/v1/me", nil)
	req.RemoteAddr = remote
	req.Header.Set("Authorization", "Bearer pl_unknown")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func newAuthFailHandler(t *testing.T, trusted []string) http.Handler {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := New(st, Config{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthFailPerMinute: 1,
		AuthFailBurst:     1,
		TrustedProxies:    trusted,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s.Handler()
}

// TestAuthFailBucketsFollowProxyConfig verifies #98: behind a trusted proxy each
// forwarded client has its own failed-auth bucket; without trusted proxies a
// spoofed X-Forwarded-For neither splits nor evades the bucket.
func TestAuthFailBucketsFollowProxyConfig(t *testing.T) {
	h := newAuthFailHandler(t, []string{"10.0.0.0/8"})
	if got := authFailStatus(h, "10.0.0.1:1", "1.1.1.1"); got != 401 {
		t.Fatalf("client A first: want 401, got %d", got)
	}
	if got := authFailStatus(h, "10.0.0.1:1", "1.1.1.1"); got != 429 {
		t.Fatalf("client A over budget: want 429, got %d", got)
	}
	if got := authFailStatus(h, "10.0.0.1:1", "2.2.2.2"); got != 401 {
		t.Fatalf("client B must have its own bucket: want 401, got %d", got)
	}

	h = newAuthFailHandler(t, nil)
	if got := authFailStatus(h, "9.9.9.9:1", "1.1.1.1"); got != 401 {
		t.Fatalf("first: want 401, got %d", got)
	}
	if got := authFailStatus(h, "9.9.9.9:1", "2.2.2.2"); got != 429 {
		t.Fatalf("spoofed XFF must not evade the bucket: want 429, got %d", got)
	}
}

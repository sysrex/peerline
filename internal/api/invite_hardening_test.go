package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
)

// TestRevokePreventsPairingGetAndPost verifies that after revoking a pairing
// invite via DELETE /v1/invites/{id}, both GET and POST on the pairing URL
// return 404. This closes the gap identified in issue #59 and #66.
// Positive control: POST after revoke (issue #169).
func TestRevokePreventsPairingGetAndPost(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:                slog.Default(),
		MaxOutstandingInvites: 10,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	// Register a peer and create a pairing invite
	alice := register(t, srv, "alice")
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)

	var invResp struct {
		PublicID   string `json:"public_id"`
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(body, &invResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}
	if invResp.PublicID == "" || invResp.PairingURL == "" {
		t.Fatalf("missing public_id or pairing_url: %s", body)
	}

	// Extract the pairing token from the URL
	// URL format: /v1/pairing/{token}
	pairingPath := invResp.PairingURL[len(srv.URL):]

	// Positive control: verify the pairing link is accessible before revoke
	resp, body = alice.do("GET", pairingPath, nil, nil)
	want(t, resp, body, 200)

	// Positive control: POST before revoke succeeds (authenticated)
	bob := register(t, srv, "bob")
	resp, body = bob.do("POST", pairingPath, map[string]any{
		"scopes": []string{},
	}, nil)
	want(t, resp, body, 200)

	// Create a new pairing invite for the revoke tests
	resp, body = alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)
	if err := json.Unmarshal(body, &invResp); err != nil {
		t.Fatalf("unmarshal second invite response: %v", err)
	}
	pairingPath = invResp.PairingURL[len(srv.URL):]

	// Revoke the invite
	resp, body = alice.do("DELETE", "/v1/invites/"+invResp.PublicID, nil, nil)
	want(t, resp, body, 204)

	// After revoke, GET on the pairing URL must return 404
	resp, body = alice.do("GET", pairingPath, nil, nil)
	want(t, resp, body, 404)

	// After revoke, authenticated POST on the pairing URL must also return 404
	resp, body = bob.do("POST", pairingPath, map[string]any{
		"scopes": []string{},
	}, nil)
	want(t, resp, body, 404)

	// After revoke, unauthenticated POST must also return 404
	charlie := &client{t: t, srv: srv}
	resp, body = charlie.do("POST", pairingPath, map[string]any{
		"name": "charlie",
	}, nil)
	want(t, resp, body, 404)
}

// TestConcurrentInviteCapAtAPILevel verifies that when N goroutines
// concurrently create invites with a cap of C, exactly C succeed and the
// rest are rejected with 429. This tests atomicity at the API layer, closing
// the gap from issue #59.
func TestConcurrentInviteCapAtAPILevel(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const cap = 3
	const concurrency = 10

	cfg := Config{
		Logger:                slog.Default(),
		MaxOutstandingInvites: cap,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	alice := register(t, srv, "alice")

	// Launch concurrent invite creation attempts
	var wg sync.WaitGroup
	results := make(chan int, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := alice.do("POST", "/v1/invites", map[string]any{
				"scopes": []string{"messages"},
			}, nil)
			results <- resp.StatusCode
		}()
	}

	wg.Wait()
	close(results)

	// Count successes and rejections
	created := 0
	tooMany := 0
	for code := range results {
		switch code {
		case 201:
			created++
		case 429:
			tooMany++
		default:
			t.Errorf("unexpected status code: %d", code)
		}
	}

	// Exactly cap invites must succeed
	if created != cap {
		t.Errorf("expected %d invites created, got %d", cap, created)
	}
	// The rest must be rejected
	if tooMany != concurrency-cap {
		t.Errorf("expected %d rejections, got %d", concurrency-cap, tooMany)
	}
}

// capturingMailer implements mailer.Sender and records all sent messages.
type capturingMailer struct {
	mu   sync.Mutex
	sent []mailer.Message
}

func (c *capturingMailer) Send(_ context.Context, m mailer.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, m)
	return nil
}

func (c *capturingMailer) Mode() string {
	return "test"
}

func (c *capturingMailer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// TestCapBeforeEmailBudget verifies that when an invite creation is rejected
// due to the cap, the email budget is not consumed. A subsequent uncapped
// invite with to_email still succeeds in sending the email. This closes the
// gap from issue #66.
func TestCapBeforeEmailBudget(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	capturer := &capturingMailer{}
	cfg := Config{
		Logger:                slog.Default(),
		MaxOutstandingInvites: 1,
		EmailPerHour:          1, // Only one email allowed per hour
		EmailBurst:            1,
		EmailRcptPerHour:      10,
		Mailer:                capturer,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	alice := register(t, srv, "alice")

	// Create the first invite (succeeds, consumes cap slot but no email)
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 201)

	// No email sent yet
	if capturer.count() != 0 {
		t.Errorf("expected 0 emails sent, got %d", capturer.count())
	}

	// Attempt to create a second invite with to_email (rejected by cap)
	resp, body = alice.do("POST", "/v1/invites", map[string]any{
		"scopes":   []string{"messages"},
		"to_email": "test@example.com",
	}, nil)
	want(t, resp, body, 429)

	// Email budget must NOT be consumed by the rejected request
	if capturer.count() != 0 {
		t.Errorf("expected 0 emails sent after cap rejection, got %d", capturer.count())
	}

	// Revoke the first invite to free the cap slot
	var firstInvite struct {
		PublicID string `json:"public_id"`
	}
	// We need to get the public_id from the first invite
	resp, body = alice.do("GET", "/v1/invites", nil, nil)
	want(t, resp, body, 200)
	var listResp struct {
		Invites []struct {
			PublicID string `json:"public_id"`
		} `json:"invites"`
	}
	if err := json.Unmarshal(body, &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(listResp.Invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(listResp.Invites))
	}
	firstInvite.PublicID = listResp.Invites[0].PublicID

	resp, body = alice.do("DELETE", "/v1/invites/"+firstInvite.PublicID, nil, nil)
	want(t, resp, body, 204)

	// Now create a new invite with to_email (should succeed and send email)
	resp, body = alice.do("POST", "/v1/invites", map[string]any{
		"scopes":   []string{"messages"},
		"to_email": "success@example.com",
	}, nil)
	want(t, resp, body, 201)

	// Email budget was preserved, so email should be sent
	if capturer.count() != 1 {
		t.Errorf("expected 1 email sent after successful invite, got %d", capturer.count())
	}
}

// TestGETLimiterSeparateBuckets verifies that two clients behind a trusted
// proxy with different X-Forwarded-For headers get separate getLim buckets,
// and the same client shares one bucket. Uses frozen clock for deterministic
// behavior. Closes issue #168.
func TestGETLimiterSeparateBuckets(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:         slog.Default(),
		TrustedProxies: []string{"10.0.0.0/8"},
	}
	srv := New(st, cfg)

	// Freeze clock to avoid wall-clock refill
	clock := time.Unix(1000, 0)
	srv.lim.SetClock(func() time.Time { return clock })

	handler := srv.Handler()

	// Helper to make a rate-limited GET request
	makeRequest := func(clientIP string) (*httptest.ResponseRecorder, []byte) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345" // Trusted proxy
		req.Header.Set("X-Forwarded-For", clientIP)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr, rr.Body.Bytes()
	}

	// Exhaust client 1's bucket: GetBurst=20, so 20 requests succeed
	for i := 0; i < GetBurst; i++ {
		rr, body := makeRequest("1.2.3.4")
		if rr.Code != 200 {
			t.Fatalf("request %d from client 1: expected 200, got %d: %s", i+1, rr.Code, body)
		}
	}

	// Request GetBurst+1 should be rate limited with Retry-After header
	rr, body := makeRequest("1.2.3.4")
	if rr.Code != 429 {
		t.Errorf("request %d from client 1: expected 429 (rate limited), got %d", GetBurst+1, rr.Code)
	}
	if ra := rr.Header().Get("Retry-After"); ra != GetRetryAfter {
		t.Errorf("expected Retry-After: %s, got %q", GetRetryAfter, ra)
	}
	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Errorf("unmarshal 429 body: %v", err)
	} else if errResp["error"] != "rate limited" {
		t.Errorf("expected uniform 429 body {\"error\":\"rate limited\"}, got %v", errResp)
	}

	// Client 2 with a different IP should have its own bucket and not be blocked
	rr, body = makeRequest("5.6.7.8")
	if rr.Code != 200 {
		t.Errorf("client 2 (different IP) should not be rate limited, got %d: %s", rr.Code, body)
	}

	// Client 1 with the same IP should still be blocked
	rr, body = makeRequest("1.2.3.4")
	if rr.Code != 429 {
		t.Errorf("client 1 should still be rate limited, got %d", rr.Code)
	}
	if ra := rr.Header().Get("Retry-After"); ra != GetRetryAfter {
		t.Errorf("client 1 retry: expected Retry-After: %s, got %q", GetRetryAfter, ra)
	}
}

// TestUntrustedClientRotatingXFF verifies that an untrusted client sending
// spoofed or rotating X-Forwarded-For headers does not get fresh buckets.
// The limiter must key on the RemoteAddr, not the XFF. Closes issue #169.
func TestUntrustedClientRotatingXFF(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:         slog.Default(),
		TrustedProxies: []string{"10.0.0.0/8"}, // Only 10.0.0.0/8 is trusted
	}
	srv := New(st, cfg)

	// Freeze clock
	clock := time.Unix(1000, 0)
	srv.lim.SetClock(func() time.Time { return clock })

	handler := srv.Handler()

	// Untrusted client at 203.0.113.50 (not in 10.0.0.0/8)
	makeRequest := func(spoofedXFF string) (*httptest.ResponseRecorder, []byte) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.50:12345" // Untrusted RemoteAddr
		if spoofedXFF != "" {
			req.Header.Set("X-Forwarded-For", spoofedXFF)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr, rr.Body.Bytes()
	}

	// Exhaust the bucket with GetBurst requests
	for i := 0; i < GetBurst; i++ {
		rr, body := makeRequest("1.1.1.1") // Spoofed XFF
		if rr.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d: %s", i+1, rr.Code, body)
		}
	}

	// Next request should be rate limited, even with a different spoofed XFF
	rr, body := makeRequest("2.2.2.2") // Rotate to different spoofed IP
	if rr.Code != 429 {
		t.Errorf("untrusted client rotating XFF: expected 429, got %d (bucket should not be fresh)", rr.Code)
	}
	if ra := rr.Header().Get("Retry-After"); ra != GetRetryAfter {
		t.Errorf("expected Retry-After: %s, got %q", GetRetryAfter, ra)
	}
	var errResp map[string]string
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Errorf("unmarshal 429 body: %v", err)
	} else if errResp["error"] != "rate limited" {
		t.Errorf("expected uniform 429 body, got %v", errResp)
	}

	// One more rotation attempt
	rr, body = makeRequest("3.3.3.3")
	if rr.Code != 429 {
		t.Errorf("untrusted client with third XFF: expected 429, got %d", rr.Code)
	}
}

// TestAnonymousGETDoesNotBlockAuthenticatedInbox verifies that an anonymous
// client exhausting GET / does not cause 429 for authenticated peers polling
// /v1/inbox. This closes the gap from issue #31/#129. Uses frozen clock.
func TestAnonymousGETDoesNotBlockAuthenticatedInbox(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger: slog.Default(),
	}
	s := New(st, cfg)

	// Freeze clock on the server's limiter manager
	clock := time.Unix(1000, 0)
	s.lim.SetClock(func() time.Time { return clock })

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Register two peers
	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")

	// Anonymous client exhausts GET / (public GET limiter)
	anon := &client{t: t, srv: srv}
	gotRateLimited := false
	for i := 0; i < GetBurst+5; i++ {
		resp, body := anon.do("GET", "/", nil, nil)
		if resp.StatusCode == 429 {
			gotRateLimited = true
			// Assert Retry-After header and uniform body
			if ra := resp.Header.Get("Retry-After"); ra != GetRetryAfter {
				t.Errorf("anonymous GET: expected Retry-After: %s, got %q", GetRetryAfter, ra)
			}
			var errResp map[string]string
			if err := json.Unmarshal(body, &errResp); err != nil {
				t.Errorf("unmarshal 429 body: %v", err)
			} else if errResp["error"] != "rate limited" {
				t.Errorf("expected uniform 429 body, got %v", errResp)
			}
			break
		}
	}

	// Fail if we never exhausted the limiter
	if !gotRateLimited {
		t.Fatal("anonymous client never got rate limited; test is vacuous")
	}

	// Alice and Bob polling /v1/inbox should not be affected (different limiter)
	resp, body := alice.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 200)

	resp, body = bob.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 200)
}

// TestAcceptByCodeAfterRevoke verifies that accepting an invite by code
// after revoke returns 404. This closes the gap from issue #33/#129.
func TestAcceptByCodeAfterRevoke(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:                slog.Default(),
		MaxOutstandingInvites: 10,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	// Register peers
	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")

	// Alice creates an invite
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 201)

	var invResp struct {
		Code     string `json:"code"`
		PublicID string `json:"public_id"`
	}
	if err := json.Unmarshal(body, &invResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}

	// Alice revokes the invite
	resp, body = alice.do("DELETE", "/v1/invites/"+invResp.PublicID, nil, nil)
	want(t, resp, body, 204)

	// Bob tries to accept using the code (should return 404)
	resp, body = bob.do("POST", "/v1/invites/accept", map[string]any{
		"code": invResp.Code,
	}, nil)
	want(t, resp, body, 404)
}

// TestDeleteUsedInviteReturns404 verifies that attempting to delete an
// already-used invite returns 404. This closes the gap from issue #33/#129.
func TestDeleteUsedInviteReturns404(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:                slog.Default(),
		MaxOutstandingInvites: 10,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	// Register peers
	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")

	// Alice creates an invite
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 201)

	var invResp struct {
		Code     string `json:"code"`
		PublicID string `json:"public_id"`
	}
	if err := json.Unmarshal(body, &invResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}

	// Bob accepts the invite
	resp, body = bob.do("POST", "/v1/invites/accept", map[string]any{
		"code": invResp.Code,
	}, nil)
	want(t, resp, body, 200)

	// Alice tries to delete the used invite (should return 404)
	resp, body = alice.do("DELETE", "/v1/invites/"+invResp.PublicID, nil, nil)
	want(t, resp, body, 404)
}

// TestSingleLogRecordUnauthenticatedPairing verifies that exactly one log
// record is emitted when redeeming a pairing link (unauthenticated), not just
// that the message string appears once. Uses syncBuf for concurrency safety.
// This closes the gap from issue #54/#129.
func TestSingleLogRecordUnauthenticatedPairing(t *testing.T) {
	var buf syncBuf
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		Logger:                logger,
		MaxOutstandingInvites: 10,
	}
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	// Register a peer and create a pairing invite
	alice := register(t, srv, "alice")
	resp, body := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)

	var invResp struct {
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(body, &invResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}

	pairingPath := invResp.PairingURL[len(srv.URL):]

	// Clear buffer before the pairing action
	buf.Reset()

	// Redeem pairing link (unauthenticated)
	anon := &client{t: t, srv: srv}
	resp, body = anon.do("POST", pairingPath, map[string]any{
		"name": "bob",
	}, nil)
	want(t, resp, body, 201)

	// Parse log output and count total records with the pairing message
	logs := buf.String()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	pairingRecords := 0
	totalRecords := 0

	for _, line := range lines {
		if line == "" {
			continue
		}
		totalRecords++
		if strings.Contains(line, `"msg":"peer registered and paired"`) {
			pairingRecords++
		}
	}

	// Assert exactly one total record with the pairing message
	if pairingRecords != 1 {
		t.Errorf("expected exactly 1 'peer registered and paired' log record, got %d\nLogs:\n%s", pairingRecords, logs)
	}

	// For extra safety, verify no duplicate messages of any kind
	// (a second differently-worded line would indicate a bug)
	if totalRecords > 1 {
		t.Errorf("expected 1 total log record for pairing, got %d\nLogs:\n%s", totalRecords, logs)
	}
}

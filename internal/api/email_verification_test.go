package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestEmailVerificationIdenticalFailures tests that all verification failures return byte-identical 404s.
func TestEmailVerificationIdenticalFailures(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	// Register and get tokens
	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	bob := &client{t: t, srv: srv}
	resp, body = bob.do("POST", "/v1/register", map[string]string{"name": "bob", "notify_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&bob.id, &bob.key})

	// Extract alice's token
	msgs := cap.all()
	var aliceToken string
	for _, m := range msgs {
		if m.To == "alice@example.com" {
			aliceToken = extractVerifyToken(m.Body)
			if aliceToken != "" {
				break
			}
		}
	}

	// Test 1: Wrong token
	resp1, body1 := alice.do("POST", "/v1/me/verify-email?token=eml_wrongtoken", nil, nil)

	// Test 2: Bob trying alice's token (wrong peer)
	resp2, body2 := bob.do("POST", "/v1/me/verify-email?token="+aliceToken, nil, nil)

	// Test 3: Alice uses correct token (succeeds)
	resp3, body3 := alice.do("POST", "/v1/me/verify-email?token="+aliceToken, nil, nil)
	want(t, resp3, body3, 200)

	// Test 4: Alice tries same token again (already used)
	resp4, body4 := alice.do("POST", "/v1/me/verify-email?token="+aliceToken, nil, nil)

	// Test 5: Missing token
	resp5, body5 := alice.do("POST", "/v1/me/verify-email", nil, nil)

	// All failures must return identical 404s
	failures := []struct {
		name string
		code int
		body []byte
	}{
		{"wrong token", resp1.StatusCode, body1},
		{"wrong peer", resp2.StatusCode, body2},
		{"already used", resp4.StatusCode, body4},
		{"missing token", resp5.StatusCode, body5},
	}

	var canonical []byte
	for i, f := range failures {
		if f.code != 404 {
			t.Errorf("%s: got status %d, want 404", f.name, f.code)
		}
		if i == 0 {
			canonical = f.body
		} else if !bytes.Equal(f.body, canonical) {
			t.Errorf("%s: body differs from canonical\n  got:  %s\n  want: %s", f.name, f.body, canonical)
		}
	}
}

// TestVerificationEmailRateLimit tests per-peer and per-address rate limiting of verification emails.
func TestVerificationEmailRateLimit(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	alice := register(t, srv, "alice")

	// Set notify_email 3 times (hits per-peer limit of 3/hour)
	for i := 0; i < 3; i++ {
		resp, body := alice.do("PUT", "/v1/me", map[string]string{"notify_email": "alice@example.com"}, nil)
		want(t, resp, body, 200)
	}

	// 4th attempt should be rate limited
	resp, body := alice.do("PUT", "/v1/me", map[string]string{"notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 429)
	if !strings.Contains(string(body), "rate limited") {
		t.Errorf("unexpected error: %s", body)
	}

	// Verify only 3 emails were sent
	msgs := cap.all()
	count := 0
	for _, m := range msgs {
		if m.To == "alice@example.com" && strings.Contains(m.Subject, "Verify") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("sent %d verification emails, want 3", count)
	}
}

// TestPerAddressVerificationRateLimit tests that per-address rate limiting applies to verification emails.
func TestPerAddressVerificationRateLimit(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")

	// Alice sets email twice
	for i := 0; i < 2; i++ {
		resp, body := alice.do("PUT", "/v1/me", map[string]string{"notify_email": "shared@example.com"}, nil)
		want(t, resp, body, 200)
	}

	// Bob sets same email twice - should hit per-address limit on 2nd attempt
	for i := 0; i < 2; i++ {
		resp, body := bob.do("PUT", "/v1/me", map[string]string{"notify_email": "shared@example.com"}, nil)
		if i == 0 {
			want(t, resp, body, 200)
		} else {
			// Should hit per-address limit
			want(t, resp, body, 429)
		}
	}

	// Verify per-address limit was applied
	msgs := cap.all()
	count := 0
	for _, m := range msgs {
		if m.To == "shared@example.com" && strings.Contains(m.Subject, "Verify") {
			count++
		}
	}
	// Should respect per-address limit (3 total)
	if count > 3 {
		t.Errorf("sent %d emails to same address, expected <= 3 due to per-address limit", count)
	}
}

// TestUnverifiedEmailNoNotifications tests that unverified emails don't receive notifications.
func TestUnverifiedEmailNoNotifications(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	alice := register(t, srv, "alice")
	bob := &client{t: t, srv: srv}
	resp, body := bob.do("POST", "/v1/register", map[string]string{"name": "bob", "notify_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&bob.id, &bob.key})

	// Bob grants Alice messages
	pairUp(t, bob, alice, []string{"messages"}, nil, nil)

	// Clear verification emails
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()

	// Alice sends message to Bob - no notification should be sent (unverified)
	resp, body = alice.do("POST", "/v1/peers/"+bob.id+"/messages", map[string]any{"type": "note", "body": "hello"}, nil)
	want(t, resp, body, 201)

	msgs := cap.all()
	if len(msgs) != 0 {
		t.Fatalf("expected 0 notifications to unverified email, got %d", len(msgs))
	}
}

// TestTokenNotInLogs verifies tokens are never logged.
func TestTokenNotInLogs(t *testing.T) {
	var logs syncBuf
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, Logger: slog.New(slog.NewTextHandler(&logs, nil))})

	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	// Extract token from email
	msgs := cap.all()
	var token string
	for _, m := range msgs {
		if m.To == "alice@example.com" {
			token = extractVerifyToken(m.Body)
			if token != "" {
				break
			}
		}
	}

	// Verify
	resp, body = alice.do("POST", "/v1/me/verify-email?token="+token, nil, nil)
	want(t, resp, body, 200)

	// Check logs don't contain the token
	logStr := logs.String()
	if strings.Contains(logStr, token) {
		t.Errorf("token %q found in logs:\n%s", token, logStr)
	}
	// Check for the token pattern (should not appear anywhere in logs)
	if strings.Contains(logStr, "eml_") {
		t.Errorf("token pattern eml_ found in logs:\n%s", logStr)
	}
}

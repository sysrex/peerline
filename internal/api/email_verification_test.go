package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEmailVerification tests the full email verification flow.
func TestEmailVerification(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})
	
	// Register with email
	c := &client{t: t, srv: srv}
	resp, body := c.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	var reg struct {
		PeerID   string `json:"peer_id"`
		APIKey   string `json:"api_key"`
		Verified bool   `json:"verified"`
	}
	json.Unmarshal(body, &reg)
	c.id, c.key = reg.PeerID, reg.APIKey
	
	if reg.Verified {
		t.Fatal("email should be unverified initially")
	}
	
	// Check verification email was sent
	msgs := cap.all()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 verification email, got %d", len(msgs))
	}
	if msgs[0].To != "alice@example.com" {
		t.Fatalf("verification email to %q", msgs[0].To)
	}
	if !strings.Contains(msgs[0].Subject, "Verify your email") {
		t.Fatalf("unexpected subject: %s", msgs[0].Subject)
	}
	
	// Extract token from email body
	body_text := msgs[0].Body
	if !strings.Contains(body_text, "/v1/me/verify-email?token=eml_") {
		t.Fatal("verification link not in email")
	}
	tokenStart := strings.Index(body_text, "token=eml_") + 6
	tokenEnd := strings.Index(body_text[tokenStart:], "\n")
	if tokenEnd == -1 {
		tokenEnd = strings.Index(body_text[tokenStart:], " ")
	}
	token := body_text[tokenStart : tokenStart+tokenEnd]
	
	// Verify email
	resp, body = c.do("POST", "/v1/me/verify-email?token="+token, nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), "verified") {
		t.Fatalf("unexpected verify response: %s", body)
	}
	
	// Check verified status
	resp, body = c.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	var me struct {
		NotifyEmail string `json:"notify_email"`
		Verified    bool   `json:"verified"`
	}
	json.Unmarshal(body, &me)
	if !me.Verified {
		t.Fatal("email should be verified")
	}
	if me.NotifyEmail != "alice@example.com" {
		t.Fatalf("notify_email: %q", me.NotifyEmail)
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

// TestEmailVerificationInvalidToken tests rejection of invalid tokens.
func TestEmailVerificationInvalidToken(t *testing.T) {
	srv := newServer(t, Config{})
	c := register(t, srv, "alice")
	
	// Try with invalid token
	resp, body := c.do("POST", "/v1/me/verify-email?token=eml_invalid", nil, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "invalid") {
		t.Fatalf("unexpected error: %s", body)
	}
}

// TestPerAddressRateLimit tests that multiple peers can't bypass rate limits.
func TestPerAddressRateLimit(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, NotifyPerHour: 2, NotifyBurst: 2})
	
	alice := register(t, srv, "alice")
	
	// Register two peers with the same email
	bob1 := registerAndVerify(t, srv, "bob1", "shared@example.com")
	bob2 := registerAndVerify(t, srv, "bob2", "shared@example.com")
	
	// Extract and verify bob1's email
	msgs := cap.all()
	var token1, token2 string
	for _, m := range msgs {
		if m.To == "shared@example.com" && strings.Contains(m.Body, bob1.id) {
			tokenStart := strings.Index(m.Body, "token=eml_") + 6
			tokenEnd := strings.Index(m.Body[tokenStart:], "\n")
			if tokenEnd == -1 {
				tokenEnd = strings.Index(m.Body[tokenStart:], " ")
			}
			token1 = m.Body[tokenStart : tokenStart+tokenEnd]
		}
		if m.To == "shared@example.com" && strings.Contains(m.Body, bob2.id) {
			tokenStart := strings.Index(m.Body, "token=eml_") + 6
			tokenEnd := strings.Index(m.Body[tokenStart:], "\n")
			if tokenEnd == -1 {
				tokenEnd = strings.Index(m.Body[tokenStart:], " ")
			}
			token2 = m.Body[tokenStart : tokenStart+tokenEnd]
		}
	}
	
	// Verify both
	resp, body := bob1.do("POST", "/v1/me/verify-email?token="+token1, nil, nil)
	want(t, resp, body, 200)
	resp, body = bob2.do("POST", "/v1/me/verify-email?token="+token2, nil, nil)
	want(t, resp, body, 200)
	
	// Clear verification emails
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()
	
	// Grant messages
	pairUp(t, bob1, alice, []string{"messages"}, nil, nil)
	pairUp(t, bob2, alice, []string{"messages"}, nil, nil)
	
	// Send messages - should respect per-address limit
	resp, body = alice.do("POST", "/v1/peers/"+bob1.id+"/messages", map[string]any{"type": "note", "body": "msg1"}, nil)
	want(t, resp, body, 201)
	
	resp, body = alice.do("POST", "/v1/peers/"+bob2.id+"/messages", map[string]any{"type": "note", "body": "msg2"}, nil)
	want(t, resp, body, 201)
	
	msgs = cap.all()
	// Should only send 2 notifications (the per-address limit), not 2 per peer
	if len(msgs) != 2 {
		t.Fatalf("expected 2 notifications (per-address limit), got %d", len(msgs))
	}
	
	// Third message should be rate-limited by per-address limit
	resp, body = alice.do("POST", "/v1/peers/"+bob1.id+"/messages", map[string]any{"type": "note", "body": "msg3"}, nil)
	want(t, resp, body, 201)
	
	msgs = cap.all()
	if len(msgs) != 2 {
		t.Fatalf("expected still 2 notifications (rate limited), got %d", len(msgs))
	}
}

// Helper to register and verify an email
func registerAndVerify(t *testing.T, srv *httptest.Server, name, email string) *client {
	t.Helper()
	// We need to use the provided server's mailer to get verification emails
	// For testing, we'll register, manually verify using the store
	c := &client{t: t, srv: srv}
	resp, body := c.do("POST", "/v1/register", map[string]string{"name": name, "notify_email": email}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("register failed: %d %s", resp.StatusCode, body)
	}
	var reg struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	json.Unmarshal(body, &reg)
	c.id, c.key = reg.PeerID, reg.APIKey
	
	// For testing: manually verify by getting the token from GET /v1/me
	// Actually, we need to extract the token from the verification email
	// Since we're using a capture mailer in the test, we need to pass it in
	// Let me rethink this...
	// The issue is we can't easily get the mailer from the server
	// So let's just have the test extract and verify the token itself
	
	return c
}

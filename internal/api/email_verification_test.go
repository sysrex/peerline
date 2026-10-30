package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/auth"
)

// TestEmailVerificationIdenticalFailures tests that all verification failures return byte-identical 404s.
func TestEmailVerificationIdenticalFailures(t *testing.T) {
	cap := &captureMailer{}
	srv, _, st := newServerWithAccess(t, Config{Mailer: cap})

	// Helper to write token directly to DB
	writeToken := func(peerID, token string) {
		_, err := st.DB().Exec(`UPDATE peers SET notify_email_token=? WHERE id=?`, token, peerID)
		if err != nil {
			t.Fatal(err)
		}
	}

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

	carol := &client{t: t, srv: srv}
	resp, body = carol.do("POST", "/v1/register", map[string]string{"name": "carol", "notify_email": "carol@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&carol.id, &carol.key})

	dave := &client{t: t, srv: srv}
	resp, body = dave.do("POST", "/v1/register", map[string]string{"name": "dave", "notify_email": "dave@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&dave.id, &dave.key})

	eve := &client{t: t, srv: srv}
	resp, body = eve.do("POST", "/v1/register", map[string]string{"name": "eve", "notify_email": "eve@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&eve.id, &eve.key})

	// Extract alice's token
	msgs := cap.all()
	var aliceToken string
	var eveToken string
	for _, m := range msgs {
		if m.To == "alice@example.com" {
			aliceToken = extractVerifyToken(m.Body)
		}
		if m.To == "eve@example.com" {
			eveToken = extractVerifyToken(m.Body)
		}
	}

	// Write an expired token for eve (issued more than 24 hours ago)
	now := time.Now().Unix()
	expiredIssuedTime := now - 86401
	expiredTokenValue := fmt.Sprintf("%d:%s", expiredIssuedTime, auth.Hash(eveToken))
	_, err := st.DB().Exec(`UPDATE peers SET notify_email_token=? WHERE id=?`, expiredTokenValue, eve.id)
	if err != nil {
		t.Fatal(err)
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

	// Test 6: Legacy plaintext token
	writeToken(carol.id, "eml_plaintext_legacy")
	resp6, body6 := carol.do("POST", "/v1/me/verify-email?token=eml_plaintext_legacy", nil, nil)

	// Test 7: Malformed token (not timestamp:hash)
	writeToken(dave.id, "malformed:value")
	resp7, body7 := dave.do("POST", "/v1/me/verify-email?token=anything", nil, nil)

	// Test 8: Expired token
	resp8, body8 := eve.do("POST", "/v1/me/verify-email?token="+eveToken, nil, nil)

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
		{"legacy plaintext", resp6.StatusCode, body6},
		{"malformed", resp7.StatusCode, body7},
		{"expired", resp8.StatusCode, body8},
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

// TestVerificationEmailRateLimit tests per-peer rate limiting of verification emails.
func TestVerificationEmailRateLimit(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	alice := register(t, srv, "alice")

	// Set notify_email 3 times with different addresses (hits per-peer limit of 3/hour)
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("alice%d@example.com", i)
		resp, body := alice.do("PUT", "/v1/me", map[string]string{"notify_email": addr}, nil)
		want(t, resp, body, 200)
	}

	// 4th attempt should be rate limited (per-peer, even with a new address)
	resp, body := alice.do("PUT", "/v1/me", map[string]string{"notify_email": "alice3@example.com"}, nil)
	want(t, resp, body, 429)
	if !strings.Contains(string(body), "rate limited") {
		t.Errorf("unexpected error: %s", body)
	}

	// Verify only 3 emails were sent
	msgs := cap.all()
	count := 0
	for _, m := range msgs {
		if strings.Contains(m.Subject, "Verify") {
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

// TestEmailVerificationExpiry tests that tokens expire after 24 hours.
func TestEmailVerificationExpiry(t *testing.T) {
	cap := &captureMailer{}
	srv, _, st := newServerWithAccess(t, Config{Mailer: cap})

	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	// Extract token
	msgs := cap.all()
	token := extractVerifyToken(msgs[0].Body)

	// Test 1: Write a token that's still valid (issued exactly 86400 seconds ago = 24 hours)
	now := time.Now().Unix()
	validIssuedTime := now - 86400 // exactly 24 hours ago
	validTokenValue := fmt.Sprintf("%d:%s", validIssuedTime, auth.Hash(token))
	_, err := st.DB().Exec(`UPDATE peers SET notify_email_token=? WHERE id=?`, validTokenValue, alice.id)
	if err != nil {
		t.Fatal(err)
	}
	resp, body = alice.do("POST", "/v1/me/verify-email?token="+token, nil, nil)
	want(t, resp, body, 200)

	// Test 2: Register bob and test expired token
	bob := &client{t: t, srv: srv}
	resp, body = bob.do("POST", "/v1/register", map[string]string{"name": "bob", "notify_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&bob.id, &bob.key})

	msgs = cap.all()
	bobToken := extractVerifyToken(msgs[len(msgs)-1].Body)

	// Write a token that's expired (issued 86401 seconds ago = 24 hours + 1 second)
	expiredIssuedTime := now - 86401
	expiredTokenValue := fmt.Sprintf("%d:%s", expiredIssuedTime, auth.Hash(bobToken))
	_, err = st.DB().Exec(`UPDATE peers SET notify_email_token=? WHERE id=?`, expiredTokenValue, bob.id)
	if err != nil {
		t.Fatal(err)
	}
	resp, body = bob.do("POST", "/v1/me/verify-email?token="+bobToken, nil, nil)
	want(t, resp, body, 404)
	if !strings.Contains(string(body), "not found") {
		t.Errorf("unexpected error: %s", body)
	}
}

// TestEmailVerificationDBError tests that DB errors return 500, not 404.
// TODO: This test is difficult to implement without mocking because closing the DB
// breaks the auth middleware first. A better approach would be to test the
// Store.VerifyNotifyEmail method directly with a mocked DB connection.
func TestEmailVerificationDBError(t *testing.T) {
	t.Skip("DB error testing requires mocking infrastructure")
}

// TestEmailVerificationLegacyAndMalformed tests that legacy plaintext and malformed tokens fail.
func TestEmailVerificationLegacyAndMalformed(t *testing.T) {
	cap := &captureMailer{}
	srv, _, st := newServerWithAccess(t, Config{Mailer: cap})

	// Helper to write token directly to DB
	writeToken := func(peerID, token string) {
		_, err := st.DB().Exec(`UPDATE peers SET notify_email_token=? WHERE id=?`, token, peerID)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Test legacy plaintext token (from #138)
	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	writeToken(alice.id, "eml_plaintext_from_138")
	resp1, body1 := alice.do("POST", "/v1/me/verify-email?token=eml_plaintext_from_138", nil, nil)

	// Test malformed: "abc:def" (not a valid timestamp)
	bob := &client{t: t, srv: srv}
	resp, body = bob.do("POST", "/v1/register", map[string]string{"name": "bob", "notify_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&bob.id, &bob.key})

	writeToken(bob.id, "abc:def")
	resp2, body2 := bob.do("POST", "/v1/me/verify-email?token=anything", nil, nil)

	// Test malformed: ":" only
	carol := &client{t: t, srv: srv}
	resp, body = carol.do("POST", "/v1/register", map[string]string{"name": "carol", "notify_email": "carol@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&carol.id, &carol.key})

	writeToken(carol.id, ":")
	resp3, body3 := carol.do("POST", "/v1/me/verify-email?token=anything", nil, nil)

	// All should return 404
	for i, test := range []struct {
		name string
		code int
		body []byte
	}{
		{"legacy plaintext", resp1.StatusCode, body1},
		{"malformed abc:def", resp2.StatusCode, body2},
		{"malformed colon-only", resp3.StatusCode, body3},
	} {
		if test.code != 404 {
			t.Errorf("%s: got status %d, want 404", test.name, test.code)
		}
		if i == 0 {
			// Store canonical for comparison
		} else if !bytes.Equal(test.body, body1) {
			t.Errorf("%s: body differs from canonical\n  got:  %s\n  want: %s", test.name, test.body, body1)
		}
	}
}

// TestTokenHashedInDB verifies the DB never stores the raw token.
func TestTokenHashedInDB(t *testing.T) {
	cap := &captureMailer{}
	srv, _, st := newServerWithAccess(t, Config{Mailer: cap})

	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	// Extract token from email
	msgs := cap.all()
	token := extractVerifyToken(msgs[0].Body)

	// Read token from DB
	var dbToken sql.NullString
	err := st.DB().QueryRow(`SELECT notify_email_token FROM peers WHERE id=?`, alice.id).Scan(&dbToken)
	if err != nil {
		t.Fatal(err)
	}
	if !dbToken.Valid {
		t.Fatal("token is NULL in DB")
	}

	// DB should not contain raw token
	if strings.Contains(dbToken.String, token) {
		t.Errorf("DB contains raw token: %s", dbToken.String)
	}

	// DB should contain the hash
	expectedHash := auth.Hash(token)
	if !strings.Contains(dbToken.String, expectedHash) {
		t.Errorf("DB doesn't contain hash. DB value: %s", dbToken.String)
	}

	// Format should be <timestamp>:<hash>
	parts := strings.Split(dbToken.String, ":")
	if len(parts) != 2 {
		t.Errorf("DB token format invalid: %s", dbToken.String)
	}
}

// TestEmailVerificationHappyPath tests the full verification flow.
func TestEmailVerificationHappyPath(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	alice := &client{t: t, srv: srv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice", "notify_email": "alice@example.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&alice.id, &alice.key})

	// Check initial status
	resp, body = alice.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	var status struct {
		NotifyEmail string `json:"notify_email"`
		Verified    bool   `json:"verified"`
	}
	json.Unmarshal(body, &status)
	if status.NotifyEmail != "alice@example.com" || status.Verified {
		t.Fatalf("initial status: email=%q verified=%v, want alice@example.com verified=false", status.NotifyEmail, status.Verified)
	}

	// Extract and verify token
	msgs := cap.all()
	token := extractVerifyToken(msgs[0].Body)
	resp, body = alice.do("POST", "/v1/me/verify-email?token="+token, nil, nil)
	want(t, resp, body, 200)

	// Check verified status
	resp, body = alice.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	json.Unmarshal(body, &status)
	if status.NotifyEmail != "alice@example.com" || !status.Verified {
		t.Fatalf("after verify: email=%q verified=%v, want alice@example.com verified=true", status.NotifyEmail, status.Verified)
	}
}

// registerAndVerify is a helper that registers a peer, verifies the email, and returns the client.
func registerAndVerify(t *testing.T, srv *httptest.Server, cap *captureMailer, name, email string) *client {
	t.Helper()
	c := &client{t: t, srv: srv}

	// Store count of messages before registration
	beforeCount := len(cap.all())

	resp, body := c.do("POST", "/v1/register", map[string]string{"name": name, "notify_email": email}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("register %s: %d %s", name, resp.StatusCode, body)
	}
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&c.id, &c.key})

	// Find the NEW verification email sent after this registration
	msgs := cap.all()
	var token string
	for i := beforeCount; i < len(msgs); i++ {
		m := msgs[i]
		if m.To == email && strings.Contains(m.Subject, "Verify") {
			token = extractVerifyToken(m.Body)
			if token != "" {
				break
			}
		}
	}
	if token == "" {
		t.Fatalf("no verification token found for %s", email)
	}

	resp, body = c.do("POST", "/v1/me/verify-email?token="+token, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("verify %s: %d %s", name, resp.StatusCode, body)
	}

	return c
}

// TestPerAddressNotificationRateLimit tests that notification rate limiting is per-address.
func TestPerAddressNotificationRateLimit(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, NotifyPerHour: 2, NotifyBurst: 2})

	alice := register(t, srv, "alice")

	// Register and verify two peers with the same email
	bob1 := registerAndVerify(t, srv, cap, "bob1", "shared@example.com")
	bob2 := registerAndVerify(t, srv, cap, "bob2", "shared@example.com")

	// Clear verification emails
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()

	// Grant messages
	pairUp(t, bob1, alice, []string{"messages"}, nil, nil)
	pairUp(t, bob2, alice, []string{"messages"}, nil, nil)

	// Send 2 messages - should get 2 notifications (within per-address limit)
	resp, body := alice.do("POST", "/v1/peers/"+bob1.id+"/messages", map[string]any{"type": "note", "body": "msg1"}, nil)
	want(t, resp, body, 201)

	resp, body = alice.do("POST", "/v1/peers/"+bob2.id+"/messages", map[string]any{"type": "note", "body": "msg2"}, nil)
	want(t, resp, body, 201)

	msgs := cap.all()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(msgs))
	}

	// Third message should be rate-limited by per-address limit
	resp, body = alice.do("POST", "/v1/peers/"+bob1.id+"/messages", map[string]any{"type": "note", "body": "msg3"}, nil)
	want(t, resp, body, 201)

	msgs = cap.all()
	if len(msgs) != 2 {
		t.Fatalf("expected still 2 notifications (rate limited), got %d", len(msgs))
	}
}

// TestRegisterWithExhaustedAddressBudget tests that registration succeeds even when
// the per-address verification email budget is exhausted.
func TestRegisterWithExhaustedAddressBudget(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap})

	// Register 3 peers with the same email to exhaust the per-address budget (3/hour)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("peer%d", i)
		resp, body := (&client{t: t, srv: srv}).do("POST", "/v1/register", map[string]string{"name": name, "notify_email": "shared@example.com"}, nil)
		want(t, resp, body, 201)
	}

	// 4th registration with same email should succeed (201) but skip sending email
	resp, body := (&client{t: t, srv: srv}).do("POST", "/v1/register", map[string]string{"name": "peer3", "notify_email": "shared@example.com"}, nil)
	want(t, resp, body, 201)

	// Verify only 3 emails were sent
	msgs := cap.all()
	count := 0
	for _, m := range msgs {
		if m.To == "shared@example.com" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("sent %d emails, want 3", count)
	}
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/mailer"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func (s *syncBuf) Reset()                      { s.mu.Lock(); defer s.mu.Unlock(); s.b.Reset() }

type inviteResp struct {
	Code      string            `json:"code"`
	AcceptURL string            `json:"accept_url"`
	Email     map[string]string `json:"email"`
}

type captureMailer struct {
	mu   sync.Mutex
	msgs []mailer.Message
}

func (c *captureMailer) Mode() string { return "smtp" }

func (c *captureMailer) Send(_ context.Context, m mailer.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *captureMailer) all() []mailer.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]mailer.Message, len(c.msgs))
	copy(out, c.msgs)
	return out
}

func (c *captureMailer) messages() []mailer.Message {
	return c.all()
}

// captureAndLog wraps a capture mailer and also forwards to Log for dev-mode testing
type captureAndLog struct {
	capture *captureMailer
	log     mailer.Log
}

func (c *captureAndLog) Mode() string { return "smtp" }

func (c *captureAndLog) Send(ctx context.Context, m mailer.Message) error {
	if err := c.capture.Send(ctx, m); err != nil {
		return err
	}
	return c.log.Send(ctx, m)
}

// Dev mode: no SMTP configured -> email is logged, invite still created and usable.
func TestEmailInviteDevMode(t *testing.T) {
	var logs syncBuf
	capture := &captureMailer{}
	srv := newServer(t, Config{
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		Mailer: capture,
	})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	var inv inviteResp
	json.Unmarshal(body, &inv)
	if inv.Code == "" || inv.Email["status"] != "sent" || inv.Email["mode"] != "smtp" || inv.Email["to"] != "bob@example.com" {
		t.Fatalf("invite: %s", body)
	}
	if inv.AcceptURL != srv.URL+"/v1/invites/accept" || strings.Contains(inv.AcceptURL, inv.Code) {
		t.Fatalf("accept_url: %s", inv.AcceptURL)
	}

	// Check email was sent via capture mailer
	msgs := capture.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Body, inv.Code) {
		t.Fatalf("email body should contain invite code %s", inv.Code)
	}
	// Email carries the code in the POST body, never in a URL query string
	if strings.Contains(msgs[0].Body, "?code=") {
		t.Fatalf("email body must not put the code in a URL query string")
	}
	if !strings.Contains(msgs[0].Body, `{"code":"`+inv.Code+`"}`) {
		t.Fatalf("email body should contain code in the POST body example")
	}

	// Fix #26: invite code must NOT appear in logs
	l := logs.String()
	if strings.Contains(l, inv.Code) {
		t.Fatalf("invite code leaked in dev mode log: %s", l)
	}
	// Email should show code in body format (JSON), not query string
	if b := msgs[0].Body; !strings.Contains(b, "POST") || !strings.Contains(b, "Content-Type: application/json") {
		t.Fatalf("email should show POST with code in JSON body: %s", b)
	}

	// Unauthenticated click (human / mail scanner) shows instructions and does not consume.
	anon := &client{t: t, srv: srv}
	path := strings.TrimPrefix(inv.AcceptURL, srv.URL) + "?code=" + inv.Code
	resp, body = anon.do("GET", path, nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), "Nothing has been accepted") {
		t.Fatalf("landing: %s", body)
	}
	resp, body = anon.do("GET", "/v1/invites/accept?code=<script>", nil, nil)
	want(t, resp, body, 400)
	if strings.Contains(string(body), "<script>") {
		t.Fatal("landing echoed bad code")
	}

	// Bob's bot accepts via the accept_url landing page with its key (POST, reciprocal scopes in body).
	resp, body = b.do("POST", path, map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"granted_by_you"`) {
		t.Fatalf("accept: %s", body)
	}
	// single use
	resp, body = b.do("POST", path, nil, nil)
	want(t, resp, body, 404)
	// grant works both ways
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "hi"}, nil)
	want(t, resp, body, 201)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "hi"}, nil)
	want(t, resp, body, 201)
}

func TestAcceptViaQueryPOST(t *testing.T) {
	srv := newServer(t, Config{PublicURL: "https://peerline.example.com/"})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	var inv inviteResp
	json.Unmarshal(body, &inv)
	if inv.AcceptURL != "https://peerline.example.com/v1/invites/accept" {
		t.Fatalf("accept_url: %s", inv.AcceptURL)
	}
	path := "/v1/invites/accept?code=" + inv.Code
	// mismatched body/query code
	resp, body = b.do("POST", path, map[string]any{"code": "inv_other"}, nil)
	want(t, resp, body, 400)
	// no body, code in query
	resp, body = b.do("POST", path, nil, nil)
	want(t, resp, body, 200)
	// code missing entirely
	resp, body = b.do("POST", "/v1/invites/accept", nil, nil)
	want(t, resp, body, 400)
}

func TestEmailInviteValidationAndRateLimit(t *testing.T) {
	srv := newServer(t, Config{EmailRcptPerHour: 1, EmailPerHour: 1, EmailBurst: 2})
	a := register(t, srv, "alice")
	for _, bad := range []string{"not-an-email", "Bob <bob@example.com>", "bob@example.com\r\nBcc: x@evil.com", "a@b.com,c@d.com", "bob@localhost"} {
		resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": bad}, nil)
		want(t, resp, body, 400)
	}
	inv := func(to string) (*http.Response, []byte) {
		in := map[string]any{"scopes": []string{"messages"}}
		if to != "" {
			in["to_email"] = to
		}
		return a.do("POST", "/v1/invites", in, nil)
	}
	resp, body := inv("bob@example.com")
	want(t, resp, body, 201)
	resp, body = inv("BOB@example.com") // per-recipient limit (case-insensitive)
	want(t, resp, body, 429)
	resp, body = inv("carol@example.com")
	want(t, resp, body, 201)
	resp, body = inv("dave@example.com") // per-inviter limit
	want(t, resp, body, 429)
	resp, body = inv("") // code-only path is not affected
	want(t, resp, body, 201)
}

type failMailer struct{}

func (failMailer) Mode() string                               { return "smtp" }
func (failMailer) Send(context.Context, mailer.Message) error { return errors.New("boom") }

func TestEmailSendFailureStillCreatesInvite(t *testing.T) {
	srv := newServer(t, Config{Mailer: failMailer{}})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	var inv inviteResp
	json.Unmarshal(body, &inv)
	if inv.Email["status"] != "failed" || inv.Code == "" {
		t.Fatalf("invite: %s", body)
	}
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 200)
}

func TestInviteEmailDirect(t *testing.T) {
	testExpiry := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	tests := []struct {
		name       string
		inviter    string
		inviterID  string
		to         string
		code       string
		publicBase string
		scopes     []string
		bags       []string
		wantIn     []string
		wantNotIn  []string
	}{
		{
			name:       "basic invite",
			inviter:    "Alice",
			inviterID:  "p_alice123",
			to:         "bot@example.com",
			code:       "inv_testcode123",
			publicBase: "https://peerline.example.com",
			scopes:     []string{"messages"},
			bags:       nil,
			wantIn: []string{
				"Alice (Peerline peer p_alice123) invited",
				"Scopes granted to you: messages",
				`{"code":"inv_testcode123"}`,
				"https://peerline.example.com/v1/invites/accept",
				"inv_testcode123",
				"POST",
				"Content-Type: application/json",
				"2026-12-31T23:59:59Z",
			},
			wantNotIn: []string{
				"?code=",
			},
		},
		{
			name:       "multiple scopes and bags",
			inviter:    "Bob",
			inviterID:  "p_bob456",
			to:         "test@example.com",
			code:       "inv_xyz789",
			publicBase: "https://test.com",
			scopes:     []string{"messages", "bags:read"},
			bags:       []string{"notes", "data"},
			wantIn: []string{
				"Bob (Peerline peer p_bob456) invited",
				"Scopes granted to you: messages, bags:read",
				"Bags: notes, data",
				`{"code":"inv_xyz789"}`,
				"https://test.com/v1/invites/accept",
				"inv_xyz789",
				"2026-12-31T23:59:59Z",
			},
			wantNotIn: []string{
				"?code=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := inviteEmail(tt.inviter, tt.inviterID, tt.to, tt.code, tt.publicBase, tt.scopes, tt.bags, testExpiry)
			if msg.To != tt.to {
				t.Errorf("To = %q, want %q", msg.To, tt.to)
			}
			if !strings.Contains(msg.Subject, tt.inviter) {
				t.Errorf("Subject %q should contain inviter %q", msg.Subject, tt.inviter)
			}
			for _, want := range tt.wantIn {
				if !strings.Contains(msg.Body, want) {
					t.Errorf("Body missing %q\nBody: %s", want, msg.Body)
				}
			}
			for _, notWant := range tt.wantNotIn {
				if strings.Contains(msg.Body, notWant) {
					t.Errorf("Body should not contain %q\nBody: %s", notWant, msg.Body)
				}
			}
		})
	}
}

// echoMailer is a mailer whose Send error embeds the full message body,
// simulating a custom mailer or relay that echoes DATA back in the error.
type echoMailer struct{}

func (echoMailer) Mode() string { return "smtp" }
func (echoMailer) Send(_ context.Context, m mailer.Message) error {
	return errors.New("mailer error: failed to send message with body: " + m.Body)
}

// TestMailerErrorRedaction verifies that when a Mailer.Send error embeds the message body
// (including an invite code), the logged error is redacted and no invite code leaks into logs.
// This is a defense-in-depth measure for issue #353.
func TestMailerErrorRedaction(t *testing.T) {
	testBothHandlers := func(t *testing.T, name string, newHandler func(*syncBuf) slog.Handler) {
		t.Run(name, func(t *testing.T) {
			var logs syncBuf
			logger := slog.New(newHandler(&logs))
			srv := newServer(t, Config{Logger: logger, Mailer: echoMailer{}})
			a := register(t, srv, "alice")

			// Create an invite with to_email, triggering the email send path
			resp, body := a.do("POST", "/v1/invites", map[string]any{
				"scopes":   []string{"messages"},
				"to_email": "test@example.com",
			}, nil)
			want(t, resp, body, 201)

			var inv inviteResp
			if err := json.Unmarshal(body, &inv); err != nil || inv.Code == "" {
				t.Fatalf("invite response: %v %s", err, body)
			}
			if inv.Email["status"] != "failed" {
				t.Errorf("email status = %q, want failed", inv.Email["status"])
			}

			// The invite code is created and returned, but should never appear in logs
			logStr := logs.String()

			// Assert logs were captured
			if logStr == "" {
				t.Fatal("no logs captured (logging not wired)")
			}

			// Assert "invite email failed" log line is present
			if !strings.Contains(logStr, "invite email failed") {
				t.Error("logs should contain 'invite email failed' line")
			}

			// Assert the redaction marker is present
			if !strings.Contains(logStr, "[REDACTED:inv_") {
				t.Error("logs should contain redaction marker '[REDACTED:inv_'")
			}

			// Assert no invite code reaches logs (exact substring check)
			if strings.Contains(logStr, inv.Code) {
				t.Errorf("invite code leaked in logs (exact match, len=%d)", len(inv.Code))
			}

			// Assert no invite code reaches logs (prefix check)
			if len(inv.Code) >= 10 && strings.Contains(logStr, inv.Code[:10]) {
				t.Errorf("invite code prefix leaked in logs (len=%d)", len(inv.Code))
			}

			// Assert no invite code reaches logs (suffix check)
			if len(inv.Code) >= 10 && strings.Contains(logStr, inv.Code[len(inv.Code)-10:]) {
				t.Errorf("invite code suffix leaked in logs (len=%d)", len(inv.Code))
			}

			// Assert no unredacted inv_ pattern with proper length appears in logs
			invCodeRegex := regexp.MustCompile(`inv_[A-Za-z0-9_-]{32,}`)
			if invCodeRegex.MatchString(logStr) {
				t.Error("logs contain unredacted inv_ token matching real token pattern")
			}
		})
	}

	testBothHandlers(t, "JSONHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewJSONHandler(buf, nil)
	})
	testBothHandlers(t, "TextHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewTextHandler(buf, nil)
	})
}

// TestVerificationEmailErrorRedaction verifies that when verification emails fail to send
// and the error embeds the eml_ token, logs are redacted (registration path).
func TestVerificationEmailErrorRedaction(t *testing.T) {
	testBothHandlers := func(t *testing.T, name string, newHandler func(*syncBuf) slog.Handler) {
		t.Run(name, func(t *testing.T) {
			var logs syncBuf
			logger := slog.New(newHandler(&logs))
			srv := newServer(t, Config{Logger: logger, Mailer: echoMailer{}})

			// Register with notify_email triggers verification email send
			resp, body := http.Post(
				srv.URL+"/v1/register",
				"application/json",
				strings.NewReader(`{"name":"alice","notify_email":"alice@example.com"}`),
			)
			if resp.StatusCode != 201 {
				t.Fatalf("register failed: %d %s", resp.StatusCode, body)
			}
			resp.Body.Close()

			logStr := logs.String()

			// Assert logs were captured
			if logStr == "" {
				t.Fatal("no logs captured (logging not wired)")
			}

			// Assert "verification email failed" log line is present
			if !strings.Contains(logStr, "verification email failed") {
				t.Error("logs should contain 'verification email failed' line")
			}

			// Assert the redaction marker is present
			if !strings.Contains(logStr, "[REDACTED:eml_") {
				t.Error("logs should contain redaction marker '[REDACTED:eml_'")
			}

			// Assert no unredacted eml_ token with proper length appears in logs
			emlTokenRegex := regexp.MustCompile(`eml_[A-Za-z0-9_-]{32,}`)
			if emlTokenRegex.MatchString(logStr) {
				t.Error("logs contain unredacted eml_ token matching real token pattern")
			}
		})
	}

	testBothHandlers(t, "JSONHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewJSONHandler(buf, nil)
	})
	testBothHandlers(t, "TextHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewTextHandler(buf, nil)
	})
}

// TestVerificationEmailUpdateErrorRedaction verifies that when verification emails fail
// during PUT /v1/me notify_email updates, logs are redacted.
func TestVerificationEmailUpdateErrorRedaction(t *testing.T) {
	testBothHandlers := func(t *testing.T, name string, newHandler func(*syncBuf) slog.Handler) {
		t.Run(name, func(t *testing.T) {
			var logs syncBuf
			logger := slog.New(newHandler(&logs))
			srv := newServer(t, Config{Logger: logger, Mailer: echoMailer{}})
			a := register(t, srv, "alice")

			// Update notify_email triggers verification email send
			resp, body := a.do("PUT", "/v1/me", map[string]any{"notify_email": "alice@example.com"}, nil)
			want(t, resp, body, 200)

			logStr := logs.String()

			// Assert logs were captured
			if logStr == "" {
				t.Fatal("no logs captured (logging not wired)")
			}

			// Assert "verification email failed" log line is present
			if !strings.Contains(logStr, "verification email failed") {
				t.Error("logs should contain 'verification email failed' line")
			}

			// Assert the redaction marker is present
			if !strings.Contains(logStr, "[REDACTED:eml_") {
				t.Error("logs should contain redaction marker '[REDACTED:eml_'")
			}

			// Assert no unredacted eml_ token with proper length appears in logs
			emlTokenRegex := regexp.MustCompile(`eml_[A-Za-z0-9_-]{32,}`)
			if emlTokenRegex.MatchString(logStr) {
				t.Error("logs contain unredacted eml_ token matching real token pattern")
			}
		})
	}

	testBothHandlers(t, "JSONHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewJSONHandler(buf, nil)
	})
	testBothHandlers(t, "TextHandler", func(buf *syncBuf) slog.Handler {
		return slog.NewTextHandler(buf, nil)
	})
}

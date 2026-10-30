package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/sysrex/peerline/internal/mailer"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

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
	combined := &captureAndLog{
		capture: capture,
		log:     mailer.Log{Logger: slog.New(slog.NewTextHandler(&logs, nil))},
	}
	srv := newServer(t, Config{
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		Mailer: combined,
	})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": "bob@example.com"}, nil)
	want(t, resp, body, 201)
	var inv inviteResp
	json.Unmarshal(body, &inv)
	if inv.Code == "" || inv.Email["status"] != "sent" || inv.Email["mode"] != "smtp" || inv.Email["to"] != "bob@example.com" {
		t.Fatalf("invite: %s", body)
	}
	if !strings.HasPrefix(inv.AcceptURL, srv.URL+"/v1/invites/accept?code=") || !strings.Contains(inv.AcceptURL, inv.Code) {
		t.Fatalf("accept_url: %s", inv.AcceptURL)
	}

	// Check email was sent via capture mailer
	msgs := capture.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(msgs))
	}
	// After #128, email has JSON body format and plain code line (no ?code= URL)
	if !strings.Contains(msgs[0].Body, inv.Code) {
		t.Fatalf("email body should contain invite code %s", inv.Code)
	}

	// Fix #26: invite code must NOT appear in logs (Log mailer path is exercised by captureAndLog)
	l := logs.String()
	if strings.Contains(l, inv.Code) {
		t.Fatalf("invite code leaked in dev mode log: %s", l)
	}

	// Unauthenticated click (human / mail scanner) shows instructions and does not consume.
	anon := &client{t: t, srv: srv}
	path := strings.TrimPrefix(inv.AcceptURL, srv.URL)
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

	// Bob's bot follows the magic link with its key (GET, reciprocal scopes via query).
	resp, body = b.do("GET", path+"&scopes=messages", nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"granted_by_you"`) {
		t.Fatalf("accept: %s", body)
	}
	// single use
	resp, body = b.do("GET", path, nil, nil)
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
	if !strings.HasPrefix(inv.AcceptURL, "https://peerline.example.com/v1/invites/accept?code=inv_") {
		t.Fatalf("accept_url: %s", inv.AcceptURL)
	}
	path := strings.TrimPrefix(inv.AcceptURL, "https://peerline.example.com")
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

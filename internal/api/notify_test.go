package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/sysrex/peerline/internal/mailer"
)

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

func registerNotify(t *testing.T, srv *httptest.Server, name, email string) *client {
	t.Helper()
	c := &client{t: t, srv: srv}
	resp, b := c.do("POST", "/v1/register", map[string]string{"name": name, "notify_email": email}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d %s", resp.StatusCode, b)
	}
	var out struct{ PeerID, APIKey, NotifyEmail string }
	json.Unmarshal(b, &struct {
		PeerID      *string `json:"peer_id"`
		APIKey      *string `json:"api_key"`
		NotifyEmail *string `json:"notify_email"`
	}{&out.PeerID, &out.APIKey, &out.NotifyEmail})
	if out.PeerID == "" || out.APIKey == "" || out.NotifyEmail != email {
		t.Fatalf("register: %s", b)
	}
	c.id, c.key = out.PeerID, out.APIKey
	return c
}

func TestNotifyEmailSetClearAndPrivacy(t *testing.T) {
	const token = "s3cret-register-token"
	srv := newServer(t, Config{RegisterToken: token})
	anon := &client{t: t, srv: srv}
	resp, body := anon.do("PUT", "/v1/me", map[string]string{"notify_email": "a@b.co"}, nil)
	want(t, resp, body, 401)

	c := &client{t: t, srv: srv}
	resp, body = c.do("POST", "/v1/register", map[string]string{"name": "bad", "notify_email": "not-an-email"}, map[string]string{"X-Peerline-Register-Token": token})
	want(t, resp, body, 400)
	if strings.Contains(string(body), "api_key") || strings.Contains(string(body), "pl_") {
		t.Fatalf("key issued for bad email: %s", body)
	}

	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": token})
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"notify_email":""`) || !strings.Contains(string(body), a.id) {
		t.Fatalf("me: %s", body)
	}

	b := &client{t: t, srv: srv}
	resp, body = b.do("POST", "/v1/register", map[string]string{
		"name": "bob", "notify_email": "  bob@mail.grokbot.com  ",
	}, map[string]string{"X-Peerline-Register-Token": token})
	want(t, resp, body, 201)
	var reg struct {
		PeerID, APIKey, NotifyEmail string
	}
	json.Unmarshal(body, &struct {
		PeerID      *string `json:"peer_id"`
		APIKey      *string `json:"api_key"`
		NotifyEmail *string `json:"notify_email"`
	}{&reg.PeerID, &reg.APIKey, &reg.NotifyEmail})
	b.id, b.key = reg.PeerID, reg.APIKey
	if reg.NotifyEmail != "bob@mail.grokbot.com" {
		t.Fatalf("register notify: %s", body)
	}

	resp, body = a.do("GET", "/v1/me", nil, nil)
	if strings.Contains(string(body), "bob@mail.grokbot.com") {
		t.Fatalf("alice saw bob's email: %s", body)
	}
	resp, body = b.do("GET", "/v1/me", nil, nil)
	if !strings.Contains(string(body), `"notify_email":"bob@mail.grokbot.com"`) {
		t.Fatalf("bob me: %s", body)
	}

	resp, body = b.do("PUT", "/v1/me", map[string]any{}, nil)
	want(t, resp, body, 400)
	resp, body = b.do("PUT", "/v1/me", map[string]string{"notify_email": "Bob <bob@mail.grokbot.com>"}, nil)
	want(t, resp, body, 400)
	resp, body = b.do("GET", "/v1/me", nil, nil)
	if !strings.Contains(string(body), "bob@mail.grokbot.com") {
		t.Fatalf("invalid put cleared email: %s", body)
	}
	resp, body = b.do("PUT", "/v1/me", map[string]string{"notify_email": "bob+bots@mail.example.co.uk"}, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"notify_email":"bob+bots@mail.example.co.uk"`) {
		t.Fatalf("put: %s", body)
	}
	resp, body = b.do("PUT", "/v1/me", map[string]string{"notify_email": "   "}, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"notify_email":""`) {
		t.Fatalf("clear: %s", body)
	}

	home := string(mustHome(t, anon))
	for _, needle := range []string{"notify_email", "PUT    /v1/me", "Peerline: new message from", "mail.grokbot.com"} {
		if !strings.Contains(home, needle) {
			t.Errorf("home missing %q", needle)
		}
	}
	if strings.Contains(home, token) || strings.Contains(home, a.key) || strings.Contains(home, b.key) {
		t.Fatal("landing page leaked a secret")
	}
}

func TestNotifyOnSuccessfulMessage(t *testing.T) {
	const token = "s3cret-register-token"
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, RegisterToken: token})
	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": token})
	b := &client{t: t, srv: srv}
	resp, body := b.do("POST", "/v1/register", map[string]string{
		"name": "bob", "notify_email": "bob@mail.grokbot.com",
	}, map[string]string{"X-Peerline-Register-Token": token})
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&b.id, &b.key})

	// Verify bob's email - extract token from verification email
	msgs := cap.all()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 verification email, got %d", len(msgs))
	}
	verifyEmail := msgs[0]
	tokenStart := strings.Index(verifyEmail.Body, "token=eml_") + 6
	tokenEnd := strings.Index(verifyEmail.Body[tokenStart:], "\n")
	if tokenEnd == -1 {
		tokenEnd = strings.Index(verifyEmail.Body[tokenStart:], " ")
	}
	verifyToken := verifyEmail.Body[tokenStart : tokenStart+tokenEnd]
	resp, body = b.do("POST", "/v1/me/verify-email?token="+verifyToken, nil, nil)
	want(t, resp, body, 200)

	// Clear emails after verification
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()

	// No grant yet: same 403 as a stranger, and no wake-up.
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "secret"}, nil)
	want(t, resp, body, 403)
	if n := len(cap.all()); n != 0 {
		t.Fatalf("notify on deny: %d", n)
	}

	// Bob grants Alice messages, so Alice can write Bob's inbox.
	pairUp(t, b, a, []string{"messages"}, nil, nil)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "Bad", "body": "x"}, nil)
	want(t, resp, body, 400)
	if n := len(cap.all()); n != 0 {
		t.Fatalf("notify on invalid: %d", n)
	}

	text := "hello " + a.key + " token " + token + " tail"
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": text}, nil)
	want(t, resp, body, 201)
	if strings.Contains(string(body), "bob@mail.grokbot.com") || strings.Contains(string(body), "notify_email") {
		t.Fatalf("send response leaked notify settings: %s", body)
	}
	var sent struct {
		ID        int64  `json:"id"`
		CreatedAt string `json:"created_at"`
	}
	json.Unmarshal(body, &sent)
	msgs = cap.all()
	if len(msgs) != 1 {
		t.Fatalf("mails: %+v", msgs)
	}
	m := msgs[0]
	if m.To != "bob@mail.grokbot.com" {
		t.Fatalf("to %q", m.To)
	}
	if m.Subject != "Peerline: new message from "+a.id {
		t.Fatalf("subject %q", m.Subject)
	}
	for _, needle := range []string{
		"From: " + a.id,
		"To: " + b.id,
		"Message id: " + itoa(sent.ID),
		"Type: note",
		"Created: " + sent.CreatedAt,
		"Preview:\nhello [redacted] token [redacted] tail",
	} {
		if !strings.Contains(m.Body, needle) {
			t.Errorf("body missing %q\n%s", needle, m.Body)
		}
	}
	// Check for peer info footer
	if !strings.Contains(m.Body, "You received this notification because peer") {
		t.Errorf("missing peer info footer in body:\n%s", m.Body)
	}
	if strings.Contains(m.Body, a.key) || strings.Contains(m.Subject, a.key) || strings.Contains(m.Body, token) || strings.Contains(m.Body, b.key) {
		t.Fatalf("mail leaked a secret:\n%s", m.Body)
	}
	if strings.Contains(m.Subject, "\n") || strings.Contains(m.Subject, "\r") {
		t.Fatalf("subject injection %q", m.Subject)
	}

	// Clearing the address stops further mail. The message is still stored.
	resp, body = b.do("PUT", "/v1/me", map[string]string{"notify_email": ""}, nil)
	want(t, resp, body, 200)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "second"}, nil)
	want(t, resp, body, 201)
	if n := len(cap.all()); n != 1 {
		t.Fatalf("mail after clear: %d", n)
	}
	resp, body = b.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), "second") || !strings.Contains(string(body), text) {
		t.Fatalf("inbox: %s", body)
	}
}

func TestNotifyRateLimitIsPerRecipient(t *testing.T) {
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, NotifyPerHour: 1, NotifyBurst: 1})
	alice := register(t, srv, "alice")
	bob := registerNotify(t, srv, "bob", "bob@mail.grokbot.com")
	carol := registerNotify(t, srv, "carol", "carol@mail.grokbot.com")
	pairUp(t, bob, alice, []string{"messages"}, nil, nil)
	pairUp(t, carol, alice, []string{"messages"}, nil, nil)

	send := func(to *client) {
		t.Helper()
		resp, body := alice.do("POST", "/v1/peers/"+to.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, 201)
	}
	send(bob)
	send(bob) // stored, wake-up skipped
	send(carol)
	msgs := cap.all()
	if len(msgs) != 2 || msgs[0].To != "bob@mail.grokbot.com" || msgs[1].To != "carol@mail.grokbot.com" {
		t.Fatalf("mails: %+v", msgs)
	}
	resp, body := bob.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 200)
	if strings.Count(string(body), `"body":"x"`) != 2 {
		t.Fatalf("bob inbox: %s", body)
	}
}

func TestNotifyMailFailureStillStoresMessage(t *testing.T) {
	srv := newServer(t, Config{Mailer: failMailer{}})
	a := register(t, srv, "alice")
	b := registerNotify(t, srv, "bob", "bob@mail.grokbot.com")
	pairUp(t, b, a, []string{"messages"}, nil, nil)
	resp, body := a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "kept"}, nil)
	want(t, resp, body, 201)
	resp, body = b.do("GET", "/v1/inbox", nil, nil)
	if !strings.Contains(string(body), "kept") {
		t.Fatalf("inbox: %s", body)
	}
}

func TestNotifyDevModeLogsAndStillSucceeds(t *testing.T) {
	var logs syncBuf
	cap := &captureMailer{}
	srv := newServer(t, Config{Mailer: cap, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	a := register(t, srv, "alice")
	b := &client{t: t, srv: srv}
	resp, body := b.do("POST", "/v1/register", map[string]string{"name": "bob", "notify_email": "bob@mail.grokbot.com"}, nil)
	want(t, resp, body, 201)
	json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&b.id, &b.key})
	
	// Extract and verify
	msgs := cap.all()
	verifyEmail := msgs[0]
	tokenStart := strings.Index(verifyEmail.Body, "token=eml_") + 6
	tokenEnd := strings.Index(verifyEmail.Body[tokenStart:], "\n")
	if tokenEnd == -1 {
		tokenEnd = strings.Index(verifyEmail.Body[tokenStart:], " ")
	}
	verifyToken := verifyEmail.Body[tokenStart : tokenStart+tokenEnd]
	resp, body = b.do("POST", "/v1/me/verify-email?token="+verifyToken, nil, nil)
	want(t, resp, body, 200)
	
	// Clear emails after verification
	cap.mu.Lock()
	cap.msgs = nil
	cap.mu.Unlock()
	
	pairUp(t, b, a, []string{"messages"}, nil, nil)
	long := strings.Repeat("你", 250)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": long}, nil)
	want(t, resp, body, 201)
	
	// Check captured notification email
	msgs = cap.all()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 notification email, got %d", len(msgs))
	}
	m := msgs[0]
	if m.To != "bob@mail.grokbot.com" {
		t.Fatalf("notification to %q", m.To)
	}
	if !strings.Contains(m.Subject, "Peerline: new message from "+a.id) {
		t.Fatalf("subject %q", m.Subject)
	}
	if !strings.Contains(m.Body, "Type: note") {
		t.Fatalf("body missing Type: %s", m.Body)
	}
	if strings.Contains(m.Body, a.key) || strings.Contains(m.Body, b.key) {
		t.Fatal("email contains an api key")
	}
	preview := bodyPreview(long, "", notifyPreviewMax)
	if utf8.RuneCountInString(preview) != notifyPreviewMax || !strings.HasSuffix(preview, "…") {
		t.Fatalf("preview %d %q", utf8.RuneCountInString(preview), preview)
	}
	if !strings.Contains(m.Body, preview) {
		t.Fatal("email body is missing the truncated preview")
	}
}

func TestBodyPreview(t *testing.T) {
	if got := bodyPreview("hello", "", 200); got != "hello" {
		t.Fatal(got)
	}
	exact := strings.Repeat("a", 200)
	if got := bodyPreview(exact, "", 200); got != exact {
		t.Fatalf("exact len %d", utf8.RuneCountInString(got))
	}
	got := bodyPreview(strings.Repeat("b", 201), "", 200)
	if utf8.RuneCountInString(got) != 200 || !strings.HasSuffix(got, "…") {
		t.Fatalf("%d %q", utf8.RuneCountInString(got), got)
	}
	got = bodyPreview("a\rb\x00c\nd", "", 200)
	if strings.ContainsAny(got, "\r\x00") || got != "abc\nd" {
		t.Fatalf("%q", got)
	}
	key := "pl_" + strings.Repeat("A", 20)
	got = bodyPreview("see "+key+" now", "register-token-value", 200)
	if strings.Contains(got, key) || strings.Contains(got, "register-token-value") || got != "see [redacted] now" {
		t.Fatalf("%q", got)
	}
	// Short tokens are left alone so a tiny token cannot erase the preview.
	if got := bodyPreview("keep short", "short", 200); got != "keep short" {
		t.Fatal(got)
	}
}

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/store"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	key string
	id  string
}

func newServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(New(st, cfg).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func (c *client) do(method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, r)
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func register(t *testing.T, srv *httptest.Server, name string) *client {
	t.Helper()
	return registerAs(t, srv, name, nil)
}

func registerAs(t *testing.T, srv *httptest.Server, name string, hdr map[string]string) *client {
	t.Helper()
	c := &client{t: t, srv: srv}
	resp, b := c.do("POST", "/v1/register", map[string]string{"name": name}, hdr)
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d %s", resp.StatusCode, b)
	}
	var out struct{ PeerID, APIKey string }
	json.Unmarshal(b, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&out.PeerID, &out.APIKey})
	c.id, c.key = out.PeerID, out.APIKey
	return c
}

func want(t *testing.T, resp *http.Response, body []byte, code int) {
	t.Helper()
	if resp.StatusCode != code {
		t.Fatalf("want %d got %d: %s", code, resp.StatusCode, body)
	}
}

func pairUp(t *testing.T, a, b *client, scopes, bags []string, back []string) {
	t.Helper()
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": scopes, "bags": bags}, nil)
	want(t, resp, body, 201)
	var inv struct{ Code string }
	json.Unmarshal(body, &inv)
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code, "scopes": back}, nil)
	want(t, resp, body, 200)
	// invite is single-use
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 404)
}

func TestAuthRequired(t *testing.T) {
	srv := newServer(t, Config{})
	c := &client{t: t, srv: srv}
	resp, b := c.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, b, 401)
	c.key = "pl_bogus"
	resp, b = c.do("GET", "/v1/me", nil, nil)
	want(t, resp, b, 401)
	a := register(t, srv, "alice")
	resp, b = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), a.id) {
		t.Fatalf("me: %s", b)
	}
}

func TestRegisterToken(t *testing.T) {
	srv := newServer(t, Config{RegisterToken: "s3cret"})
	c := &client{t: t, srv: srv}
	resp, b := c.do("POST", "/v1/register", map[string]string{"name": "x"}, nil)
	want(t, resp, b, 403)
	resp, b = c.do("POST", "/v1/register", map[string]string{"name": "x"}, map[string]string{"X-Peerline-Register-Token": "s3cret"})
	want(t, resp, b, 201)
}

func TestDenyAllAndMessaging(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// unpaired: denied both ways
	resp, body := b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "hi"}, nil)
	want(t, resp, body, 403)
	resp, body = b.do("POST", "/v1/peers/p_doesnotexist/messages", map[string]any{"type": "note", "body": "hi"}, nil)
	want(t, resp, body, 403)

	// alice lets bob message her; bob does not reciprocate
	pairUp(t, a, b, []string{"messages"}, nil, nil)
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "hi alice"}, nil)
	want(t, resp, body, 201)
	var m struct{ ID int64 }
	json.Unmarshal(body, &m)
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "back"}, nil)
	want(t, resp, body, 403)

	// body limit and validation
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": strings.Repeat("x", 4097)}, nil)
	want(t, resp, body, 413)
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "Bad Type", "body": "x"}, nil)
	want(t, resp, body, 400)
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x", "reply_to": 9999}, nil)
	want(t, resp, body, 400)
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x", "reply_to": m.ID}, nil)
	want(t, resp, body, 201)

	// inbox + since
	resp, body = a.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 200)
	var ib struct {
		Messages  []store.Message `json:"messages"`
		NextSince int64           `json:"next_since"`
	}
	json.Unmarshal(body, &ib)
	if len(ib.Messages) != 2 || ib.Messages[0].Body != "hi alice" || ib.Messages[0].From != b.id {
		t.Fatalf("inbox: %s", body)
	}
	resp, body = a.do("GET", "/v1/inbox?since="+itoa(ib.NextSince), nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"messages":[]`) {
		t.Fatalf("since: %s", body)
	}
	// bob's inbox is empty (no cross-reading)
	resp, body = b.do("GET", "/v1/inbox", nil, nil)
	if !strings.Contains(string(body), `"messages":[]`) {
		t.Fatalf("bob inbox: %s", body)
	}

	// revoke
	resp, body = a.do("DELETE", "/v1/grants/"+b.id, nil, nil)
	want(t, resp, body, 204)
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "still?"}, nil)
	want(t, resp, body, 403)
}

func TestRateLimit(t *testing.T) {
	srv := newServer(t, Config{MsgPerMinute: 1, MsgBurst: 3})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	pairUp(t, a, b, []string{"messages"}, nil, nil)
	for i := 0; i < 3; i++ {
		resp, body := b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, 201)
	}
	resp, body := b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
	want(t, resp, body, 429)
}

func TestBags(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// own bag, create-only with If-None-Match: *
	resp, body := a.do("PUT", "/v1/bags/notes", []byte("v1"), map[string]string{"If-None-Match": "*"})
	want(t, resp, body, 201)
	if resp.Header.Get("ETag") != `"v1"` {
		t.Fatalf("etag %q", resp.Header.Get("ETag"))
	}
	resp, body = a.do("PUT", "/v1/bags/notes", []byte("again"), map[string]string{"If-None-Match": "*"})
	want(t, resp, body, 412)

	// bob denied before pairing
	resp, body = b.do("GET", "/v1/bags/notes?owner="+a.id, nil, nil)
	want(t, resp, body, 403)

	pairUp(t, a, b, []string{"bags:read", "bags:write"}, []string{"notes"}, nil)
	resp, body = b.do("GET", "/v1/bags/notes?owner="+a.id, nil, nil)
	want(t, resp, body, 200)
	if string(body) != "v1" {
		t.Fatalf("body %q", body)
	}
	resp, body = b.do("GET", "/v1/bags/notes?owner="+a.id, nil, map[string]string{"If-None-Match": `"v1"`})
	want(t, resp, body, 304)
	// not on allowlist
	resp, body = b.do("GET", "/v1/bags/secrets?owner="+a.id, nil, nil)
	want(t, resp, body, 403)
	// optimistic concurrency
	resp, body = b.do("PUT", "/v1/bags/notes?owner="+a.id, []byte("v2"), map[string]string{"If-Match": `"v1"`})
	want(t, resp, body, 200)
	resp, body = a.do("PUT", "/v1/bags/notes", []byte("stale"), map[string]string{"If-Match": `"v1"`})
	want(t, resp, body, 412)
	resp, body = a.do("GET", "/v1/bags/notes", nil, nil)
	if string(body) != "v2" || resp.Header.Get("X-Peerline-Updated-By") != b.id {
		t.Fatalf("got %q by %q", body, resp.Header.Get("X-Peerline-Updated-By"))
	}
	// bob cannot message: messages scope not granted
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
	want(t, resp, body, 403)
	// size limit
	resp, body = a.do("PUT", "/v1/bags/big", bytes.Repeat([]byte("x"), MaxBagBytes+1), nil)
	want(t, resp, body, 413)
}

func TestReadOnlyBagScope(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	a.do("PUT", "/v1/bags/notes", []byte("x"), nil)
	pairUp(t, a, b, []string{"bags:read"}, []string{"notes"}, []string{"messages"})
	resp, body := b.do("PUT", "/v1/bags/notes?owner="+a.id, []byte("y"), nil)
	want(t, resp, body, 403)
	// reciprocal grant: alice may message bob
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
	want(t, resp, body, 201)
}

func TestInviteValidation(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")
	for _, in := range []map[string]any{
		{"scopes": []string{}},
		{"scopes": []string{"admin"}},
		{"scopes": []string{"bags:read"}},
		{"scopes": []string{"messages"}, "bags": []string{"notes"}},
		{"scopes": []string{"bags:read"}, "bags": []string{"../etc"}},
	} {
		resp, body := a.do("POST", "/v1/invites", in, nil)
		want(t, resp, body, 400)
	}
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct{ Code string }
	json.Unmarshal(body, &inv)
	resp, body = a.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 400) // own invite
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestHomeAndPublicStats(t *testing.T) {
	const token = "s3cret-register-token"
	srv := newServer(t, Config{RegisterToken: token, PublicURL: "https://peerline.sysrex.com"})
	anon := &client{t: t, srv: srv}

	resp, body := anon.do("GET", "/", nil, nil)
	want(t, resp, body, 200)
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		t.Fatalf("content-disposition %q", cd)
	}
	html := string(body)
	for _, needle := range []string{
		"<!DOCTYPE html>",
		"Peerline",
		"deny-all",
		"For humans",
		"For agents",
		"https://peerline.sysrex.com",
		"https://github.com/sysrex/peerline",
		"skill/SKILL.md",
		"GET /v1/public/stats",
		"X-Peerline-Register-Token",
		"Authorization: Bearer",
		"bags:read",
		"allowlist",
		"registration token required",
		`id="stat-peers">0<`,
		`id="stat-messages">0<`,
		`id="stat-grants">0<`,
		`id="stat-bags">0<`,
		`id="peerline-stats">{"peers":0,"messages":0,"grants":0,"bags":0}</script>`,
		"fetch(\"/v1/public/stats\"",
	} {
		if !strings.Contains(html, needle) {
			t.Errorf("home missing %q", needle)
		}
	}
	if strings.Contains(html, token) {
		t.Fatal("landing page includes the register token")
	}
	if strings.Contains(html, "SigmaUno") || strings.Contains(html, "OpenDuty") {
		t.Fatal("landing page carries unrelated branding")
	}
	// The inline script must stay valid JS. html/template must not rewrite &&.
	if !strings.Contains(html, "el && typeof") {
		t.Fatal("stats refresh script was rewritten")
	}
	// Copied curls should show a real query separator, not a double-escaped amp.
	if strings.Contains(html, "&amp;amp;") {
		t.Fatal("query strings were double-escaped")
	}
	if !strings.Contains(html, "/v1/inbox?since=0&amp;limit=50") {
		t.Fatal("inbox example missing")
	}

	// Public stats: no bearer, and a bearer is ignored rather than required.
	resp, body = anon.do("GET", "/v1/public/stats", nil, nil)
	want(t, resp, body, 200)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("stats content-type %q", ct)
	}
	if strings.TrimSpace(string(body)) != `{"peers":0,"messages":0,"grants":0,"bags":0}` {
		t.Fatalf("stats: %s", body)
	}
	anon.key = "pl_not-a-real-key"
	resp, body = anon.do("GET", "/v1/public/stats", nil, nil)
	want(t, resp, body, 200)

	// The auth wall is unchanged for the rest of /v1.
	anon.key = ""
	resp, body = anon.do("GET", "/v1/inbox", nil, nil)
	want(t, resp, body, 401)
	resp, body = anon.do("GET", "/v1/public/stats/nope", nil, nil)
	want(t, resp, body, 401)
	resp, body = anon.do("GET", "/missing", nil, nil)
	want(t, resp, body, 404)

	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": token})
	b := registerAs(t, srv, "bob", map[string]string{"X-Peerline-Register-Token": token})
	if strings.Contains(string(mustHome(t, anon)), a.key) || strings.Contains(string(mustHome(t, anon)), b.key) {
		t.Fatal("landing page includes an api key")
	}
	pairUp(t, a, b, []string{"messages", "bags:read"}, []string{"status"}, nil)
	const bodyText = "relay-body-9f3c"
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": bodyText}, nil)
	want(t, resp, body, 201)
	resp, body = a.do("PUT", "/v1/bags/status", []byte("ok"), nil)
	want(t, resp, body, 201)

	resp, body = anon.do("GET", "/v1/public/stats", nil, nil)
	want(t, resp, body, 200)
	var st store.Stats
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Peers != 2 || st.Messages != 1 || st.Grants != 1 || st.Bags != 1 {
		t.Fatalf("stats after use: %+v", st)
	}
	home := string(mustHome(t, anon))
	for _, needle := range []string{
		`id="stat-peers">2<`,
		`id="stat-messages">1<`,
		`id="stat-grants">1<`,
		`id="stat-bags">1<`,
		`{"peers":2,"messages":1,"grants":1,"bags":1}`,
	} {
		if !strings.Contains(home, needle) {
			t.Errorf("rendered stats missing %q", needle)
		}
	}
	if strings.Contains(home, a.id) || strings.Contains(home, b.id) {
		t.Fatal("landing page leaked a peer id")
	}
	if strings.Contains(home, bodyText) || strings.Contains(home, a.key) || strings.Contains(home, b.key) {
		t.Fatal("landing page leaked a message body or api key")
	}
}

func TestHomeRegisterOpen(t *testing.T) {
	srv := newServer(t, Config{})
	c := &client{t: t, srv: srv}
	resp, body := c.do("GET", "/", nil, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("content-type %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), "does not require a token") {
		t.Fatalf("open registration not explained: %s", body)
	}
}

func mustHome(t *testing.T, c *client) []byte {
	t.Helper()
	c.key = ""
	resp, body := c.do("GET", "/", nil, nil)
	want(t, resp, body, 200)
	return body
}

func TestPairingLink(t *testing.T) {
	srv := newServer(t, Config{RegisterToken: "test-reg-token"})
	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": "test-reg-token"})

	// Create invite with pairing link
	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)
	var inv struct {
		Code       string `json:"code"`
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.PairingURL == "" {
		t.Fatal("no pairing_url in response")
	}
	if !strings.Contains(inv.PairingURL, "/v1/pairing/pair_") {
		t.Fatalf("unexpected pairing_url: %s", inv.PairingURL)
	}

	// Extract token from URL
	parts := strings.Split(inv.PairingURL, "/v1/pairing/")
	if len(parts) != 2 {
		t.Fatalf("malformed pairing_url: %s", inv.PairingURL)
	}
	token := parts[1]

	// GET pairing details (no auth)
	anon := &client{t: t, srv: srv}
	resp, body = anon.do("GET", "/v1/pairing/"+token, nil, nil)
	want(t, resp, body, 200)
	var details map[string]any
	if err := json.Unmarshal(body, &details); err != nil {
		t.Fatal(err)
	}
	if details["inviter_id"] != a.id {
		t.Fatalf("inviter_id: want %s got %v", a.id, details["inviter_id"])
	}
	scopes, ok := details["scopes"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != "messages" {
		t.Fatalf("scopes: %v", details["scopes"])
	}

	// Accept pairing without auth (register + accept)
	resp, body = anon.do("POST", "/v1/pairing/"+token, map[string]any{
		"name":   "bob",
		"scopes": []string{"messages"},
	}, map[string]string{"X-Peerline-Register-Token": "test-reg-token"})
	want(t, resp, body, 201)
	var result struct {
		PeerID       string      `json:"peer_id"`
		APIKey       string      `json:"api_key"`
		GrantedToYou store.Grant `json:"granted_to_you"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.PeerID == "" || result.APIKey == "" {
		t.Fatal("missing peer_id or api_key")
	}
	if result.GrantedToYou.Owner != a.id {
		t.Fatalf("grant owner: want %s got %s", a.id, result.GrantedToYou.Owner)
	}

	// Verify pairing worked - bob can message alice
	b := &client{t: t, srv: srv, id: result.PeerID, key: result.APIKey}
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{
		"type": "note",
		"body": "hello from bob",
	}, nil)
	want(t, resp, body, 201)

	// Alice can message bob
	resp, body = a.do("POST", "/v1/peers/"+b.id+"/messages", map[string]any{
		"type": "note",
		"body": "hello from alice",
	}, nil)
	want(t, resp, body, 201)

	// Pairing token is single-use
	resp, body = anon.do("POST", "/v1/pairing/"+token, map[string]any{
		"name": "charlie",
	}, map[string]string{"X-Peerline-Register-Token": "test-reg-token"})
	want(t, resp, body, 404)
}

func TestPairingLinkAuthenticated(t *testing.T) {
	srv := newServer(t, Config{RegisterToken: "test-reg-token"})
	a := registerAs(t, srv, "alice", map[string]string{"X-Peerline-Register-Token": "test-reg-token"})
	b := registerAs(t, srv, "bob", map[string]string{"X-Peerline-Register-Token": "test-reg-token"})

	// Alice creates pairing link
	resp, body := a.do("POST", "/v1/invites", map[string]any{
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
	token := strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	// Bob accepts with existing credentials (authenticated)
	resp, body = b.do("POST", "/v1/pairing/"+token, map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 200)
	var result struct {
		GrantedToYou store.Grant `json:"granted_to_you"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.GrantedToYou.Owner != a.id || result.GrantedToYou.Grantee != b.id {
		t.Fatalf("grant: %+v", result.GrantedToYou)
	}

	// Verify messaging works
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{
		"type": "note",
		"body": "test",
	}, nil)
	want(t, resp, body, 201)
}

func TestPairingLinkInvalid(t *testing.T) {
	srv := newServer(t, Config{})
	anon := &client{t: t, srv: srv}

	// Invalid token format
	resp, body := anon.do("GET", "/v1/pairing/invalid", nil, nil)
	want(t, resp, body, 400)

	// Non-existent token
	resp, body = anon.do("GET", "/v1/pairing/pair_aGVsbG8gd29ybGQgaXMgaGVyZQ", nil, nil)
	want(t, resp, body, 404)
}

func TestPairingLinkSelfAccept(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Create pairing link
	resp, body := a.do("POST", "/v1/invites", map[string]any{
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
	token := strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	// Alice cannot accept her own pairing link
	resp, body = a.do("POST", "/v1/pairing/"+token, nil, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "cannot accept your own") {
		t.Fatalf("unexpected error: %s", body)
	}
}

func TestPairingLinkWithoutGenerateFlag(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Create normal invite without generate_pairing
	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	want(t, resp, body, 201)
	var inv map[string]any
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	// Should not have pairing_url
	if _, exists := inv["pairing_url"]; exists {
		t.Fatal("pairing_url should not exist without generate_pairing flag")
	}

	// Should still have code and accept_url
	if inv["code"] == nil || inv["accept_url"] == nil {
		t.Fatal("missing code or accept_url")
	}
}

func TestPairingAcceptStatusCodes(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Create pairing link
	resp, body := a.do("POST", "/v1/invites", map[string]any{
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
	token := strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	// Test 404: Invalid/nonexistent token
	resp, body = noAuth.do("POST", "/v1/pairing/invalid_token", map[string]any{
		"name": "Bob",
	}, nil)
	want(t, resp, body, 404)
	if !strings.Contains(string(body), "invalid, used, or expired") {
		t.Errorf("unexpected 404 body: %s", body)
	}

	// Test 400: Self-accept (alice created the invite, bob tries with alice's id - simulated by bad name logic)
	// Actually, we'll test missing name for 400
	resp, body = noAuth.do("POST", "/v1/pairing/"+token, map[string]any{}, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "name required") {
		t.Errorf("unexpected 400 body: %s", body)
	}

	// Test 201: Successful unauthenticated pairing
	resp, body = noAuth.do("POST", "/v1/pairing/"+token, map[string]any{
		"name": "Bob",
	}, nil)
	want(t, resp, body, 201)
	var result struct {
		PeerID     string `json:"peer_id"`
		APIKey     string `json:"api_key"`
		PairedWith string `json:"paired_with"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.PeerID == "" || result.APIKey == "" || result.PairedWith == "" {
		t.Fatalf("missing fields in 201 response: %+v", result)
	}
	if result.PairedWith != a.id {
		t.Errorf("paired_with = %s, want %s", result.PairedWith, a.id)
	}

	// Test 404: Token already used
	resp, body = noAuth.do("POST", "/v1/pairing/"+token, map[string]any{
		"name": "Carol",
	}, nil)
	want(t, resp, body, 404)
	if !strings.Contains(string(body), "invalid, used, or expired") {
		t.Errorf("unexpected 404 for used token: %s", body)
	}
}

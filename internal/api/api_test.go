package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	anon := &client{t: t, srv: srv}

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

	// Test 404: Invalid/nonexistent token (must be properly formatted but not in DB)
	resp, body = anon.do("POST", "/v1/pairing/pair_nonexistenttoken1234", map[string]any{
		"name": "Bob",
	}, nil)
	want(t, resp, body, 404)
	if !strings.Contains(string(body), "invalid, used, or expired") {
		t.Errorf("unexpected 404 body: %s", body)
	}

	// Test 400: Self-accept (alice created the invite, bob tries with alice's id - simulated by bad name logic)
	// Actually, we'll test missing name for 400
	resp, body = anon.do("POST", "/v1/pairing/"+token, map[string]any{}, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "name required") {
		t.Errorf("unexpected 400 body: %s", body)
	}

	// Test 201: Successful unauthenticated pairing
	resp, body = anon.do("POST", "/v1/pairing/"+token, map[string]any{
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
	resp, body = anon.do("POST", "/v1/pairing/"+token, map[string]any{
		"name": "Carol",
	}, nil)
	want(t, resp, body, 404)
	if !strings.Contains(string(body), "invalid, used, or expired") {
		t.Errorf("unexpected 404 for used token: %s", body)
	}
}

// Security hardening tests for #17, #18, #21-#24, #31-#39

func TestXFFParsing(t *testing.T) {
	trustedNets, _ := ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.1"})

	tests := []struct {
		name        string
		remoteAddr  string
		xff         []string
		trustedNets []*net.IPNet
		want        string
	}{
		{
			name:        "client-forged leftmost entry",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"1.2.3.4, 203.0.113.5"},
			trustedNets: trustedNets,
			want:        "203.0.113.5", // rightmost untrusted
		},
		{
			name:        "untrusted RemoteAddr ignores XFF",
			remoteAddr:  "203.0.113.1:5678",
			xff:         []string{"1.2.3.4, 10.0.0.5"},
			trustedNets: trustedNets,
			want:        "203.0.113.1",
		},
		{
			name:        "chain of trusted proxies",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.99, 10.0.0.2, 10.0.0.3"},
			trustedNets: trustedNets,
			want:        "203.0.113.99",
		},
		{
			name:        "IPv4-mapped IPv6 normalization",
			remoteAddr:  "[::ffff:203.0.113.5]:1234",
			xff:         nil,
			trustedNets: nil,
			want:        "203.0.113.5",
		},
		{
			name:        "IPv6 canonical form",
			remoteAddr:  "[2001:0db8:0000:0000:0000:0000:0000:0001]:1234",
			xff:         nil,
			trustedNets: nil,
			want:        "2001:db8::1",
		},
		{
			name:        "bare IP trusted proxy",
			remoteAddr:  "192.168.1.1:1234",
			xff:         []string{"203.0.113.10"},
			trustedNets: trustedNets,
			want:        "203.0.113.10",
		},
		{
			name:        "multiple XFF headers combined",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"1.2.3.4, 203.0.113.20", "10.0.0.5"},
			trustedNets: trustedNets,
			want:        "203.0.113.20", // attacker in first header, proxy in second
		},
		{
			name:        "missing XFF header",
			remoteAddr:  "10.0.0.1:1234",
			xff:         nil,
			trustedNets: trustedNets,
			want:        "10.0.0.1", // falls back to RemoteAddr
		},
		{
			name:        "empty XFF header value",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{""},
			trustedNets: trustedNets,
			want:        "10.0.0.1", // falls back to RemoteAddr
		},
		{
			name:        "whitespace and empty entries in XFF",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"  , , 203.0.113.30, , 10.0.0.2  "},
			trustedNets: trustedNets,
			want:        "203.0.113.30", // skips empty/whitespace entries
		},
		{
			name:        "all XFF entries trusted fallback",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"10.0.0.2, 10.0.0.3, 192.168.1.1"},
			trustedNets: trustedNets,
			want:        "10.0.0.1", // all XFF trusted, falls back to RemoteAddr
		},
		{
			name:        "IPv6 in XFF chain",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"2001:db8::42, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "2001:db8::42", // IPv6 address returned in canonical form
		},
		{
			name:        "spoofed leftmost never used",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"99.99.99.99", "203.0.113.50, 10.0.0.5"},
			trustedNets: trustedNets,
			want:        "203.0.113.50", // rightmost untrusted, not leftmost spoof
		},
		{
			name:        "malformed IP in XFF skipped",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"not-an-ip, 203.0.113.60, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "203.0.113.60", // skips malformed, takes next valid untrusted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientIP(tt.remoteAddr, tt.xff, tt.trustedNets)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "valid CIDRs",
			cidrs:   []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantErr: false,
			wantLen: 2,
		},
		{
			name:    "bare IPs",
			cidrs:   []string{"10.0.0.1", "192.168.1.1"},
			wantErr: false,
			wantLen: 2,
		},
		{
			name:    "mixed",
			cidrs:   []string{"10.0.0.0/8", "192.168.1.1"},
			wantErr: false,
			wantLen: 2,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"10.0.0.0/999"},
			wantErr: true,
		},
		{
			name:    "invalid IP",
			cidrs:   []string{"not-an-ip"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseTrustedProxies(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTrustedProxies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(nets) != tt.wantLen {
				t.Errorf("ParseTrustedProxies() len = %d, want %d", len(nets), tt.wantLen)
			}
		})
	}
}

func TestIPv6RateLimitKeyPrefixing(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "IPv6 uses /64 prefix",
			ip:   "2001:db8:1234:5678:abcd:ef01:2345:6789",
			want: "2001:db8:1234:5678::",
		},
		{
			name: "IPv6 different host same /64",
			ip:   "2001:db8:1234:5678:9999:9999:9999:9999",
			want: "2001:db8:1234:5678::",
		},
		{
			name: "IPv4 unchanged",
			ip:   "203.0.113.42",
			want: "203.0.113.42",
		},
		{
			name: "IPv4-mapped IPv6 unmapped then full",
			ip:   "::ffff:203.0.113.42",
			want: "203.0.113.42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rateLimitKey(tt.ip)
			if got != tt.want {
				t.Errorf("rateLimitKey(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestAuthenticatedGETRateLimiting(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")
	b := register(t, srv, "bob")

	// Authenticated GETs are per-peer-id (120/min, burst 40)
	// Alice hammers /v1/me, Bob should be unaffected
	for i := 0; i < 45; i++ {
		resp, body := a.do("GET", "/v1/me", nil, nil)
		if i < 40 {
			want(t, resp, body, 200)
		} else {
			// After burst exhausted, should be rate limited
			if resp.StatusCode != 429 {
				t.Fatalf("iteration %d: expected 429, got %d", i, resp.StatusCode)
			}
			break
		}
	}

	// Bob should still be fine
	resp, body := b.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
}

func TestInboxPollingNoRateLimit(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Realistic polling: authLim is 120/min = 2/s sustained, burst 40
	// Test that we can use the full burst without hitting 429
	for i := 0; i < 40; i++ {
		resp, body := a.do("GET", "/v1/inbox", nil, nil)
		if resp.StatusCode == 429 {
			t.Fatalf("iteration %d: unexpected 429 during burst polling", i)
		}
		want(t, resp, body, 200)
	}

	// After burst, wait for refill (1 second gives us 2 more tokens)
	time.Sleep(1 * time.Second)

	// Should be able to make 2 more requests
	for i := 0; i < 2; i++ {
		resp, body := a.do("GET", "/v1/inbox", nil, nil)
		if resp.StatusCode == 429 {
			t.Fatalf("after refill: unexpected 429 during polling")
		}
		want(t, resp, body, 200)
	}
}

func TestRegisterRateLimitAfterTokenCheck(t *testing.T) {
	srv := newServer(t, Config{RegisterToken: "secret123"})

	// Without register token, should fail with 403 before charging rate limit
	// We can hammer this without getting 429
	for i := 0; i < 20; i++ {
		resp, body := doAnon(t, srv, "POST", "/v1/register", map[string]any{"name": "test"}, nil)
		want(t, resp, body, 403)
		if strings.Contains(string(body), "rate limited") {
			t.Fatal("got 429 before token check")
		}
	}
}

func TestPairingRateLimitAfterTokenValidation(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Create a pairing invite
	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)
	var inv struct {
		PairingURL string `json:"pairing_url"`
	}
	json.Unmarshal(body, &inv)
	validToken := strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	// Invalid token format should fail validation before charging pairLim (returns 400)
	// Use token that doesn't match the regex (too short or wrong prefix)
	for i := 0; i < 15; i++ {
		resp, body := doAnon(t, srv, "POST", "/v1/pairing/bad", map[string]any{"name": "test"}, nil)
		want(t, resp, body, 400)
		if strings.Contains(string(body), "rate limited") {
			t.Fatal("got rate limit before format check")
		}
	}

	// Valid token should work (charges pairLim after format validation)
	resp, body = doAnon(t, srv, "POST", "/v1/pairing/"+validToken, map[string]any{"name": "bob"}, nil)
	want(t, resp, body, 201)
}

func TestInviteListPagination(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")
	b := register(t, srv, "bob")

	// Alice creates 5 invites
	for i := 0; i < 5; i++ {
		resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
		want(t, resp, body, 201)
	}

	// List with limit=2
	resp, body := a.do("GET", "/v1/invites?limit=2", nil, nil)
	want(t, resp, body, 200)
	var list1 struct {
		Invites []store.InviteMetadata `json:"invites"`
	}
	json.Unmarshal(body, &list1)
	if len(list1.Invites) != 2 {
		t.Fatalf("expected 2 invites, got %d", len(list1.Invites))
	}

	// List with limit=2&offset=2
	resp, body = a.do("GET", "/v1/invites?limit=2&offset=2", nil, nil)
	want(t, resp, body, 200)
	var list2 struct {
		Invites []store.InviteMetadata `json:"invites"`
	}
	json.Unmarshal(body, &list2)
	if len(list2.Invites) != 2 {
		t.Fatalf("expected 2 invites, got %d", len(list2.Invites))
	}

	// Bob can't see Alice's invites
	resp, body = b.do("GET", "/v1/invites", nil, nil)
	want(t, resp, body, 200)
	var listB struct {
		Invites []store.InviteMetadata `json:"invites"`
	}
	json.Unmarshal(body, &listB)
	if len(listB.Invites) != 0 {
		t.Fatalf("Bob should see 0 invites, got %d", len(listB.Invites))
	}
}

func TestDeleteInviteByID(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")
	b := register(t, srv, "bob")

	// Alice creates an invite
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct {
		PublicID string `json:"public_id"`
	}
	json.Unmarshal(body, &inv)

	// Bob can't delete Alice's invite
	resp, body = b.do("DELETE", fmt.Sprintf("/v1/invites/%s", inv.PublicID), nil, nil)
	want(t, resp, body, 404)

	// Alice can delete her own invite
	resp, body = a.do("DELETE", fmt.Sprintf("/v1/invites/%s", inv.PublicID), nil, nil)
	want(t, resp, body, 204)

	// Repeat delete returns 404
	resp, body = a.do("DELETE", fmt.Sprintf("/v1/invites/%s", inv.PublicID), nil, nil)
	want(t, resp, body, 404)
}

func TestInviteCodeNeverLogged(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	srv := newServer(t, Config{Logger: logger})
	a := register(t, srv, "alice")

	// Create an invite
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct {
		Code     string `json:"code"`
		PublicID string `json:"public_id"`
	}
	json.Unmarshal(body, &inv)

	// Delete the invite (triggers log)
	a.do("DELETE", fmt.Sprintf("/v1/invites/%s", inv.PublicID), nil, nil)

	// Check logs don't contain the code or any prefix
	logs := logBuf.String()
	if strings.Contains(logs, inv.Code) {
		t.Error("invite code found in logs")
	}
	codePrefix := inv.Code[:10]
	if strings.Contains(logs, codePrefix) {
		t.Error("invite code prefix found in logs")
	}
	// Should contain public_id
	if !strings.Contains(logs, inv.PublicID) {
		t.Error("public_id not found in logs")
	}
}

func TestInviteCapEnforcedAtomically(t *testing.T) {
	srv := newServer(t, Config{MaxOutstandingInvites: 3})
	a := register(t, srv, "alice")

	// Create 3 invites (at cap)
	for i := 0; i < 3; i++ {
		resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
		want(t, resp, body, 201)
	}

	// 4th should fail
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 429)
	if !strings.Contains(string(body), "too many outstanding invites") {
		t.Errorf("unexpected error: %s", body)
	}
}

func TestInviteTTLDefaults(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// No TTL specified, should default to 1h
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct {
		ExpiresAt string `json:"expires_at"`
	}
	json.Unmarshal(body, &inv)
	expTime, _ := time.Parse(time.RFC3339, inv.ExpiresAt)
	if time.Until(expTime) > 65*time.Minute || time.Until(expTime) < 55*time.Minute {
		t.Errorf("expiry not ~1h from now: %v", expTime)
	}

	// TTL > 7 days should fail
	resp, body = a.do("POST", "/v1/invites", map[string]any{
		"scopes":      []string{"messages"},
		"ttl_seconds": 604801,
	}, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "must not exceed") {
		t.Errorf("unexpected error: %s", body)
	}
}

func TestGeneratePairingReturnsOnlyURL(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)

	var result map[string]any
	json.Unmarshal(body, &result)

	// Should have pairing_url and public_id
	if _, ok := result["pairing_url"]; !ok {
		t.Error("missing pairing_url")
	}
	if _, ok := result["public_id"]; !ok {
		t.Error("missing public_id")
	}

	// Should NOT have code or accept_url
	if _, ok := result["code"]; ok {
		t.Error("code should not be present")
	}
	if _, ok := result["accept_url"]; ok {
		t.Error("accept_url should not be present")
	}
}

func TestGeneratePairingWithEmailRejected(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
		"to_email":         "bob@example.com",
	}, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "cannot combine") {
		t.Errorf("unexpected error: %s", body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := newServer(t, Config{})

	resp, _ := doAnon(t, srv, "GET", "/", nil, nil)

	headers := []struct {
		name string
		want string
	}{
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
		{"X-Content-Type-Options", "nosniff"},
	}

	for _, h := range headers {
		if got := resp.Header.Get(h.name); got != h.want {
			t.Errorf("%s = %q, want %q", h.name, got, h.want)
		}
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %s", csp)
	}
}

func TestNameSanitization(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "tag characters",
			input: "alice\U000E0020test",
			want:  "alicetest",
		},
		{
			name:  "bidi override",
			input: "alice\u202Etest",
			want:  "alicetest",
		},
		{
			name:  "bidi isolate",
			input: "alice\u2066test",
			want:  "alicetest",
		},
		{
			name:  "zero-width space",
			input: "alice\u200Btest",
			want:  "alicetest",
		},
		{
			name:  "length cap",
			input: strings.Repeat("a", 100),
			want:  strings.Repeat("a", 64),
		},
		{
			name:  "allowed chars preserved",
			input: "Alice-123 O'Brien",
			want:  "Alice-123 O'Brien",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPairingGETNoPrefilledScopes(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	// Create pairing link with specific scopes
	resp, body := a.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	want(t, resp, body, 201)
	var inv struct {
		PairingURL string `json:"pairing_url"`
	}
	json.Unmarshal(body, &inv)
	token := strings.Split(inv.PairingURL, "/v1/pairing/")[1]

	// GET the pairing page
	resp, body = doAnon(t, srv, "GET", "/v1/pairing/"+token, nil, nil)
	want(t, resp, body, 200)

	var pairingResp map[string]any
	json.Unmarshal(body, &pairingResp)

	// Should contain consent language in instructions
	instructions, ok := pairingResp["instructions"].(map[string]any)
	if !ok {
		t.Fatal("missing instructions")
	}
	summary, ok := instructions["summary"].(string)
	if !ok || !strings.Contains(strings.ToLower(summary), "approval") {
		t.Error("instructions missing consent/approval language")
	}

	// Check that example POST bodies show empty scopes
	auth, ok := instructions["authenticated"].(map[string]any)
	if !ok {
		t.Fatal("missing authenticated instructions")
	}
	authBody, ok := auth["body"].(string)
	if !ok || !strings.Contains(authBody, `"scopes":[]`) {
		t.Error("authenticated example should show empty scopes")
	}

	unauth, ok := instructions["unauthenticated"].(map[string]any)
	if !ok {
		t.Fatal("missing unauthenticated instructions")
	}
	unauthBody, ok := unauth["body"].(string)
	if !ok || !strings.Contains(unauthBody, `"scopes":[]`) {
		t.Error("unauthenticated example should show empty scopes")
	}

	// Top-level scopes field should show what the inviter is offering (can be non-empty)
	// That's intentional and not a security issue
	topScopes, ok := pairingResp["scopes"].([]any)
	if !ok {
		t.Error("missing top-level scopes field")
	}
	if len(topScopes) == 0 {
		t.Error("top-level scopes should show what inviter is offering")
	}
}

func doAnon(t *testing.T, srv *httptest.Server, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	anon := &client{t: t, srv: srv}
	return anon.do(method, path, body, hdr)
}

// Lifecycle tests for LimiterManager and MaintenanceManager

func TestLimiterManagerStops(t *testing.T) {
	cfg := Config{
		MsgPerMinute:     60,
		MsgBurst:         10,
		EmailPerHour:     10,
		EmailBurst:       5,
		EmailRcptPerHour: 10,
		NotifyPerHour:    10,
		NotifyBurst:      5,
	}
	mgr := NewLimiterManager(cfg)

	// Let it run a bit
	time.Sleep(100 * time.Millisecond)

	// Call Stop
	mgr.Stop()

	// Calling Stop again should not panic
	mgr.Stop()
}

func TestMaintenanceManagerStops(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mgr := NewMaintenanceManager(ctx, st, logger, 30*24*60*60)

	// Let it run a bit
	time.Sleep(100 * time.Millisecond)

	// Call Stop
	mgr.Stop()

	// Calling Stop again should not panic
	mgr.Stop()
}

// TestRevokePreventsPairing verifies DELETE by public_id causes pairing to fail (#59 partial)
func TestRevokePreventsPairing(t *testing.T) {
	cfg := Config{}
	srv := newServer(t, cfg)
	alice := register(t, srv, "Alice")
	bob := register(t, srv, "Bob")

	// Create a pairing invite
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"generate_pairing": true,
		"scopes":           []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: %d %s", resp.StatusCode, b)
	}
	var invResp struct {
		PublicID   string `json:"public_id"`
		PairingURL string `json:"pairing_url"`
	}
	json.Unmarshal(b, &invResp)

	// Delete the invite by public_id
	resp, b = alice.do("DELETE", "/v1/invites/"+invResp.PublicID, nil, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete invite: %d %s", resp.StatusCode, b)
	}

	// Extract pairing token from URL
	parts := strings.Split(invResp.PairingURL, "/v1/pairing/")
	pairingToken := parts[len(parts)-1]

	// Attempt pairing (should fail with 404)
	c := &client{t: t, srv: srv}
	resp, b = c.do("POST", "/v1/pairing/"+pairingToken, map[string]string{
		"name": "Bob",
	}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("pairing after revoke: status %d, want 404, body %s", resp.StatusCode, b)
	}

	// Second DELETE is idempotent (returns 404 per documented behavior)
	resp, b = alice.do("DELETE", "/v1/invites/"+invResp.PublicID, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second DELETE: status %d, want 404 (idempotent/not found)", resp.StatusCode)
	}

	// Unknown public_id returns 404
	resp, b = alice.do("DELETE", "/v1/invites/ffffffffffffffffffffffffffffffff", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown public_id DELETE: status %d, want 404", resp.StatusCode)
	}

	// Bob creates an invite
	resp, b = bob.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bob create invite: %d %s", resp.StatusCode, b)
	}
	var bobInv struct {
		PublicID string `json:"public_id"`
	}
	json.Unmarshal(b, &bobInv)

	// Alice tries to delete Bob's invite (returns 404, not found or not owner)
	resp, b = alice.do("DELETE", "/v1/invites/"+bobInv.PublicID, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("other owner's public_id DELETE: status %d, want 404", resp.StatusCode)
	}
}

// TestInviteCapBeforeEmailBudget verifies cap check doesn't consume email quota (#53)
func TestInviteCapBeforeEmailBudget(t *testing.T) {
	cfg := Config{}
	cfg.MaxOutstandingInvites = 2 // Set cap to 2
	srv := newServer(t, cfg)
	alice := register(t, srv, "Alice")

	// Create first invite (should succeed, 1/2)
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "bob@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Create second invite (should succeed, 2/2 - at cap)
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "carol@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("second invite (at cap): %d %s", resp.StatusCode, b)
	}

	// Attempt third invite (one over cap, should fail without spending email budget)
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "dave@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("over-cap invite: status %d, want 429, body %s", resp.StatusCode, b)
	}
	if !bytes.Contains(b, []byte("too many outstanding invites")) {
		t.Errorf("over-cap error: %s, want cap message", b)
	}
	if !bytes.Contains(b, []byte("limit 2")) {
		t.Errorf("over-cap error: should mention limit 2")
	}
}

// TestSingleLogLineUnauthenticatedPairing verifies exactly one log line (#54)
func TestSingleLogLineUnauthenticatedPairing(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{}
	cfg.Logger = logger
	srv := httptest.NewServer(New(st, cfg).Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	// Create a pairing invite
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"generate_pairing": true,
		"scopes":           []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var invResp struct {
		PairingURL string `json:"pairing_url"`
	}
	json.Unmarshal(b, &invResp)

	parts := strings.Split(invResp.PairingURL, "/v1/pairing/")
	pairingToken := parts[len(parts)-1]

	// Clear buffer
	buf.Reset()

	// Redeem pairing link (unauthenticated)
	c := &client{t: t, srv: srv}
	resp, b = c.do("POST", "/v1/pairing/"+pairingToken, map[string]string{
		"name": "Bob",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("pairing: %d %s", resp.StatusCode, b)
	}

	// Check log output
	logs := buf.String()
	count := strings.Count(logs, "\"msg\":\"peer registered and paired\"")
	if count != 1 {
		t.Errorf("log lines with 'peer registered and paired': %d, want 1\nLogs:\n%s", count, logs)
	}

	// Verify no pairing token in logs
	if strings.Contains(logs, pairingToken) {
		t.Errorf("pairing token found in logs")
	}
}

// TestSanitizerUnicode verifies Unicode handling in sanitizeInviterName
func TestSanitizerUnicode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Basic cases
		{"ASCII", "Alice Smith", "Alice Smith"},
		{"Unicode letters", "José García", "José García"},
		{"Chinese", "李明", "李明"},
		{"Japanese", "田中太郎", "田中太郎"},
		{"Arabic", "محمد علي", "محمد علي"},
		{"Mixed valid", "Alice-O'Neil, Jr.", "Alice-O'Neil, Jr."},
		{"Hindi with combining marks", "राजेश कुमार", "राजेश कुमार"},
		{"Thai with combining marks", "สมชาย ใจดี", "สมชาย ใจดี"},

		// Bidi controls (Cf category) - all filtered
		{"Bidi LRE", "Alice\u202AEvil", "AliceEvil"},
		{"Bidi RLE", "Alice\u202BEvil", "AliceEvil"},
		{"Bidi PDF", "Alice\u202CEvil", "AliceEvil"},
		{"Bidi LRO", "Alice\u202DEvil", "AliceEvil"},
		{"Bidi RLO", "Alice\u202EEvil", "AliceEvil"},
		{"Bidi LRI", "Alice\u2066Evil", "AliceEvil"},
		{"Bidi RLI", "Alice\u2067Evil", "AliceEvil"},
		{"Bidi FSI", "Alice\u2068Evil", "AliceEvil"},
		{"Bidi PDI", "Alice\u2069Evil", "AliceEvil"},
		{"Bidi LRM", "Alice\u200EEvil", "AliceEvil"},
		{"Bidi RLM", "Alice\u200FEvil", "AliceEvil"},

		// Zero-width and format characters (Cf category)
		{"Zero-width space", "Alice\u200BEvil", "AliceEvil"},
		{"Zero-width non-joiner", "Alice\u200CEvil", "AliceEvil"},
		{"Zero-width joiner", "Alice\u200DEvil", "AliceEvil"},
		{"BOM", "Alice\uFEFFEvil", "AliceEvil"},

		// Tag characters
		{"Tag space", "Alice\U000E0020Evil", "AliceEvil"},
		{"Tag char", "Alice\U000E0041Evil", "AliceEvil"},

		// Hangul fillers
		{"Hangul filler U+115F", "Alice\u115FEvil", "AliceEvil"},
		{"Hangul filler U+1160", "Alice\u1160Evil", "AliceEvil"},
		{"Hangul filler U+3164", "Alice\u3164Evil", "AliceEvil"},
		{"Hangul filler U+FFA0", "Alice\uFFA0Evil", "AliceEvil"},

		// Variation selectors
		{"Variation selector FE00", "Alice\uFE00Evil", "AliceEvil"},
		{"Variation selector FE0F", "Alice\uFE0FEvil", "AliceEvil"},
		{"Variation selector E0100", "Alice\U000E0100Evil", "AliceEvil"},

		// NFKC normalization
		{"Fullwidth ASCII", "Ａｌｉｃｅ", "Alice"},  // Fullwidth → ASCII
		{"Superscript", "Alice²", "Alice2"},    // ² → 2
		{"Ligature", "ﬁle", "file"},            // ﬁ → fi
		{"Circled number", "Alice①", "Alice1"}, // ① → 1
		{"Compatibility ideograph", "塚", "塚"},  // U+FA10 → U+585A

		// Space collapsing
		{"Multiple spaces", "Alice   Smith", "Alice Smith"},
		{"Leading spaces", "   Alice", "Alice"},
		{"Trailing spaces", "Alice   ", "Alice"},
		{"Mixed whitespace", "Alice  \t  Smith", "Alice Smith"}, // Tab becomes space, then collapsed

		// Emoji and symbols (filtered out)
		{"Emoji removed", "Alice 😀 Smith", "Alice Smith"},
		{"Symbol removed", "Alice ★ Smith", "Alice Smith"},

		// Edge cases
		{"Empty string", "", ""},
		{"Only spaces", "   ", ""},
		{"Only filtered chars", "\u200B\u200C\uFEFF", ""},
		// 64 runes (not bytes): "日" is 3 bytes, 64 copies = 192 bytes, should keep exactly 64 runes
		{"Long multibyte truncated at 64 runes", strings.Repeat("日", 70), strings.Repeat("日", 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestAPIClock verifies that api.Server.now is used in createInvite.
// Note: the API clock (Server.now, time.Time) and the store clock (Store.now, int64)
// are independent and can disagree; this test only fakes the API clock.
func TestAPIClock(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := New(st, Config{})
	defer srv.Stop()

	// Stub the clock and verify non-nil default
	if srv.now == nil {
		t.Fatal("New() should set non-nil default clock")
	}
	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return fixedTime }

	// Create test server and client
	testSrv := httptest.NewServer(srv.Handler())
	defer testSrv.Close()

	// Register a peer
	c := &client{t: t, srv: testSrv}
	resp, body := c.do("POST", "/v1/register", map[string]string{"name": "alice"}, nil)
	want(t, resp, body, 201)
	var reg struct{ PeerID, APIKey string }
	if err := json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&reg.PeerID, &reg.APIKey}); err != nil {
		t.Fatal(err)
	}
	c.id, c.key = reg.PeerID, reg.APIKey

	// Create an invite with default TTL (1h)
	resp, body = c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)

	var inv struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	expTime, err := time.Parse(time.RFC3339, inv.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	expected := fixedTime.Add(time.Hour).UTC()
	if !expTime.Equal(expected) {
		t.Errorf("expires_at = %v, want %v", expTime, expected)
	}

	// Boundary test: advance clock by 100 seconds and create another invite
	srv.now = func() time.Time { return fixedTime.Add(100 * time.Second) }
	resp, body = c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}
	expTime, err = time.Parse(time.RFC3339, inv.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	expected = fixedTime.Add(100*time.Second + time.Hour).UTC()
	if !expTime.Equal(expected) {
		t.Errorf("expires_at after +100s = %v, want %v", expTime, expected)
	}
}

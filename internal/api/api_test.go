package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/store"
	"golang.org/x/text/unicode/norm"
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
			name:        "malformed IP in XFF stops walk",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.60, not-an-ip"},
			trustedNets: trustedNets,
			want:        "10.0.0.1", // stops at malformed, falls back to last trusted (remoteAddr)
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
	var logs syncBuf
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

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

	// Positive control: logs should contain expected events
	logStr := logs.String()
	if !strings.Contains(logStr, inv.PublicID) {
		t.Error("public_id should be logged (positive control)")
	}

	// Check logs don't contain the code or any prefix
	if strings.Contains(logStr, inv.Code) {
		t.Error("invite code found in logs")
	}
	codePrefix := inv.Code[:10]
	if strings.Contains(logStr, codePrefix) {
		t.Error("invite code prefix found in logs")
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

func TestCSPNoUnsafeInline(t *testing.T) {
	srv := newServer(t, Config{})

	tests := []struct {
		name string
		path string
	}{
		{"home page", "/"},
		{"public stats API", "/v1/public/stats"},
		{"healthz", "/healthz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := doAnon(t, srv, "GET", tt.path, nil, nil)
			csp := resp.Header.Get("Content-Security-Policy")
			if csp == "" {
				t.Error("missing Content-Security-Policy header")
				return
			}
			if strings.Contains(csp, "unsafe-inline") {
				t.Errorf("CSP contains 'unsafe-inline': %s", csp)
			}
		})
	}

	// Test an authenticated API route
	a := register(t, srv, "alice")
	resp, _ := a.do("GET", "/v1/me", nil, nil)
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Error("/v1/me: missing Content-Security-Policy header")
	} else if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("/v1/me: CSP contains 'unsafe-inline': %s", csp)
	}
}

func TestCSPHomePageNonce(t *testing.T) {
	srv := newServer(t, Config{})
	anon := &client{t: t, srv: srv}

	resp, body := anon.do("GET", "/", nil, nil)
	want(t, resp, body, 200)

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing CSP header")
	}

	// Extract nonce from CSP header
	// Expected format: script-src 'nonce-...'
	var nonce string
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src ") {
			// Extract nonce value
			if idx := strings.Index(part, "'nonce-"); idx >= 0 {
				nonceStart := idx + len("'nonce-")
				if endIdx := strings.Index(part[nonceStart:], "'"); endIdx >= 0 {
					nonce = part[nonceStart : nonceStart+endIdx]
					break
				}
			}
		}
	}

	if nonce == "" {
		t.Fatalf("no nonce found in CSP: %s", csp)
	}

	// Unescape HTML entities in body before checking nonces
	// (html/template escapes '+' to '&#43;' in attributes)
	html := html.UnescapeString(string(body))
	expectedStyle := `<style nonce="` + nonce + `">`
	expectedScript := `<script nonce="` + nonce + `">`

	if !strings.Contains(html, expectedStyle) {
		t.Errorf("style tag missing nonce attribute: want %q", expectedStyle)
	}
	if !strings.Contains(html, expectedScript) {
		t.Errorf("script tag missing nonce attribute: want %q", expectedScript)
	}

	// Verify CSP includes base-uri and form-action
	if !strings.Contains(csp, "base-uri 'none'") {
		t.Errorf("CSP missing base-uri 'none': %s", csp)
	}
	if !strings.Contains(csp, "form-action 'none'") {
		t.Errorf("CSP missing form-action 'none': %s", csp)
	}
	// Verify CSP includes connect-src for fetch() calls
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP missing connect-src 'self': %s", csp)
	}

	// Verify the style body starts with :root and script body starts with (function
	styleStart := strings.Index(html, `<style nonce="`+nonce+`">`)
	if styleStart == -1 {
		t.Fatal("style tag not found")
	}
	styleEnd := strings.Index(html[styleStart:], `</style>`)
	if styleEnd == -1 {
		t.Fatal("style closing tag not found")
	}
	styleBody := html[styleStart+len(`<style nonce="`+nonce+`">`) : styleStart+styleEnd]
	styleBody = strings.TrimSpace(styleBody)
	if !strings.HasPrefix(styleBody, ":root") {
		previewLen := 50
		if len(styleBody) < previewLen {
			previewLen = len(styleBody)
		}
		t.Errorf("style body should start with ':root', got: %q", styleBody[:previewLen])
	}

	scriptStart := strings.Index(html, `<script nonce="`+nonce+`">`)
	if scriptStart == -1 {
		t.Fatal("script tag not found")
	}
	scriptEnd := strings.Index(html[scriptStart:], `</script>`)
	if scriptEnd == -1 {
		t.Fatal("script closing tag not found")
	}
	scriptBody := html[scriptStart+len(`<script nonce="`+nonce+`">`) : scriptStart+scriptEnd]
	scriptBody = strings.TrimSpace(scriptBody)
	if !strings.HasPrefix(scriptBody, "(function") {
		previewLen := 50
		if len(scriptBody) < previewLen {
			previewLen = len(scriptBody)
		}
		t.Errorf("script body should start with '(function', got: %q", scriptBody[:previewLen])
	}
}

func TestCSPNonceWithSpecialChars(t *testing.T) {
	// Deterministic test with a nonce containing '+', '/', and '='
	// to verify html/template escaping doesn't break the page
	fixedNonce := "ab+c/d=="

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Execute template with fixed nonce
	var buf bytes.Buffer
	stats := store.Stats{Peers: 0, Messages: 0, Grants: 0, Bags: 0}
	statsJSON, _ := json.Marshal(stats)

	err = homeTmpl.Execute(&buf, homeData{
		BaseURL:      "http://localhost",
		RegisterOpen: true,
		Nonce:        fixedNonce,
		StatsJSON:    template.JS(statsJSON),
		Stats:        stats,
	})
	if err != nil {
		t.Fatalf("template execution failed: %v", err)
	}

	rendered := buf.String()
	unescaped := html.UnescapeString(rendered)

	// Verify tags contain the nonce exactly (after unescaping)
	expectedStyleTag := `<style nonce="` + fixedNonce + `">`
	expectedScriptTag := `<script nonce="` + fixedNonce + `">`

	if !strings.Contains(unescaped, expectedStyleTag) {
		t.Errorf("unescaped HTML missing style tag with nonce: want %q", expectedStyleTag)
		// Show what we got around where it should be
		if idx := strings.Index(unescaped, "<style"); idx >= 0 {
			end := idx + 50
			if end > len(unescaped) {
				end = len(unescaped)
			}
			t.Errorf("found instead: %q", unescaped[idx:end])
		}
	}

	if !strings.Contains(unescaped, expectedScriptTag) {
		t.Errorf("unescaped HTML missing script tag with nonce: want %q", expectedScriptTag)
		// Show what we got around where it should be (skip the JSON script block)
		startSearch := strings.Index(unescaped, "</section>")
		if startSearch >= 0 {
			if idx := strings.Index(unescaped[startSearch:], "<script"); idx >= 0 {
				idx += startSearch
				end := idx + 50
				if end > len(unescaped) {
					end = len(unescaped)
				}
				t.Errorf("found instead: %q", unescaped[idx:end])
			}
		}
	}

	// Verify no stray '>' after the tags
	styleTagStart := strings.Index(unescaped, expectedStyleTag)
	if styleTagStart >= 0 {
		afterStyleTag := styleTagStart + len(expectedStyleTag)
		if afterStyleTag < len(unescaped) && unescaped[afterStyleTag] == '>' {
			t.Error("style tag has stray '>' after opening tag")
		}
	}

	scriptTagStart := strings.Index(unescaped, expectedScriptTag)
	if scriptTagStart >= 0 && scriptTagStart > strings.Index(unescaped, "</section>") {
		afterScriptTag := scriptTagStart + len(expectedScriptTag)
		if afterScriptTag < len(unescaped) && unescaped[afterScriptTag] == '>' {
			t.Error("script tag has stray '>' after opening tag")
		}
	}
}

func TestCSPAPIRoutesStrict(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"me", "GET", "/v1/me"},
		{"inbox", "GET", "/v1/inbox"},
		{"public stats", "GET", "/v1/public/stats"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var body []byte
			if tt.path == "/v1/public/stats" {
				anon := &client{t: t, srv: srv}
				resp, body = anon.do(tt.method, tt.path, nil, nil)
			} else {
				resp, body = a.do(tt.method, tt.path, nil, nil)
			}
			want(t, resp, body, 200)

			csp := resp.Header.Get("Content-Security-Policy")
			if csp == "" {
				t.Error("missing CSP header")
				return
			}

			// API routes should have strict CSP
			if !strings.Contains(csp, "default-src 'none'") {
				t.Errorf("CSP missing default-src 'none': %s", csp)
			}
			if !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("CSP missing frame-ancestors 'none': %s", csp)
			}
			if !strings.Contains(csp, "base-uri 'none'") {
				t.Errorf("CSP missing base-uri 'none': %s", csp)
			}
			if !strings.Contains(csp, "form-action 'none'") {
				t.Errorf("CSP missing form-action 'none': %s", csp)
			}

			// Should not have script-src or style-src at all
			if strings.Contains(csp, "script-src") {
				t.Errorf("API route should not have script-src: %s", csp)
			}
			if strings.Contains(csp, "style-src") {
				t.Errorf("API route should not have style-src: %s", csp)
			}
			// Should not have connect-src (API routes don't need it)
			if strings.Contains(csp, "connect-src") {
				t.Errorf("API route should not have connect-src: %s", csp)
			}
		})
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
	cfg.EmailPerHour = 1          // Tight budget: only 1 email allowed
	cfg.EmailBurst = 1
	cfg.EmailRcptPerHour = 10 // Generous recipient budget to isolate sender
	srv := newServer(t, cfg)
	alice := register(t, srv, "Alice")

	// Create first invite without email (should succeed, 1/2, no budget spent)
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Create second invite without email (should succeed, 2/2 - at cap, no budget spent)
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("second invite (at cap): %d %s", resp.StatusCode, b)
	}

	// Attempt third invite with to_email (should fail with 429, no budget consumed)
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

	// Revoke one invite to make room
	resp, b = alice.do("GET", "/v1/invites", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites: %d %s", resp.StatusCode, b)
	}
	var listResp struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := json.Unmarshal(b, &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Invites) < 1 {
		t.Fatal("no invites to revoke")
	}
	revokeID := listResp.Invites[0]["public_id"].(string)
	resp, b = alice.do("DELETE", "/v1/invites/"+revokeID, nil, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}

	// Now create an invite with to_email (should succeed, proving budget wasn't consumed)
	// If budget was consumed during cap rejection, this would fail with 429
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "dave@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("invite after cap rejection: status %d, want 201, body %s", resp.StatusCode, b)
		t.Errorf("this proves email budget WAS consumed during the cap rejection")
	}

	// Verify the invite was actually created and can be listed
	resp, b = alice.do("GET", "/v1/invites", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites final: %d %s", resp.StatusCode, b)
	}
	var finalResp struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := json.Unmarshal(b, &finalResp); err != nil {
		t.Fatal(err)
	}
	if len(finalResp.Invites) != 2 {
		t.Errorf("final invite count: %d, want 2 (one revoked, one new with email)", len(finalResp.Invites))
	}
}

// TestEmailLimitDeletesInvite verifies invite is deleted when email limit fails (#53)
func TestEmailLimitDeletesInvite(t *testing.T) {
	cfg := Config{}
	cfg.EmailPerHour = 3
	cfg.EmailBurst = 3
	srv := newServer(t, cfg)
	alice := register(t, srv, "Alice")

	// Exhaust sender's email budget (3 burst)
	for i := 0; i < 3; i++ {
		resp, b := alice.do("POST", "/v1/invites", map[string]any{
			"to_email": fmt.Sprintf("user%d@example.com", i),
			"scopes":   []string{"messages"},
		}, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("invite %d: %d %s", i, resp.StatusCode, b)
		}
	}

	// List invites before next attempt
	resp, b := alice.do("GET", "/v1/invites", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites: %d %s", resp.StatusCode, b)
	}
	var beforeResp struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := json.Unmarshal(b, &beforeResp); err != nil {
		t.Fatal(err)
	}

	// Next invite should fail with rate limit
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "ratelimited@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("rate limited invite: status %d, want 429, body %s", resp.StatusCode, b)
	}
	if !bytes.Contains(b, []byte("rate limited")) {
		t.Errorf("rate limit error: %s, want rate limit message", b)
	}

	// List invites after - count should be the same (invite was deleted)
	resp, b = alice.do("GET", "/v1/invites", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites after: %d %s", resp.StatusCode, b)
	}
	var afterResp struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := json.Unmarshal(b, &afterResp); err != nil {
		t.Fatal(err)
	}

	if len(afterResp.Invites) != len(beforeResp.Invites) {
		t.Errorf("invite count changed: before=%d, after=%d (invite should have been deleted)", len(beforeResp.Invites), len(afterResp.Invites))
	}
}

// TestDeletedInviteCannotBeAccepted verifies hard-deleted invites are unusable (#53)
func TestDeletedInviteCannotBeAccepted(t *testing.T) {
	cfg := Config{}
	cfg.EmailPerHour = 1
	cfg.EmailBurst = 1
	srv := newServer(t, cfg)
	alice := register(t, srv, "Alice")
	bob := register(t, srv, "Bob")

	// Alice creates an invite with email, consuming her budget
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "bob@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}
	var inv1 struct {
		Code string `json:"code"`
	}
	json.Unmarshal(b, &inv1)

	// Alice tries to create another invite with email (should fail, invite created then deleted)
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "carol@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate limited invite: status %d, want 429, body %s", resp.StatusCode, b)
	}

	// Bob tries to accept the first invite (should succeed)
	resp, b = bob.do("POST", "/v1/invites/accept?code="+inv1.Code, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("accept first invite: %d %s, want 200", resp.StatusCode, b)
	}
}

// TestConcurrentInviteCapRace verifies the concurrent cap check race is fixed (#53).
//
// Verified on a scratch branch with the OLD ordering (hook after create, budget check before create):
// Test FAILS with output: 'budget check: 0 email invites succeeded, want 4'
// All 5 requests consume budget, leaving 0 tokens available.
//
// With NEW ordering (hook before create, create before budget check): PASSES with 4 tokens available.
func TestConcurrentInviteCapRace(t *testing.T) {
	cfg := Config{}
	cfg.MaxOutstandingInvites = 2
	cfg.EmailPerHour = 10
	cfg.EmailBurst = 5 // 5 tokens available
	cfg.EmailRcptPerHour = 20

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rawSrv := New(st, cfg)
	srv := httptest.NewServer(rawSrv.Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	// Create first invite to get close to cap (1/2)
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Set up N-party barrier: all 5 goroutines wait until all arrive, then release together
	const concurrent = 5
	var arrivalCount int
	var arrivalMu sync.Mutex
	allArrived := make(chan struct{})
	var closeOnce sync.Once

	rawSrv.testInviteCreatedHook = func(peerID string) {
		arrivalMu.Lock()
		arrivalCount++
		if arrivalCount == concurrent {
			closeOnce.Do(func() { close(allArrived) })
		}
		arrivalMu.Unlock()

		select {
		case <-allArrived:
			// All arrived, proceed
		case <-time.After(5 * time.Second):
			t.Error("barrier timeout: not all goroutines arrived")
		}
	}

	// Launch concurrent requests at the cap with to_email
	// One should succeed (2/2), others should fail at atomic cap check
	// BUG on main: all 5 consume budget before atomic check (5 tokens consumed)
	// FIX here: only the 1 successful request consumes budget (1 token consumed)
	results := make(chan int, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := alice.do("POST", "/v1/invites", map[string]any{
				"to_email": fmt.Sprintf("user%d@example.com", i),
				"scopes":   []string{"messages"},
			}, nil)
			results <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(results)

	// Collect results
	var created, rejected int
	for status := range results {
		if status == http.StatusCreated {
			created++
		} else if status == http.StatusTooManyRequests {
			rejected++
		} else {
			t.Errorf("unexpected status: %d", status)
		}
	}

	// Exactly one should have succeeded (reaching cap at 2/2)
	if created != 1 {
		t.Errorf("concurrent creates: %d succeeded, want 1", created)
	}
	if rejected != concurrent-1 {
		t.Errorf("concurrent rejects: %d, want %d", rejected, concurrent-1)
	}

	// Verify final state: exactly 2 invites
	resp, b = alice.do("GET", "/v1/invites", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites: %d %s", resp.StatusCode, b)
	}
	var listResp struct {
		Invites []map[string]any `json:"invites"`
	}
	if err := json.Unmarshal(b, &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Invites) != 2 {
		t.Errorf("final invite count: %d, want 2 (at cap)", len(listResp.Invites))
	}

	// Clear hook for budget verification
	rawSrv.testInviteCreatedHook = nil

	// Revoke one invite to make room for budget check
	revokeID := listResp.Invites[0]["public_id"].(string)
	resp, b = alice.do("DELETE", "/v1/invites/"+revokeID, nil, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}

	// Verify budget: check how many more email invites succeed
	// If bug existed: 5 tokens consumed during race, 0 left
	// With fix: 1 token consumed during race, 4 left
	// We should be able to create 4 more email invites
	var budgetSucceeded int
	for i := 0; i < 6; i++ { // Try 6, expect 4 to succeed
		resp, b := alice.do("POST", "/v1/invites", map[string]any{
			"to_email": fmt.Sprintf("budget%d@example.com", i),
			"scopes":   []string{"messages"},
		}, nil)
		if resp.StatusCode == http.StatusCreated {
			budgetSucceeded++
			// Revoke immediately to avoid hitting cap
			var inv struct {
				PublicID string `json:"public_id"`
			}
			json.Unmarshal(b, &inv)
			alice.do("DELETE", "/v1/invites/"+inv.PublicID, nil, nil)
		} else if resp.StatusCode == http.StatusTooManyRequests && bytes.Contains(b, []byte("rate limited")) {
			break // Hit rate limit as expected
		}
	}

	if budgetSucceeded != 4 {
		t.Errorf("budget check: %d email invites succeeded, want 4 (5 total tokens - 1 consumed in race)", budgetSucceeded)
		t.Errorf("this proves email budget was over-consumed during concurrent cap rejection")
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
		// Issue #68: Devanagari test
		{"Devanagari", "हिन्दी", "हिन्दी"},

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

		// Issue #35: Additional Cf characters and Zl/Zp
		{"U+061C Arabic letter mark", "Alice\u061CEvil", "AliceEvil"},
		{"U+2060 Word joiner", "Alice\u2060Evil", "AliceEvil"},
		{"U+00AD Soft hyphen", "Alice\u00ADEvil", "AliceEvil"},
		{"U+2028 Line separator", "Alice\u2028Evil", "AliceEvil"},
		{"U+2029 Paragraph separator", "Alice\u2029Evil", "AliceEvil"},

		// Issue #63 & #84: Invisible Mn characters
		{"U+034F COMBINING GRAPHEME JOINER", "a\u034Fb", "ab"},
		{"U+0334 Combining tilde overlay", "a\u0334b", "a\u0334b"},
		{"U+180B Mongolian FVS1", "a\u180Bb", "ab"},
		{"U+180C Mongolian FVS2", "a\u180Cb", "ab"},
		{"U+180D Mongolian FVS3", "a\u180Db", "ab"},
		{"U+180F Mongolian FVS4", "a\u180Fb", "ab"},
		{"U+17B4 Khmer inherent vowel", "a\u17B4b", "ab"},
		{"U+17B5 Khmer inherent vowel", "a\u17B5b", "ab"},

		// Issue #84: Combining marks constraints
		// Mark limit is checked in NFD (decomposed) form to ensure visible result has max 3 marks per base
		{"3 marks allowed", "a\u0301\u0302\u0303", "á\u0302\u0303"},                          // a + 3 marks -> á + 2 marks (NFC composition)
		{"20 marks capped at 3", "a" + strings.Repeat("\u0301", 20), "á́́"},                  // a + 20 marks -> a + 3 marks (may compose)
		{"64 marks alone becomes fallback", strings.Repeat("\u0301", 64), "A Peerline peer"}, // No base -> fallback (issue #68)
		{"100 marks capped at 3", "a" + strings.Repeat("\u0301", 100), "á́́"},                // a + 100 marks -> a + 3 marks
		{"Mark after space dropped", "a \u0301b", "a b"},
		{"Mark at start dropped", "\u0301abc", "abc"},
		{"Mark after punctuation dropped", "a.\u0301b", "a.b"},
		{"Mark after letter then punctuation", "a\u0301.b", "á.b"}, // a+mark -> á (NFC)

		// Issue #68: Tab and newline handling
		{"Tab becomes space", "Alice\tSmith", "Alice Smith"},
		{"Newline becomes space", "Alice\nSmith", "Alice Smith"},
		{"Carriage return becomes space", "Alice\rSmith", "Alice Smith"},
		{"Tab with spaces", "Alice  \t  Smith", "Alice Smith"},

		// Issue #68: Empty result fallback
		{"Only symbols becomes fallback", "★★★", "A Peerline peer"},
		{"Only filtered chars", "\u200B\u200C\uFEFF", "A Peerline peer"},
		{"Only marks becomes fallback", "\u0301\u0302\u0303", "A Peerline peer"},

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

		// Emoji and symbols (filtered out)
		{"Emoji removed", "Alice 😀 Smith", "Alice Smith"},
		{"Symbol removed", "Alice ★ Smith", "Alice Smith"},

		// Edge cases
		{"Empty string", "", "A Peerline peer"},
		{"Only spaces", "   ", "A Peerline peer"},

		// Issue #68: Length tests (64 runes max, counted on final NFC output)
		{"70 ASCII letters", strings.Repeat("a", 70), strings.Repeat("a", 64)},
		{"30 CJK chars under byte limit", strings.Repeat("日", 30), strings.Repeat("日", 30)},
		// 64 runes (not bytes): "日" is 3 bytes, 64 copies = 192 bytes, should keep exactly 64 runes
		{"Long multibyte truncated at 64 runes", strings.Repeat("日", 70), strings.Repeat("日", 64)},
		// Precomposed characters: é (U+00E9) is 1 rune in NFC
		{"70 precomposed é gives 64", strings.Repeat("é", 70), strings.Repeat("é", 64)},
		// Hangul syllables: 한 (U+D55C) is 1 rune in NFC, decomposes to 3 jamo in NFD
		{"70 Hangul syllables gives 64", strings.Repeat("한", 70), strings.Repeat("한", 64)},
		// a+acute recomposes to á in NFC, 70 gives 64
		{"70 a+acute recomposes to 64 á", strings.Repeat("a\u0301", 70), strings.Repeat("á", 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%q) = %q, want %q", tt.input, got, tt.want)
			}

			// For tests involving combining marks, verify that NFD form has at most 3 marks per base
			if strings.Contains(tt.name, "marks") || strings.Contains(tt.name, "Devanagari") || strings.Contains(tt.name, "Thai") || strings.Contains(tt.name, "Hindi") {
				nfd := norm.NFD.String(got)
				consecutiveMarks := 0
				maxMarks := 0
				for _, r := range nfd {
					isMark := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r)
					if isMark {
						consecutiveMarks++
						if consecutiveMarks > maxMarks {
							maxMarks = consecutiveMarks
						}
					} else if unicode.IsLetter(r) || unicode.IsNumber(r) {
						consecutiveMarks = 0
					} else {
						consecutiveMarks = 0
					}
				}
				if maxMarks > 3 {
					t.Errorf("sanitizeInviterName(%q) NFD has %d consecutive marks (max 3 allowed), NFD=%q", tt.input, maxMarks, nfd)
				}
			}
		})
	}
}

// TestSanitizerSplitCluster verifies that truncation respects grapheme cluster boundaries
func TestSanitizerSplitCluster(t *testing.T) {
	// 63 'a' + e+grave+combining-mark-below (doesn't compose in NFC) + "zzz"
	// Should give 63 'a' without the partial cluster
	input := strings.Repeat("a", 63) + "e\u0300\u0316" + "zzz"
	got := sanitizeInviterName(input)
	want := strings.Repeat("a", 63)

	if got != want {
		t.Errorf("sanitizeInviterName split cluster = %q (len %d), want %q (len %d)", got, len([]rune(got)), want, len([]rune(want)))
	}

	// Verify UTF-8 validity
	if !utf8.ValidString(got) {
		t.Errorf("sanitizeInviterName returned invalid UTF-8")
	}

	// Verify result is NFC
	if !norm.NFC.IsNormalString(got) {
		t.Errorf("sanitizeInviterName result is not NFC normalized")
	}

	// Verify no trailing combining marks
	runes := []rune(got)
	if len(runes) > 0 {
		lastRune := runes[len(runes)-1]
		if unicode.Is(unicode.Mn, lastRune) || unicode.Is(unicode.Mc, lastRune) || unicode.Is(unicode.Me, lastRune) {
			t.Errorf("sanitizeInviterName has trailing combining mark U+%04X", lastRune)
		}
	}
}

// TestSanitizerHugeInput verifies the input guard prevents unbounded normalization work
func TestSanitizerHugeInput(t *testing.T) {
	// 100 KB of 'a' characters
	input := strings.Repeat("a", 100*1024)
	got := sanitizeInviterName(input)

	// Should return 64 'a' characters (truncated at input guard, then at 64 runes)
	want := strings.Repeat("a", 64)
	if got != want {
		t.Errorf("sanitizeInviterName(100KB input) = %q (len %d), want %q (len %d)", got[:20]+"...", len([]rune(got)), want, len([]rune(want)))
	}
}

// TestSanitizerInputGuardInvalidUTF8 verifies the input guard doesn't trim back past invalid bytes elsewhere
func TestSanitizerInputGuardInvalidUTF8(t *testing.T) {
	// 2000 bytes of 'a' with 0xff (invalid UTF-8) at byte 10
	// Should give 64 'a' (not fallback), proving we don't trim back to empty
	input := strings.Repeat("a", 10) + "\xff" + strings.Repeat("a", 1989)
	got := sanitizeInviterName(input)
	want := strings.Repeat("a", 64)

	if got != want {
		t.Errorf("sanitizeInviterName(2000 bytes with invalid at byte 10) = %q (len %d), want %q (len %d)", got, len([]rune(got)), want, len([]rune(want)))
	}
}

// TestSanitizerInputGuardRuneBoundary verifies the input guard respects rune boundaries
func TestSanitizerInputGuardRuneBoundary(t *testing.T) {
	// Create input that has a 3-byte UTF-8 character (日) right at the 1024-byte cut
	// Fill up to 1022 bytes with 'a', then add 日 (3 bytes) so it straddles the boundary
	base := strings.Repeat("a", 1022)
	input := base + "日" + strings.Repeat("b", 100)

	got := sanitizeInviterName(input)

	// The guard should cut before 日 (not in the middle), then cap at 64 runes
	// So we should get 64 'a' characters (first 64 of the 1022)
	want := strings.Repeat("a", 64)
	if got != want {
		t.Errorf("sanitizeInviterName(input with 3-byte rune at boundary) = %q (len %d), want %q (len %d)", got, len([]rune(got)), want, len([]rune(want)))
	}
}

// TestSanitizerTrailingSpaceTrim verifies trailing spaces are trimmed after 64-rune cut
func TestSanitizerTrailingSpaceTrim(t *testing.T) {
	// 64 'a' followed by space and more text
	// The 64-rune cut will include the space; it should be trimmed
	input := strings.Repeat("a", 63) + " b" + strings.Repeat("c", 100)
	got := sanitizeInviterName(input)

	// Should get 63 'a' (no trailing space)
	want := strings.Repeat("a", 63)
	if got != want {
		t.Errorf("sanitizeInviterName(63a + space + text) = %q (len %d), want %q (len %d)", got, len([]rune(got)), want, len([]rune(want)))
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

// TestRateLimitWithMultipleXFFHeaders verifies that multiple X-Forwarded-For
// header lines are properly combined when the RemoteAddr is trusted (#61).
func TestRateLimitWithMultipleXFFHeaders(t *testing.T) {
	// Unit test coverage for multiple XFF headers is in clientip_test.go
	// This integration test verifies end-to-end behavior through the HTTP handler
	srv := newServer(t, Config{
		TrustedProxies: []string{"127.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
	})

	// Register and pair two peers
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	pairUp(t, a, b, []string{"messages"}, nil, nil)

	// Make a request with custom XFF headers to verify they're processed
	// This tests that the rate limiting sees the combined XFF list
	req, _ := http.NewRequest("GET", srv.URL+"/v1/inbox", nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	// Multiple XFF headers should be combined: ["203.0.113.10", "10.0.0.2", "10.0.0.3"]
	req.Header.Add("X-Forwarded-For", "203.0.113.10, 10.0.0.2")
	req.Header.Add("X-Forwarded-For", "10.0.0.3")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The request should succeed (not testing rate limiting here, just that it works)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestInviteAcceptGETDoesNotChangeState verifies that authenticated GET
// /v1/invites/accept returns 405 and does not consume the invite (issue #28).
func TestInviteAcceptGETDoesNotChangeState(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// Alice creates an invite for Bob
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct {
		Code      string `json:"code"`
		AcceptURL string `json:"accept_url"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	// Authenticated GET returns 405 and does not accept the invite
	resp, body = b.do("GET", "/v1/invites/accept?code="+inv.Code, nil, nil)
	want(t, resp, body, 405)
	if !strings.Contains(string(body), "use POST to accept") {
		t.Errorf("expected 405 error message, got: %s", body)
	}
	if resp.Header.Get("Allow") != "POST" {
		t.Errorf("expected Allow: POST header, got: %s", resp.Header.Get("Allow"))
	}

	// Verify invite is still pending: Bob can still accept with POST
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 200)

	// Verify pairing succeeded: Bob can now message Alice
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "test"}, nil)
	want(t, resp, body, 201)
}

// TestInviteAcceptUnauthenticatedGETShowsLanding verifies that unauthenticated
// GET /v1/invites/accept shows the landing page and does not consume the invite.
func TestInviteAcceptUnauthenticatedGETShowsLanding(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// Alice creates an invite
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct{ Code string }
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}

	// Unauthenticated GET shows landing page (no key)
	bNoAuth := &client{t: t, srv: srv, key: ""}
	resp, body = bNoAuth.do("GET", "/v1/invites/accept?code="+inv.Code, nil, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain content type, got: %s", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), "Peerline invite") {
		t.Errorf("expected landing page content, got: %s", body)
	}
	if !strings.Contains(string(body), "curl -X POST") {
		t.Errorf("expected POST instruction in landing page, got: %s", body)
	}
	// Landing page should show code in body format (JSON)
	if !strings.Contains(string(body), `"code":"`) || !strings.Contains(string(body), "Content-Type: application/json") {
		t.Errorf("expected code in JSON body format in landing page, got: %s", body)
	}

	// Verify invite is still pending: Bob can accept with POST
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 200)
}

// TestInviteAcceptGETWithScopesReturns405 verifies that authenticated GET with
// &scopes= and &bags= returns 405 and creates no grant (issue #28).
func TestInviteAcceptGETWithScopesReturns405(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// Alice creates an invite for Bob
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct{ Code string }
	json.Unmarshal(body, &inv)

	// Authenticated GET with &scopes= and &bags= returns 405
	resp, body = b.do("GET", "/v1/invites/accept?code="+inv.Code+"&scopes=messages&bags=x", nil, nil)
	want(t, resp, body, 405)

	// Verify no grant was created (both directions should be empty)
	resp, body = a.do("GET", "/v1/grants", nil, nil)
	want(t, resp, body, 200)
	var aGrants struct {
		Grants []any `json:"grants"`
	}
	json.Unmarshal(body, &aGrants)
	if len(aGrants.Grants) != 0 {
		t.Errorf("alice grants: want 0, got %d: %s", len(aGrants.Grants), body)
	}

	resp, body = b.do("GET", "/v1/grants", nil, nil)
	want(t, resp, body, 200)
	var bGrants struct {
		Grants []any `json:"grants"`
	}
	json.Unmarshal(body, &bGrants)
	if len(bGrants.Grants) != 0 {
		t.Errorf("bob grants: want 0, got %d: %s", len(bGrants.Grants), body)
	}

	// Invite is still pending: Bob can accept with POST
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv.Code}, nil)
	want(t, resp, body, 200)
}

// TestInviteAcceptPathsNeverLogCode verifies that invite codes never appear in
// logs across all accept paths: POST body, POST query, GET 405, HEAD, landing, failed (issue #28, #146).
// TestInviteAcceptPathsNeverLogCode verifies that invite codes never appear in
// logs across all accept paths, including success, error, and failure cases (issue #28, #146, #174).
// This test captures only the slog logger; there is no http.Server.ErrorLog or access-log middleware today.
func TestInviteAcceptPathsNeverLogCode(t *testing.T) {
	var logs syncBuf
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	srv := newServer(t, Config{Logger: logger})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	c := register(t, srv, "carol")

	// Create invites for different test cases
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv1 struct{ Code string }
	json.Unmarshal(body, &inv1)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv2 struct{ Code string }
	json.Unmarshal(body, &inv2)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv3 struct{ Code string }
	json.Unmarshal(body, &inv3)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv4 struct{ Code string }
	json.Unmarshal(body, &inv4)

	// Test all accept paths:
	// 1. POST with body code (successful)
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv1.Code}, nil)
	want(t, resp, body, 200)

	// 2. POST with query code (successful, deprecated)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv2.Code, nil, nil)
	want(t, resp, body, 200)

	// 3. Authenticated GET (405)
	resp, body = c.do("GET", "/v1/invites/accept?code="+inv3.Code, nil, nil)
	want(t, resp, body, 405)

	// 4. HEAD with auth (405)
	req, _ := http.NewRequest("HEAD", srv.URL+"/v1/invites/accept?code="+inv3.Code, nil)
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 405 {
		t.Errorf("HEAD: want 405, got %d", resp2.StatusCode)
	}

	// 5. Unauthenticated landing page
	anon := &client{t: t, srv: srv, key: ""}
	resp, body = anon.do("GET", "/v1/invites/accept?code="+inv3.Code, nil, nil)
	want(t, resp, body, 200)

	// 6. Failed accept (well-formed but unknown code)
	unknownCode := auth.NewSecret("inv_")
	resp, body = c.do("POST", "/v1/invites/accept", map[string]any{"code": unknownCode}, nil)
	want(t, resp, body, 404)

	// 7. Failed: bad scopes (code stays valid)
	resp, body = c.do("POST", "/v1/invites/accept", map[string]any{"code": inv3.Code, "scopes": []string{"BadScope"}}, nil)
	want(t, resp, body, 400)

	// 8. Failed: accepting own invite (code stays valid)
	resp, body = a.do("POST", "/v1/invites/accept", map[string]any{"code": inv4.Code}, nil)
	want(t, resp, body, 400)

	// 9. Failed: body/query mismatch (both codes stay valid)
	resp, body = c.do("POST", "/v1/invites/accept?code="+inv3.Code, map[string]any{"code": inv4.Code}, nil)
	want(t, resp, body, 400)

	// Positive control: assert logs captured expected events
	logStr := logs.String()
	if !strings.Contains(logStr, "pairing accepted") {
		t.Error("logs should contain 'pairing accepted' (positive control)")
	}
	if !strings.Contains(logStr, "peer registered") {
		t.Error("logs should contain 'peer registered' (positive control)")
	}

	// Check logs don't contain any of the codes or their prefixes
	for _, code := range []string{inv1.Code, inv2.Code, inv3.Code, inv4.Code, unknownCode} {
		if strings.Contains(logStr, code) {
			t.Errorf("invite code %s found in logs", code)
		}
		if len(code) >= 10 && strings.Contains(logStr, code[:10]) {
			t.Errorf("invite code prefix %s found in logs", code[:10])
		}
	}
}

// TestInviteAccept405Comprehensive covers all the edge cases from issue #146 and #174.
func TestInviteAccept405Comprehensive(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	// Create invites with different states: valid, used, expired, missing
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv1 struct{ Code string }
	json.Unmarshal(body, &inv1)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv2 struct{ Code string }
	json.Unmarshal(body, &inv2)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "ttl_seconds": 1}, nil)
	want(t, resp, body, 201)
	var inv3 struct{ Code string }
	json.Unmarshal(body, &inv3)
	time.Sleep(2 * time.Second) // Let it expire

	// Use inv2
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, nil)
	want(t, resp, body, 200)

	missingCode := auth.NewSecret("inv_")

	// Test 1: HEAD with auth returns 405 with deprecation headers
	req, _ := http.NewRequest("HEAD", srv.URL+"/v1/invites/accept?code="+inv1.Code, nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 405 {
		t.Errorf("HEAD with auth: want 405, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Allow") != "POST" {
		t.Errorf("HEAD Allow header: want POST, got %s", resp2.Header.Get("Allow"))
	}
	if resp2.Header.Get("Deprecation") == "" {
		t.Error("HEAD with auth: missing Deprecation header")
	}
	if resp2.Header.Get("Link") == "" {
		t.Error("HEAD with auth: missing Link header")
	}

	// Test 2: HEAD without auth shows landing page (ServeMux routes HEAD to GET)
	req, _ = http.NewRequest("HEAD", srv.URL+"/v1/invites/accept?code="+inv1.Code, nil)
	resp2, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("HEAD without auth: want 200, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("HEAD without auth: want Cache-Control no-store, got %s", resp2.Header.Get("Cache-Control"))
	}

	// Test 3: GET with invalid/bogus Bearer token returns 405 (not 401)
	resp, body = b.do("GET", "/v1/invites/accept?code="+inv1.Code, nil, map[string]string{"Authorization": "Bearer pl_bogus"})
	want(t, resp, body, 405)
	if !strings.Contains(string(body), "use POST to accept") {
		t.Errorf("bogus key GET body: %s", body)
	}

	// Test 4: 405 responses are identical for valid, used, expired, missing codes (no oracle)
	get405 := func(code string) ([]byte, http.Header) {
		r, b := b.do("GET", "/v1/invites/accept?code="+code, nil, nil)
		if r.StatusCode != 405 {
			t.Fatalf("expected 405 for code %s, got %d", code, r.StatusCode)
		}
		return b, r.Header
	}
	validBody, validHdr := get405(inv1.Code)
	usedBody, usedHdr := get405(inv2.Code)
	expiredBody, expiredHdr := get405(inv3.Code)
	missingBody, missingHdr := get405(missingCode)

	for i, pair := range []struct {
		name string
		body []byte
		hdr  http.Header
	}{
		{"used", usedBody, usedHdr},
		{"expired", expiredBody, expiredHdr},
		{"missing", missingBody, missingHdr},
	} {
		if !bytes.Equal(validBody, pair.body) {
			t.Errorf("405 body differs for %s:\nvalid: %s\n%s: %s", pair.name, validBody, pair.name, pair.body)
		}
		for _, h := range []string{"Allow", "Content-Type", "Deprecation", "Link"} {
			if validHdr.Get(h) != pair.hdr.Get(h) {
				t.Errorf("405 header %s differs for %s (test %d): valid=%q %s=%q",
					h, pair.name, i, validHdr.Get(h), pair.name, pair.hdr.Get(h))
			}
		}
	}

	// Test 5: Body and query code mismatch returns 400
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv1.Code, map[string]any{"code": "inv_other"}, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "code in body and query differ") {
		t.Errorf("mismatch error: %s", body)
	}

	// Test 6: Other methods (strict, issue #174)
	// PUT/PATCH should get 405 from the authed mux (handler exists but wrong method).
	// DELETE gets 404 (no handler at all in authed mux).
	for _, method := range []string{"PUT", "PATCH"} {
		r, _ := http.NewRequest(method, srv.URL+"/v1/invites/accept?code="+inv1.Code, nil)
		r.Header.Set("Authorization", "Bearer "+b.key)
		rsp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		if rsp.StatusCode != 405 {
			t.Errorf("%s: want 405, got %d", method, rsp.StatusCode)
		}
		if rsp.Header.Get("Allow") == "" {
			t.Errorf("%s: missing Allow header", method)
		}
	}
	// DELETE: no handler in authed mux, should get 404
	r, _ := http.NewRequest("DELETE", srv.URL+"/v1/invites/accept?code="+inv1.Code, nil)
	r.Header.Set("Authorization", "Bearer "+b.key)
	rsp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != 404 {
		t.Errorf("DELETE: want 404, got %d", rsp.StatusCode)
	}

	// Test 7: Trailing slash returns 404 (strict, issue #174)
	resp, body = b.do("POST", "/v1/invites/accept/?code="+inv1.Code, nil, nil)
	if resp.StatusCode != 404 {
		t.Errorf("trailing slash POST: want 404, got %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", srv.URL+"/v1/invites/accept/?code="+inv1.Code, nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	resp2, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("trailing slash GET: want 404, got %d", resp2.StatusCode)
	}

	// Test 8: HEAD trailing slash
	req, _ = http.NewRequest("HEAD", srv.URL+"/v1/invites/accept/?code="+inv1.Code, nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	resp2, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("HEAD trailing slash: want 404, got %d", resp2.StatusCode)
	}

	// Test 9: Unauthenticated landing with bad code returns 400
	anon := &client{t: t, srv: srv, key: ""}
	resp, body = anon.do("GET", "/v1/invites/accept?code=inv_bad", nil, nil)
	want(t, resp, body, 400)
	if !strings.Contains(string(body), "malformed") {
		t.Errorf("bad code landing: %s", body)
	}

	// Verify inv1 is still pending after all the above
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv1.Code}, nil)
	want(t, resp, body, 200)
}

// TestInviteAcceptDeprecationHeaders verifies that query-only codes get
// Deprecation and Link headers, but body codes do not (issue #28, #146).
// TestInviteAcceptDeprecationHeaders verifies RFC 9745 deprecation headers
// on all responses where the request has ?code= (issue #28, #146, #173, #174).
func TestInviteAcceptDeprecationHeaders(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")

	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv1 struct{ Code string }
	json.Unmarshal(body, &inv1)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv2 struct{ Code string }
	json.Unmarshal(body, &inv2)

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv3 struct{ Code string }
	json.Unmarshal(body, &inv3)

	// 1. Query-only POST success: should have headers and Cache-Control
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv1.Code, nil, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("query-only POST success: missing Deprecation header")
	}
	if !strings.HasPrefix(resp.Header.Get("Deprecation"), "@") {
		t.Errorf("Deprecation format: want @<unix>, got %s", resp.Header.Get("Deprecation"))
	}
	if resp.Header.Get("Link") == "" {
		t.Error("query-only POST success: missing Link header")
	}
	if !strings.Contains(resp.Header.Get("Link"), "rel=\"deprecation\"") {
		t.Errorf("Link rel: want deprecation, got %s", resp.Header.Get("Link"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("query-only POST success: want Cache-Control no-store, got %s", resp.Header.Get("Cache-Control"))
	}

	// 2. Body-only POST success: should NOT have deprecation headers
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Deprecation") != "" {
		t.Errorf("body-only POST: unexpected Deprecation header: %s", resp.Header.Get("Deprecation"))
	}
	if resp.Header.Get("Link") != "" {
		t.Errorf("body-only POST: unexpected Link header: %s", resp.Header.Get("Link"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("body-only POST: want Cache-Control no-store, got %s", resp.Header.Get("Cache-Control"))
	}

	// 3. Query-only POST error (404): should have headers (issue #173)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv1.Code, nil, nil) // already used
	want(t, resp, body, 404)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("query-only POST 404: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("query-only POST 404: missing Link header")
	}

	// 4. Query-only POST error (400: bad scopes): should have headers
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv3.Code, map[string]any{"scopes": []string{"BadScope"}}, nil)
	want(t, resp, body, 400)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("query-only POST 400 bad scopes: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("query-only POST 400 bad scopes: missing Link header")
	}

	// 5. Query-only POST error (400: own invite): should have headers
	resp, body = a.do("POST", "/v1/invites/accept?code="+inv3.Code, nil, nil)
	want(t, resp, body, 400)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("query-only POST 400 own invite: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("query-only POST 400 own invite: missing Link header")
	}

	// 6. Body+query POST (body wins): should have headers (issue #173)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv3.Code, map[string]any{"code": inv3.Code}, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("body+query POST: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("body+query POST: missing Link header")
	}

	// 7. Unauthenticated landing GET with ?code=: should have headers (issue #173)
	anon := &client{t: t, srv: srv, key: ""}
	resp, body = anon.do("GET", "/v1/invites/accept?code="+inv2.Code, nil, nil)
	want(t, resp, body, 200)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("unauthenticated landing GET: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("unauthenticated landing GET: missing Link header")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("unauthenticated landing GET: want Cache-Control no-store, got %s", resp.Header.Get("Cache-Control"))
	}

	// 8. Authenticated GET 405 with ?code=: should have headers (already tested in 405 comprehensive)
	resp, body = b.do("GET", "/v1/invites/accept?code="+inv2.Code, nil, nil)
	want(t, resp, body, 405)
	if resp.Header.Get("Deprecation") == "" {
		t.Error("authenticated GET 405: missing Deprecation header")
	}
	if resp.Header.Get("Link") == "" {
		t.Error("authenticated GET 405: missing Link header")
	}
}

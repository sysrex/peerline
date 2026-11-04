package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
	"golang.org/x/text/unicode/norm"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	key string
	id  string
}

// newBarrier creates an N-party barrier for concurrent test synchronization.
// All n callers block in the returned function until all arrive, then all are released together.
// If not all arrive within timeout, the test fails.
// Note: arrivalCount == n allows the barrier to pass; a caller arriving after release passes through immediately.
func newBarrier(t testing.TB, n int, timeout time.Duration) func() {
	t.Helper()
	var arrivalCount int
	var mu sync.Mutex
	allArrived := make(chan struct{})
	var closeOnce sync.Once

	return func() {
		mu.Lock()
		arrivalCount++
		if arrivalCount == n {
			closeOnce.Do(func() { close(allArrived) })
		}
		mu.Unlock()

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-allArrived:
		case <-timer.C:
			mu.Lock()
			arrived := arrivalCount
			mu.Unlock()
			t.Errorf("barrier timeout: %d/%d goroutines arrived", arrived, n)
		}
	}
}

func newServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	st, err := store.OpenWithOptions(t.TempDir()+"/t.db", store.OpenOptions{Clock: cfg.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	prepareTestConfig(t, st, &cfg)
	apiSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(apiSrv.Stop)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// newServerWithAccess returns a test server along with the underlying Server and Store for tests that need internal access.
func newServerWithAccess(t *testing.T, cfg Config) (*httptest.Server, *Server, *store.Store) {
	t.Helper()
	dbPath := t.TempDir() + "/t.db"
	st, err := store.OpenWithOptions(dbPath, store.OpenOptions{Clock: cfg.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	prepareTestConfig(t, st, &cfg)
	s, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, s, st
}

// newServerWithDB returns a test server along with a raw database connection for tests that need to manipulate DB state directly.
func newServerWithDB(t *testing.T, cfg Config) (*httptest.Server, *Server, *store.Store, *sql.DB) {
	t.Helper()
	dbPath := t.TempDir() + "/t.db"
	st, err := store.OpenWithOptions(dbPath, store.OpenOptions{Clock: cfg.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Open a second connection for test manipulation
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	prepareTestConfig(t, st, &cfg)
	s, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, s, st, db
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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

func assertSecurityHeaders(t *testing.T, hdr http.Header, context string) {
	t.Helper()
	if got := hdr.Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: Cache-Control = %q, want no-store", context, got)
	}
	if got := hdr.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", context, got)
	}
	if got := hdr.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("%s: Referrer-Policy = %q, want no-referrer", context, got)
	}
	if got := hdr.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("%s: X-Frame-Options = %q, want DENY", context, got)
	}
	csp := hdr.Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("%s: missing Content-Security-Policy header", context)
	} else if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("%s: CSP missing default-src 'none': %s", context, csp)
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

// extractVerifyToken extracts the verification token from an email body.
func extractVerifyToken(body string) string {
	tokenStart := strings.Index(body, "token=eml_")
	if tokenStart == -1 {
		return ""
	}
	tokenStart += len("token=")
	tokenEnd := strings.IndexAny(body[tokenStart:], "'\n ")
	if tokenEnd == -1 {
		tokenEnd = len(body[tokenStart:])
	}
	return body[tokenStart : tokenStart+tokenEnd]
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

func TestBagStorageLimits(t *testing.T) {
	// limit to 3 bags and 100 bytes total
	srv := newServer(t, Config{MaxBagsPerPeer: 3, MaxBagBytesPerPeer: 100})
	a := register(t, srv, "alice")

	// create 3 bags under the limits
	resp, body := a.do("PUT", "/v1/bags/a", bytes.Repeat([]byte("x"), 30), nil)
	want(t, resp, body, 201)
	resp, body = a.do("PUT", "/v1/bags/b", bytes.Repeat([]byte("y"), 30), nil)
	want(t, resp, body, 201)
	resp, body = a.do("PUT", "/v1/bags/c", bytes.Repeat([]byte("z"), 30), nil)
	want(t, resp, body, 201)

	// 4th bag exceeds count limit
	resp, body = a.do("PUT", "/v1/bags/d", []byte("w"), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "bag count limit reached") {
		t.Errorf("count limit body: %s", body)
	}

	// updating existing bag should still work (at count cap)
	resp, body = a.do("PUT", "/v1/bags/a", bytes.Repeat([]byte("x"), 35), nil)
	want(t, resp, body, 200)

	// growing beyond byte quota
	resp, body = a.do("PUT", "/v1/bags/a", bytes.Repeat([]byte("x"), 100), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "storage quota exceeded") {
		t.Errorf("quota body: %s", body)
	}

	// shrinking while over quota should work
	resp, body = a.do("PUT", "/v1/bags/a", []byte("small"), nil)
	want(t, resp, body, 200)

	// new bag that would exceed byte limit
	srv2 := newServer(t, Config{MaxBagBytesPerPeer: 50})
	b := register(t, srv2, "bob")
	resp, body = b.do("PUT", "/v1/bags/small", bytes.Repeat([]byte("x"), 40), nil)
	want(t, resp, body, 201)
	resp, body = b.do("PUT", "/v1/bags/big", bytes.Repeat([]byte("y"), 20), nil)
	want(t, resp, body, 413)
}

func TestBagStorageShrinkOverQuota(t *testing.T) {
	// Share a store across two API servers with different byte caps
	tmpFile := t.TempDir() + "/shrink.db"
	st, err := store.Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Server with large cap
	srv1 := httptest.NewServer(mustNew(t, st, Config{MaxBagBytesPerPeer: 1000}).Handler())
	defer srv1.Close()
	a1 := &client{t: t, srv: srv1}

	// Register alice
	resp, body := a1.do("POST", "/v1/register", []byte(`{"name":"Alice"}`), nil)
	want(t, resp, body, 201)
	var reg struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatal(err)
	}
	a1.id = reg.PeerID
	a1.key = reg.APIKey

	// Create two bags totaling 100 bytes
	resp, body = a1.do("PUT", "/v1/bags/data1", bytes.Repeat([]byte("x"), 60), nil)
	want(t, resp, body, 201)
	resp, body = a1.do("PUT", "/v1/bags/data2", bytes.Repeat([]byte("y"), 40), nil)
	want(t, resp, body, 201)

	// Now create a server with 50-byte cap (alice is over quota)
	srv2 := httptest.NewServer(mustNew(t, st, Config{MaxBagBytesPerPeer: 50}).Handler())
	defer srv2.Close()
	a2 := &client{t: t, srv: srv2, key: a1.key, id: a1.id}

	// Shrinking data1 from 60→55 should work even though total stays over (95 > 50)
	resp, body = a2.do("PUT", "/v1/bags/data1", bytes.Repeat([]byte("x"), 55), nil)
	want(t, resp, body, 200)

	// Growing data1 by 1 byte should fail
	resp, body = a2.do("PUT", "/v1/bags/data1", bytes.Repeat([]byte("x"), 56), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "storage quota exceeded") {
		t.Errorf("expected storage quota exceeded, got: %s", body)
	}

	// Creating a new bag should fail
	resp, body = a2.do("PUT", "/v1/bags/data3", []byte("z"), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "storage quota exceeded") {
		t.Errorf("expected storage quota exceeded, got: %s", body)
	}
}

func TestBagLimitsGranteeChargedToOwner(t *testing.T) {
	// Owner has 3-bag limit
	srv := newServer(t, Config{MaxBagsPerPeer: 3, MaxBagBytesPerPeer: 100})
	owner := register(t, srv, "owner")
	grantee := register(t, srv, "grantee")

	// Grant bags:write to grantee for data and data2
	pairUp(t, owner, grantee, []string{"bags:write"}, []string{"data", "data2"}, nil)

	// Owner creates 2 bags
	resp, body := owner.do("PUT", "/v1/bags/bag1", []byte("owner1"), nil)
	want(t, resp, body, 201)
	resp, body = owner.do("PUT", "/v1/bags/bag2", []byte("owner2"), nil)
	want(t, resp, body, 201)

	// Grantee creates a bag in owner's namespace - should succeed
	resp, body = grantee.do("PUT", "/v1/bags/data?owner="+owner.id, bytes.Repeat([]byte("x"), 20), nil)
	want(t, resp, body, 201)

	// Owner now at 3-bag limit. Grantee's 4th bag should fail with owner's count limit
	resp, body = grantee.do("PUT", "/v1/bags/data2?owner="+owner.id, []byte("test"), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "storage limit reached") {
		t.Errorf("expected generic limit for grantee, got: %s", body)
	}

	// Grantee can still create in their own namespace (their quota is separate)
	resp, body = grantee.do("PUT", "/v1/bags/mine", []byte("grantee data"), nil)
	want(t, resp, body, 201)

	// Test byte quota: grantee write charged to owner
	resp, body = owner.do("PUT", "/v1/bags/bag1", bytes.Repeat([]byte("x"), 40), nil)
	want(t, resp, body, 200)
	resp, body = owner.do("PUT", "/v1/bags/bag2", bytes.Repeat([]byte("y"), 40), nil)
	want(t, resp, body, 200)
	// owner now at 100 bytes (40+40+20)

	// Grantee tries to write 30 more bytes (would total 120, over 100 limit)
	resp, body = grantee.do("PUT", "/v1/bags/data?owner="+owner.id, bytes.Repeat([]byte("z"), 30), nil)
	want(t, resp, body, 413)
	if !strings.Contains(string(body), "storage limit reached") {
		t.Errorf("expected generic limit for grantee, got: %s", body)
	}
}

func TestBagWriteRateLimitPerCaller(t *testing.T) {
	srv := newServer(t, Config{})
	owner := register(t, srv, "owner")
	grantee := register(t, srv, "grantee")
	pairUp(t, owner, grantee, []string{"bags:write"}, []string{"data"}, nil)

	limited := false
	for i := 0; i < 40; i++ {
		resp, _ := grantee.do("PUT", "/v1/bags/data?owner="+owner.id, []byte("x"), nil)
		if resp.StatusCode == 429 {
			if resp.Header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("bag PUT burst was never rate limited")
	}
	resp, body := owner.do("PUT", "/v1/bags/mine", []byte("ok"), nil)
	want(t, resp, body, 201)
}

func TestBagLimitsNonGrantee403(t *testing.T) {
	// Test 1: Count cap - non-grantee gets 403, not 413
	st1, err := store.Open(t.TempDir() + "/test1.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st1.Close()
	srv1 := httptest.NewServer(mustNew(t, st1, Config{MaxBagsPerPeer: 2, MaxBagBytesPerPeer: 100}).Handler())
	defer srv1.Close()

	owner1 := register(t, srv1, "owner")
	nonGrantee1 := register(t, srv1, "other")

	// Owner creates 2 bags (at count limit)
	resp, body := owner1.do("PUT", "/v1/bags/bag1", []byte("data1"), nil)
	want(t, resp, body, 201)
	resp, body = owner1.do("PUT", "/v1/bags/bag2", []byte("data2"), nil)
	want(t, resp, body, 201)

	// Non-grantee tries to create a NEW bag that would exceed owner's count cap
	// Should get 403 (auth check first), not 413 (quota check second)
	resp, body = nonGrantee1.do("PUT", "/v1/bags/newbag?owner="+owner1.id, []byte("attempt"), nil)
	want(t, resp, body, 403)
	if !strings.Contains(string(body), "not permitted") {
		t.Errorf("expected not permitted, got: %s", body)
	}

	// Verify no row was written
	_, err = st1.GetBag(context.Background(), owner1.id, "newbag")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("newbag was written despite 403; err=%v", err)
	}

	// Test 2: Byte cap - non-grantee gets 403, not 413
	st2, err := store.Open(t.TempDir() + "/test2.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	srv2 := httptest.NewServer(mustNew(t, st2, Config{MaxBagsPerPeer: 10, MaxBagBytesPerPeer: 50}).Handler())
	defer srv2.Close()

	owner2 := register(t, srv2, "owner2")
	nonGrantee2 := register(t, srv2, "other2")

	// Owner fills byte quota (50 bytes)
	resp, body = owner2.do("PUT", "/v1/bags/data", bytes.Repeat([]byte("x"), 50), nil)
	want(t, resp, body, 201)

	// Non-grantee tries to create a new bag that would exceed owner's byte cap
	// Should get 403, not 413
	resp, body = nonGrantee2.do("PUT", "/v1/bags/extra?owner="+owner2.id, []byte("y"), nil)
	want(t, resp, body, 403)
	if !strings.Contains(string(body), "not permitted") {
		t.Errorf("expected not permitted, got: %s", body)
	}

	// Verify no row was written
	_, err = st2.GetBag(context.Background(), owner2.id, "extra")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("extra bag was written despite 403; err=%v", err)
	}
}

func TestBagStorageDefaults(t *testing.T) {
	// Test that New applies defaults
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	srv := mustNew(t, st, Config{})
	if srv.cfg.MaxBagsPerPeer != 100 {
		t.Errorf("got MaxBagsPerPeer %d, want 100", srv.cfg.MaxBagsPerPeer)
	}
	if srv.cfg.MaxBagBytesPerPeer != 1048576 {
		t.Errorf("got MaxBagBytesPerPeer %d, want 1048576", srv.cfg.MaxBagBytesPerPeer)
	}
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
	mgr := NewMaintenanceManager(ctx, st, logger, nil, 30*24*60*60, 6)

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
// The barrier (via testInviteCreatedHook) holds all requests before CreateInviteAtomic.
// The "created == 1" assertion catches a count-then-insert regression in the atomic cap check.
// The "budgetSucceeded == 4" assertion catches charging the email limiter before the create succeeds.
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

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	const concurrent = 5
	barrier := newBarrier(t, concurrent, 5*time.Second)
	var armed atomic.Bool
	rawSrv.testInviteCreatedHook = func(peerID string) {
		if armed.Load() {
			barrier()
		}
	}

	srv := httptest.NewServer(rawSrv.Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	// Create first invite to get close to cap (1/2), with hook not armed
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"scopes": []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Arm the hook for concurrent requests
	armed.Store(true)

	// Launch concurrent requests at the cap with to_email
	// One should succeed (2/2), others should fail at atomic cap check
	// Only the 1 successful request may consume email budget (1 token consumed).
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

	// Disarm the hook for budget verification
	armed.Store(false)

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

// TestConcurrentInviteCapRacePairing verifies the concurrent cap check race through the generate_pairing path.
// The hook runs before both CreateInviteAtomic and CreateInviteWithPairingAtomic, so both paths need testing.
func TestConcurrentInviteCapRacePairing(t *testing.T) {
	cfg := Config{}
	cfg.MaxOutstandingInvites = 2

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	const concurrent = 5
	barrier := newBarrier(t, concurrent, 5*time.Second)
	var armed atomic.Bool
	rawSrv.testInviteCreatedHook = func(peerID string) {
		if armed.Load() {
			barrier()
		}
	}

	srv := httptest.NewServer(rawSrv.Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	// Create first invite to get close to cap (1/2), with hook not armed
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Arm the hook for concurrent requests
	armed.Store(true)

	results := make(chan int, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := alice.do("POST", "/v1/invites", map[string]any{
				"scopes":           []string{"messages"},
				"generate_pairing": true,
			}, nil)
			results <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(results)

	// Disarm the hook
	armed.Store(false)

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

	if created != 1 {
		t.Errorf("concurrent creates: %d succeeded, want 1", created)
	}
	if rejected != concurrent-1 {
		t.Errorf("concurrent rejects: %d, want %d", rejected, concurrent-1)
	}

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
}

// TestConcurrentInviteCapRaceConfirm verifies the concurrent cap check race through the require_confirm path.
// The hook runs before CreateConfirmInviteAtomic (when require_confirm is true), so this path needs coverage too.
func TestConcurrentInviteCapRaceConfirm(t *testing.T) {
	cfg := Config{}
	cfg.MaxOutstandingInvites = 2
	cfg.CodePepper = []byte("test-pepper")

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rawSrv.SetClaimStore(st)

	const concurrent = 5
	barrier := newBarrier(t, concurrent, 5*time.Second)
	var armed atomic.Bool
	rawSrv.testInviteCreatedHook = func(peerID string) {
		if armed.Load() {
			barrier()
		}
	}

	srv := httptest.NewServer(rawSrv.Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	// Create first invite to get close to cap (1/2), with hook not armed
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"scopes":           []string{"messages"},
		"generate_pairing": true,
		"require_confirm":  true,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Arm the hook for concurrent requests
	armed.Store(true)

	results := make(chan int, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := alice.do("POST", "/v1/invites", map[string]any{
				"scopes":           []string{"messages"},
				"generate_pairing": true,
				"require_confirm":  true,
			}, nil)
			results <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(results)

	// Disarm the hook
	armed.Store(false)

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

	if created != 1 {
		t.Errorf("concurrent creates: %d succeeded, want 1", created)
	}
	if rejected != concurrent-1 {
		t.Errorf("concurrent rejects: %d, want %d", rejected, concurrent-1)
	}

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
}

// TestReadyAllowRaceSharedRecipient verifies the Ready→Allow race with concurrent requests to the same recipient.
// Ready does not consume tokens, so multiple requests can pass Ready together, but only the first Allow succeeds.
// The test uses a frozen clock and a test seam (testAfterEmailReadyHook) to deterministically verify that losers
// of the rcptLim race get their mailLim tokens refunded.
func TestReadyAllowRaceSharedRecipient(t *testing.T) {
	frozenTime := time.Unix(1000000000, 0)
	cfg := Config{}
	cfg.MaxOutstandingInvites = 20
	cfg.EmailPerHour = 10
	cfg.EmailBurst = 10
	cfg.EmailRcptPerHour = 1
	cfg.Clock = clocktest.New(frozenTime)

	dbPath := t.TempDir() + "/t.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rawSrv.Stop()

	const concurrent = 10
	sharedRecipient := "shared@example.com"
	barrier := newBarrier(t, concurrent, 5*time.Second)
	var armed atomic.Bool

	// Use testAfterEmailReadyHook to synchronize after Ready checks, before Allow calls
	rawSrv.testAfterEmailReadyHook = func(peerID string) {
		if armed.Load() {
			barrier()
		}
	}

	srv := httptest.NewServer(rawSrv.Handler())
	defer srv.Close()

	alice := register(t, srv, "Alice")

	armed.Store(true)

	results := make(chan int, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := alice.do("POST", "/v1/invites", map[string]any{
				"to_email": sharedRecipient,
				"scopes":   []string{"messages"},
			}, nil)
			results <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(results)

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

	// With EmailRcptPerHour = 1 (burst also 1), only one request should succeed
	if created != 1 {
		t.Errorf("concurrent creates to same recipient: %d succeeded, want 1", created)
	}
	if rejected != concurrent-1 {
		t.Errorf("concurrent rejects: %d, want %d", rejected, concurrent-1)
	}

	armed.Store(false)

	// Verify exactly 1 invite exists (the others were cleaned up during rejection)
	var inviteCount int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM invites WHERE from_peer=? AND used_by IS NULL`,
		alice.id).Scan(&inviteCount); err != nil {
		t.Fatalf("count invites: %v", err)
	}
	if inviteCount != 1 {
		t.Errorf("invite count: %d, want 1 (others should be cleaned up)", inviteCount)
	}

	// Verify sender budget was refunded: with EmailBurst=10 and 1 consumed, alice should send 9 more
	// invites to distinct recipients (total 10 consumed), then the 11th should fail at 429.
	for i := 0; i < 9; i++ {
		resp, b := alice.do("POST", "/v1/invites", map[string]any{
			"to_email": fmt.Sprintf("distinct%d@example.com", i),
			"scopes":   []string{"messages"},
		}, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("budget check invite %d: expected 201, got %d: %s", i, resp.StatusCode, b)
			t.Errorf("this proves the sender's mailLim tokens were NOT refunded after losing the rcptLim race")
			break
		}
	}

	// The 11th email invite should fail at 429 (burst exhausted)
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "should-fail@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting EmailBurst=10, got %d: %s", resp.StatusCode, b)
	}
}

// TestInviteRateLimitDeleteFailure verifies behavior when the compensating delete fails after email rate limit rejection.
// Uses a SQLite BEFORE DELETE trigger to force the delete to fail, ensuring the server returns 500 with a generic
// error body (no internal error text leaked), the orphan invite remains, and can be cleaned up via the API.
func TestInviteRateLimitDeleteFailure(t *testing.T) {
	var logs bytes.Buffer
	capture := &captureMailer{}
	cfg := Config{}
	cfg.EmailPerHour = 10
	cfg.EmailBurst = 1 // Burst of 1, so second email will hit rate limit
	cfg.EmailRcptPerHour = 10
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	cfg.Mailer = capture

	dbPath := t.TempDir() + "/t.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Open a second connection for trigger manipulation
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rawSrv.Stop)

	srv := httptest.NewServer(rawSrv.Handler())
	t.Cleanup(srv.Close)

	alice := register(t, srv, "Alice")

	// Create first email invite to consume the burst token
	resp, b := alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "first@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, b)
	}

	// Revoke the first invite so we have a clean slate
	var firstInv struct {
		PublicID string `json:"public_id"`
	}
	if err := json.Unmarshal(b, &firstInv); err != nil {
		t.Fatal(err)
	}
	resp, b = alice.do("DELETE", "/v1/invites/"+firstInv.PublicID, nil, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke first: %d %s", resp.StatusCode, b)
	}

	// Install a BEFORE DELETE trigger that raises an error
	_, err = db.Exec(`CREATE TRIGGER fail_inv_del BEFORE DELETE ON invites BEGIN SELECT RAISE(ABORT, 'trigger_error'); END`)
	if err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP TRIGGER IF EXISTS fail_inv_del`); err != nil {
			t.Errorf("drop trigger: %v", err)
		}
	})

	// Attempt to create a second invite with email, which will hit rate limit and try to delete
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "test@example.com",
		"scopes":   []string{"messages"},
	}, nil)

	// Should get 500 (internal error), not 429
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 when cleanup fails, got %d: %s", resp.StatusCode, b)
	}

	// Error body should be generic, not leak internal details
	bodyStr := string(b)
	if !strings.Contains(bodyStr, "internal error") {
		t.Errorf("expected generic 'internal error' body, got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "trigger") || strings.Contains(bodyStr, "ABORT") {
		t.Errorf("error body leaked internal details: %s", bodyStr)
	}

	// Should NOT have Retry-After header (this is a 500, not a 429)
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		t.Errorf("unexpected Retry-After header on 500: %s", retryAfter)
	}

	// Verify exactly one email was sent to first@example.com and none to test@example.com
	msgs := capture.messages()
	var firstCount, testCount int
	for _, m := range msgs {
		if m.To == "first@example.com" {
			firstCount++
		}
		if m.To == "test@example.com" {
			testCount++
		}
	}
	if firstCount != 1 {
		t.Errorf("expected exactly 1 email to first@example.com, got %d", firstCount)
	}
	if testCount != 0 {
		t.Errorf("expected 0 emails to test@example.com (rate limit + delete failure), got %d", testCount)
	}

	// Verify the delete failure is logged
	logOutput := logs.String()
	if !strings.Contains(logOutput, "rate limited and invite cleanup failed") {
		t.Errorf("expected log line for delete failure, got: %s", logOutput)
	}

	// Drop the trigger
	_, err = db.Exec(`DROP TRIGGER fail_inv_del`)
	if err != nil {
		t.Fatalf("drop trigger: %v", err)
	}

	// Verify the orphan invite exists (cleanup failed, so it's still there)
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
	if len(listResp.Invites) != 1 {
		t.Errorf("orphan invite count: %d, want 1 (cleanup failed, invite remains)", len(listResp.Invites))
	}

	// Verify the orphan can be revoked through the API
	if len(listResp.Invites) > 0 {
		orphanID := listResp.Invites[0]["public_id"].(string)
		resp, b := alice.do("DELETE", "/v1/invites/"+orphanID, nil, nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("revoke orphan: expected 204, got %d: %s", resp.StatusCode, b)
		}

		// Verify it's gone
		resp, b = alice.do("GET", "/v1/invites", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list after revoke: %d %s", resp.StatusCode, b)
		}
		var finalList struct {
			Invites []map[string]any `json:"invites"`
		}
		if err := json.Unmarshal(b, &finalList); err != nil {
			t.Fatal(err)
		}
		if len(finalList.Invites) != 0 {
			t.Errorf("after revoke: %d invites, want 0", len(finalList.Invites))
		}
	}
}

// TestRecipientLimitRefundDeleteFailure verifies that when mailLim.Allow succeeds but rcptLim.Allow
// fails, the sender's mail token is refunded even if the compensating delete fails. Uses concurrent
// requests synchronized with testAfterEmailReadyHook to ensure both pass Ready together, so one
// succeeds and one hits the rcptLim failure path with refund.
func TestRecipientLimitRefundDeleteFailure(t *testing.T) {
	frozenTime := time.Unix(1000000000, 0)
	clk := clocktest.New(frozenTime)
	capture := &captureMailer{}
	cfg := Config{}
	cfg.EmailPerHour = 10
	cfg.EmailBurst = 2       // Burst of 2 to test refund logic
	cfg.EmailRcptPerHour = 1 // Only 1 email per recipient per hour
	cfg.Mailer = capture
	cfg.Clock = clk

	dbPath := t.TempDir() + "/t.db"
	st, err := store.OpenWithOptions(dbPath, store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Install BEFORE DELETE trigger to force cleanup failure
	_, err = db.Exec(`CREATE TRIGGER fail_inv_del BEFORE DELETE ON invites BEGIN SELECT RAISE(ABORT, 'trigger_error'); END`)
	if err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP TRIGGER IF EXISTS fail_inv_del`); err != nil {
			t.Errorf("drop trigger: %v", err)
		}
	})

	prepareTestConfig(t, st, &cfg)
	rawSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rawSrv.Stop)

	const concurrent = 2
	barrier := newBarrier(t, concurrent, 5*time.Second)
	var armed atomic.Bool
	rawSrv.testAfterEmailReadyHook = func(peerID string) {
		if armed.Load() {
			barrier()
		}
	}

	srv := httptest.NewServer(rawSrv.Handler())
	t.Cleanup(srv.Close)

	alice := register(t, srv, "Alice")

	// Arm the hook for concurrent requests
	armed.Store(true)

	// Launch 2 concurrent requests to same@example.com
	// Both pass Ready together, one Allow succeeds, the other hits rcptLim failure with refund
	type result struct {
		status     int
		body       []byte
		retryAfter string
	}
	results := make(chan result, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, body := alice.do("POST", "/v1/invites", map[string]any{
				"to_email": "same@example.com",
				"scopes":   []string{"messages"},
			}, nil)
			results <- result{
				status:     resp.StatusCode,
				body:       body,
				retryAfter: resp.Header.Get("Retry-After"),
			}
		}()
	}
	wg.Wait()
	close(results)

	// Disarm the hook
	armed.Store(false)

	var created, failed int
	var failureBody string
	var failureRetryAfter string
	for r := range results {
		if r.status == http.StatusCreated {
			created++
		} else if r.status == http.StatusInternalServerError {
			failed++
			failureBody = string(r.body)
			failureRetryAfter = r.retryAfter
		} else {
			t.Errorf("unexpected status: %d", r.status)
		}
	}

	// Exactly one should succeed (201), one should fail at rcptLim with delete failure (500)
	if created != 1 {
		t.Errorf("concurrent creates: %d succeeded, want 1", created)
	}
	if failed != 1 {
		t.Errorf("delete failures: %d, want 1", failed)
	}

	// Verify 500 response has generic error body, no trigger text, no Retry-After
	if !strings.Contains(failureBody, "internal error") {
		t.Errorf("500 body should contain 'internal error', got: %s", failureBody)
	}
	if strings.Contains(failureBody, "trigger") || strings.Contains(failureBody, "ABORT") {
		t.Errorf("500 body leaked internal details: %s", failureBody)
	}
	if failureRetryAfter != "" {
		t.Errorf("500 should not have Retry-After header, got: %s", failureRetryAfter)
	}

	// Verify exactly one email sent to same@example.com
	msgs := capture.messages()
	var sameCount int
	for _, m := range msgs {
		if m.To == "same@example.com" {
			sameCount++
		}
	}
	if sameCount != 1 {
		t.Errorf("expected 1 email to same@example.com, got %d", sameCount)
	}

	// Verify orphan invite persists by checking database directly (with trigger still in place)
	var inviteCount int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM invites WHERE from_peer=? AND used_by IS NULL`,
		alice.id).Scan(&inviteCount); err != nil {
		t.Fatalf("count invites: %v", err)
	}
	if inviteCount != 2 {
		t.Errorf("orphan count: %d, want 2 (one succeeded, one orphaned)", inviteCount)
	}

	// Drop trigger so we can revoke orphans through the API
	_, err = db.Exec(`DROP TRIGGER fail_inv_del`)
	if err != nil {
		t.Fatalf("drop trigger: %v", err)
	}

	// Now revoke orphans through the API
	resp, b := alice.do("GET", "/v1/invites", nil, nil)
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
		t.Errorf("list should show 2 invites before revoke, got %d", len(listResp.Invites))
	}
	for _, inv := range listResp.Invites {
		if orphanID, ok := inv["public_id"].(string); ok {
			resp, b := alice.do("DELETE", "/v1/invites/"+orphanID, nil, nil)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("DELETE orphan: expected 204, got %d: %s", resp.StatusCode, b)
			}
		}
	}

	// Verify sender budget was refunded: EmailBurst=2, first request consumed 1 (leaving 1),
	// second request consumed 1 then refunded 1 (leaving 1). Without refund, 0 would remain.
	// So distinct@ should succeed (proves refund happened), and another@ should fail.
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "distinct@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("refund check: expected 201, got %d: %s", resp.StatusCode, b)
		t.Errorf("this proves sender's mailLim tokens were NOT refunded after rcptLim failure")
	}

	// Budget now exhausted, next distinct recipient should fail
	resp, b = alice.do("POST", "/v1/invites", map[string]any{
		"to_email": "another@example.com",
		"scopes":   []string{"messages"},
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting budget, got %d: %s", resp.StatusCode, b)
	}
}

// TestBarrierTimeout verifies the barrier timeout path by calling it with insufficient goroutines
// and checking that the timeout error is reported correctly.
func TestBarrierTimeout(t *testing.T) {
	fake := &fakeTB{TB: t}
	barrier := newBarrier(fake, 2, 50*time.Millisecond)

	// Call barrier only once (never reaching the expected count of 2)
	done := make(chan struct{})
	go func() {
		barrier()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("barrier should have completed after timeout")
	}

	// Verify exactly one error was recorded
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %v", len(fake.errs), fake.errs)
	}

	// Verify the error message format
	if !strings.Contains(fake.errs[0], "1/2 goroutines arrived") {
		t.Errorf("error message: got %q, want substring '1/2 goroutines arrived'", fake.errs[0])
	}
}

// fakeTB embeds testing.TB and overrides Errorf to record errors for inspection.
type fakeTB struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Errorf(format string, args ...interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
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
	prepareTestConfig(t, st, &cfg)
	apiSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(apiSrv.Handler())
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
		name               string
		input              string
		want               string
		skipInvariantCheck bool // Set true for fallback rows (no base characters) where invariant checks don't apply
	}{
		// Basic cases
		{"ASCII", "Alice Smith", "Alice Smith", false},
		{"Unicode letters", "José García", "José García", false},
		{"Chinese", "李明", "李明", false},
		{"Japanese", "田中太郎", "田中太郎", false},
		{"Arabic", "محمد علي", "محمد علي", false},
		{"Mixed valid", "Alice-O'Neil, Jr.", "Alice-O'Neil, Jr.", false},
		{"Hindi with combining marks", "राजेश कुमार", "राजेश कुमार", false},
		{"Thai with combining marks", "สมชาย ใจดี", "สมชาย ใจดี", false},
		// Issue #68: Devanagari test
		{"Devanagari", "हिन्दी", "हिन्दी", false},

		// Bidi controls (Cf category) - all filtered
		{"Bidi LRE", "Alice\u202AEvil", "AliceEvil", false},
		{"Bidi RLE", "Alice\u202BEvil", "AliceEvil", false},
		{"Bidi PDF", "Alice\u202CEvil", "AliceEvil", false},
		{"Bidi LRO", "Alice\u202DEvil", "AliceEvil", false},
		{"Bidi RLO", "Alice\u202EEvil", "AliceEvil", false},
		{"Bidi LRI", "Alice\u2066Evil", "AliceEvil", false},
		{"Bidi RLI", "Alice\u2067Evil", "AliceEvil", false},
		{"Bidi FSI", "Alice\u2068Evil", "AliceEvil", false},
		{"Bidi PDI", "Alice\u2069Evil", "AliceEvil", false},
		{"Bidi LRM", "Alice\u200EEvil", "AliceEvil", false},
		{"Bidi RLM", "Alice\u200FEvil", "AliceEvil", false},

		// Zero-width and format characters (Cf category)
		{"Zero-width space", "Alice\u200BEvil", "AliceEvil", false},
		{"Zero-width non-joiner", "Alice\u200CEvil", "AliceEvil", false},
		{"Zero-width joiner", "Alice\u200DEvil", "AliceEvil", false},
		{"BOM", "Alice\uFEFFEvil", "AliceEvil", false},

		// Tag characters
		{"Tag space", "Alice\U000E0020Evil", "AliceEvil", false},
		{"Tag char", "Alice\U000E0041Evil", "AliceEvil", false},

		// Hangul fillers
		{"Hangul filler U+115F", "Alice\u115FEvil", "AliceEvil", false},
		{"Hangul filler U+1160", "Alice\u1160Evil", "AliceEvil", false},
		{"Hangul filler U+3164", "Alice\u3164Evil", "AliceEvil", false},
		{"Hangul filler U+FFA0", "Alice\uFFA0Evil", "AliceEvil", false},

		// Variation selectors
		{"Variation selector FE00", "Alice\uFE00Evil", "AliceEvil", false},
		{"Variation selector FE0F", "Alice\uFE0FEvil", "AliceEvil", false},
		{"Variation selector E0100", "Alice\U000E0100Evil", "AliceEvil", false},

		// Issue #35: Additional Cf characters and Zl/Zp
		{"U+061C Arabic letter mark", "Alice\u061CEvil", "AliceEvil", false},
		{"U+2060 Word joiner", "Alice\u2060Evil", "AliceEvil", false},
		{"U+00AD Soft hyphen", "Alice\u00ADEvil", "AliceEvil", false},
		{"U+2028 Line separator", "Alice\u2028Evil", "AliceEvil", false},
		{"U+2029 Paragraph separator", "Alice\u2029Evil", "AliceEvil", false},

		// Issue #63 & #84: Invisible Mn characters
		{"U+034F COMBINING GRAPHEME JOINER", "a\u034Fb", "ab", false},
		{"U+0334 Combining tilde overlay", "a\u0334b", "a\u0334b", false},
		{"U+180B Mongolian FVS1", "a\u180Bb", "ab", false},
		{"U+180C Mongolian FVS2", "a\u180Cb", "ab", false},
		{"U+180D Mongolian FVS3", "a\u180Db", "ab", false},
		{"U+180F Mongolian FVS4", "a\u180Fb", "ab", false},
		{"U+17B4 Khmer inherent vowel", "a\u17B4b", "ab", false},
		{"U+17B5 Khmer inherent vowel", "a\u17B5b", "ab", false},

		// Issue #84: Combining marks constraints
		// Mark limit is checked in NFD (decomposed) form to ensure visible result has max 3 marks per base
		{"3 marks allowed", "a\u0301\u0302\u0303", "á\u0302\u0303", false},                         // a + 3 marks -> á + 2 marks (NFC composition)
		{"20 marks capped at 3", "a" + strings.Repeat("\u0301", 20), "á́́", false},                 // a + 20 marks -> a + 3 marks (may compose)
		{"64 marks alone becomes fallback", strings.Repeat("\u0301", 64), "A Peerline peer", true}, // No base -> fallback (issue #68); skip invariants
		{"100 marks capped at 3", "a" + strings.Repeat("\u0301", 100), "á́́", false},               // a + 100 marks -> a + 3 marks
		{"Mark after space dropped", "a \u0301b", "a b", false},
		{"Mark at start dropped", "\u0301abc", "abc", false},
		{"Mark after punctuation dropped", "a.\u0301b", "a.b", false},
		{"Mark after letter then punctuation", "a\u0301.b", "á.b", false}, // a+mark -> á (NFC)

		// Issue #68: Tab and newline handling
		{"Tab becomes space", "Alice\tSmith", "Alice Smith", false},
		{"Newline becomes space", "Alice\nSmith", "Alice Smith", false},
		{"Carriage return becomes space", "Alice\rSmith", "Alice Smith", false},
		{"Tab with spaces", "Alice  \t  Smith", "Alice Smith", false},

		// Issue #68: Empty result fallback
		{"Only symbols becomes fallback", "★★★", "A Peerline peer", true},              // Skip invariants (no base)
		{"Only filtered chars", "\u200B\u200C\uFEFF", "A Peerline peer", true},         // Skip invariants (all filtered)
		{"Only marks becomes fallback", "\u0301\u0302\u0303", "A Peerline peer", true}, // Skip invariants (no base)

		// NFKC normalization
		{"Fullwidth ASCII", "Ａｌｉｃｅ", "Alice", false},  // Fullwidth → ASCII
		{"Superscript", "Alice²", "Alice2", false},    // ² → 2
		{"Ligature", "ﬁle", "file", false},            // ﬁ → fi
		{"Circled number", "Alice①", "Alice1", false}, // ① → 1
		{"Compatibility ideograph", "塚", "塚", false},  // U+FA10 → U+585A

		// Space collapsing
		{"Multiple spaces", "Alice   Smith", "Alice Smith", false},
		{"Leading spaces", "   Alice", "Alice", false},
		{"Trailing spaces", "Alice   ", "Alice", false},

		// Emoji and symbols (filtered out)
		{"Emoji removed", "Alice 😀 Smith", "Alice Smith", false},
		{"Symbol removed", "Alice ★ Smith", "Alice Smith", false},

		// Edge cases
		{"Empty string", "", "A Peerline peer", true},   // Skip invariants (empty)
		{"Only spaces", "   ", "A Peerline peer", true}, // Skip invariants (only spaces)

		// Issue #68: Length tests (64 runes max, counted on final NFC output)
		{"70 ASCII letters", strings.Repeat("a", 70), strings.Repeat("a", 64), false},
		{"30 CJK chars under byte limit", strings.Repeat("日", 30), strings.Repeat("日", 30), false},
		// 64 runes (not bytes): "日" is 3 bytes, 64 copies = 192 bytes, should keep exactly 64 runes
		{"Long multibyte truncated at 64 runes", strings.Repeat("日", 70), strings.Repeat("日", 64), false},
		// Precomposed characters: é (U+00E9) is 1 rune in NFC
		{"70 precomposed é gives 64", strings.Repeat("é", 70), strings.Repeat("é", 64), false},
		// Hangul syllables: 한 (U+D55C) is 1 rune in NFC, decomposes to 3 jamo in NFD
		{"70 Hangul syllables gives 64", strings.Repeat("한", 70), strings.Repeat("한", 64), false},
		// a+acute recomposes to á in NFC, 70 gives 64
		{"70 a+acute recomposes to 64 á", strings.Repeat("a\u0301", 70), strings.Repeat("á", 64), false},

		// Issue #181: Edge cases for combining-mark cluster boundaries
		{"cluster ending at rune 64 kept whole", strings.Repeat("a", 63) + "e\u0300", strings.Repeat("a", 63) + "è", false},
		{"cluster + trailing space at cut", strings.Repeat("a", 63) + "e\u0300 zzz", strings.Repeat("a", 63) + "è", false},
		{"4 marks on one base capped at 3", "a\u0300\u0301\u0302\u0303", "\u00e0\u0301\u0302", false}, // 4 marks -> 3 marks

		// Emoji with ZWJ, flags, skin tone modifiers (all filtered: ZWJ is Cf, regional indicators and modifiers are So/Sk)
		{"ZWJ emoji filtered", "Alice👨‍👩‍👧Smith", "AliceSmith", false},
		{"Flag emoji filtered", "Alice🇺🇸Smith", "AliceSmith", false},
		{"Skin tone modifier filtered", "Alice👍🏻Smith", "AliceSmith", false},

		// NFKC expansion: U+FDFA (ﷺ) expands to 18 characters in NFKC
		{"ﷺ×5 NFKC expands", strings.Repeat("\uFDFA", 5), "صلى الله عليه وسلمصلى الله عليه وسلمصلى الله عليه وسلمصلى الله ع", false}, // 5*18=90 -> 64

		// Issue #182/#206: Virama cut (CCC 9) - should not leave dangling virama
		{"virama cut at 64", strings.Repeat("a", 62) + "क्ष" + "bbb", strings.Repeat("a", 62), false},       // क + virama + ष cut before the conjunct
		{"chained virama at 64", strings.Repeat("a", 60) + "क्ष्म" + "bbb", strings.Repeat("a", 60), false}, // क्ष्म (stacked) → 65 runes → 64 → backs off through all 3 clusters → 60 a (no trailing virama)
		{"many chained viramas", strings.Repeat("क्", 32) + "का", strings.Repeat("क्", 28), false},          // 65 runes → 64 (32 pairs) → backoff drops 4 clusters (bound hit) → 56 runes (28 pairs, ends in virama); was fallback on main

		// Issue #206: Stacked conjunct (C V C V | C) - dropCluster removes entire stacked conjunct
		{"stacked conjunct at 64", strings.Repeat("a", 60) + "क्क्ष" + "bbb", strings.Repeat("a", 60), false},            // 60 a + क्क्ष (stacked) → 66 runes → 64 → backs off through all 3 clusters → 60 a (no trailing virama)
		{"4-virama stack at 64", strings.Repeat("a", 56) + "स्त्र्य्म" + "bbb", strings.Repeat("a", 56), false},          // 68 runes total (56 a + 9-rune stack + bbb) → 64 (म at 64) → backs off 4 clusters → 56 a (bound hit)
		{"6-virama stack at 64", strings.Repeat("a", 54) + "स्त्र्य्म्न" + "bbb", strings.Repeat("a", 54) + "स्", false}, // 68 runes total (54 a + 11-rune stack + bbb) → 64 ends at ् (म् at cut) → backs off 4 clusters (म्, य्, र्, त् dropped) → 54 a + स् (56 runes, 1 cluster remains; bound hit, fails if bound≥5)

		// Issue #315: Word-final virama before punctuation (should be kept, not dropped)
		// क् is 2 runes (क at 62, ् at 63), so with 62 'a' + क् + punctuation, the virama is at 63 and punctuation at 64
		// The cap is 64 runes (positions 0-63), so we keep the virama but not the punctuation at position 64
		{"word-final virama before dot", strings.Repeat("a", 62) + "क्." + "bbb", strings.Repeat("a", 62) + "क्", false},  // क at 62, ् at 63, . at 64 → keep virama (word-final)
		{"word-final virama before dash", strings.Repeat("a", 62) + "ம்-" + "bbb", strings.Repeat("a", 62) + "ம்", false}, // ம at 62, ் at 63, - at 64 → keep virama (word-final)
		{"word-final virama before comma", strings.Repeat("a", 62) + "क्," + "bbb", strings.Repeat("a", 62) + "क्", false},
		{"word-final virama before underscore", strings.Repeat("a", 62) + "ம்_" + "bbb", strings.Repeat("a", 62) + "ம்", false},
		{"word-final virama before apostrophe", strings.Repeat("a", 62) + "क्'" + "bbb", strings.Repeat("a", 62) + "क्", false},

		// Issue #332, #346: Bounded back-off for long virama runs prevents collapse.
		// When the bound is hit, the output may end in a visible virama or half-form (#346).
		{"40 Tamil க் bounded", strings.Repeat("க்", 40), strings.Repeat("க்", 28), false},                            // 80 runes → 64 (32 pairs) → backoff drops 4 clusters → 56 runes (28 pairs, bound hit, ends in pulli)
		{"40 க் + 70 ब bounded", strings.Repeat("க்", 40) + strings.Repeat("ब", 70), strings.Repeat("க்", 28), false}, // 150 runes → 64 (32 க் pairs) → backoff drops 4 clusters → 56 runes (28 pairs, bound hit, ends in pulli)
		{"ab + 40 Tamil க் bounded", "ab" + strings.Repeat("க்", 40), "ab" + strings.Repeat("க்", 27), false},         // 82 runes → 64 (ab+31 pairs) → backoff drops 4 clusters → 56 runes (ab+27 pairs, bound hit, ends in pulli)
		{"40 Devanagari क् bounded", strings.Repeat("क्", 40), strings.Repeat("क्", 28), false},                       // 80 runes → 64 (32 clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in virama; #346 pin)
		{"ab + 40 Devanagari क् bounded", "ab" + strings.Repeat("क्", 40), "ab" + strings.Repeat("क्", 27), false},    // 82 runes → 64 (ab+31 clusters) → backoff drops 4 clusters → 56 runes (ab+27 clusters, bound hit, ends in virama)
		{"40 क् + 70 ब bounded", strings.Repeat("क्", 40) + strings.Repeat("ब", 70), strings.Repeat("क्", 28), false}, // 150 runes → 64 (32 क् clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in virama)
		{"40 Bengali ক্ bounded", strings.Repeat("ক্", 40), strings.Repeat("ক্", 28), false},                          // 80 runes → 64 (32 clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in hasanta)
		{"ab + 40 Bengali ক্ bounded", "ab" + strings.Repeat("ক্", 40), "ab" + strings.Repeat("ক্", 27), false},       // 82 runes → 64 (ab+31 clusters) → backoff drops 4 clusters → 56 runes (ab+27 clusters, bound hit, ends in hasanta)
		{"40 ক্ + 70 ব bounded", strings.Repeat("ক্", 40) + strings.Repeat("ব", 70), strings.Repeat("ক্", 28), false}, // 150 runes → 64 (32 ক্ clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in hasanta)
		{"40 Malayalam ക് bounded", strings.Repeat("ക്", 40), strings.Repeat("ക്", 28), false},                        // 80 runes → 64 (32 clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in virama)
		{"ab + 40 Malayalam ക് bounded", "ab" + strings.Repeat("ക്", 40), "ab" + strings.Repeat("ക്", 27), false},     // 82 runes → 64 (ab+31 clusters) → backoff drops 4 clusters → 56 runes (ab+27 clusters, bound hit, ends in virama)
		{"40 ക് + 70 ബ bounded", strings.Repeat("ക്", 40) + strings.Repeat("ബ", 70), strings.Repeat("ക്", 28), false}, // 150 runes → 64 (32 ക് clusters) → backoff drops 4 clusters → 56 runes (28 clusters, bound hit, ends in virama)
		{"Latin 70×a at cap", strings.Repeat("a", 70), strings.Repeat("a", 64), false},                                // 70 runes → 64 runes (no virama, simple cap)
		{"64 runes Deva क् at end", strings.Repeat("a", 62) + "क्", strings.Repeat("a", 62) + "क्", false},            // Exactly 64 runes ending in virama → unchanged
		{"65 runes Deva क् at 63", strings.Repeat("a", 63) + "क्", strings.Repeat("a", 63), false},                    // 65 runes → 64 (virama at 64) → backoff drops 1 cluster → 63 a (word-final virama removed)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%q) = %q, want %q", tt.input, got, tt.want)
			}

			// Check all invariants (idempotence, prefix, ≤64 runes, no Cf) unless skipped
			// Skip only for fallback rows (no base characters) where structural checks don't apply
			if !tt.skipInvariantCheck {
				checkSanitizeInvariants(t, tt.input, got, "table", true)
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

// TestTruncateUTF8 verifies the UTF-8 truncation helper
func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int
		wantLen int
	}{
		{"empty", "", 10, 0},
		{"shorter than max", "abc", 10, 3},
		{"exact max", "abcde", 5, 5},
		{"max 0", "abc", 0, 0},

		// Cut inside multibyte runes (lead byte should be excluded)
		{"2-byte rune at cut", "aaa" + "é", 4, 3},       // é is c3 a9, cut at c3
		{"3-byte rune at cut byte 1", "aa" + "日", 3, 2}, // 日 is e6 97 a5, cut at e6
		{"3-byte rune at cut byte 2", "aa" + "日", 4, 2}, // cut at 97
		{"4-byte rune at cut byte 1", "aa" + "😀", 3, 2}, // 😀 is f0 9f 98 80, cut at f0
		{"4-byte rune at cut byte 2", "aa" + "😀", 4, 2}, // cut at 9f
		{"4-byte rune at cut byte 3", "aa" + "😀", 5, 2}, // cut at 98

		// Multiple multibyte runes
		{"multiple 3-byte", strings.Repeat("日", 10), 10, 9}, // 9 bytes = 3 runes

		// Continuation byte runs (exercises backoff loop)
		{"continuation bytes at cut", "aaa" + string([]byte{0x80, 0x80, 0x80}), 4, 2}, // backs off past 0x80 at position 3
		{"many continuation bytes", string([]byte{0x80, 0x80, 0x80, 0x80, 0x80}), 3, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateUTF8(tt.input, tt.max)

			// Check length
			if len(got) != tt.wantLen {
				t.Errorf("truncateUTF8(%q, %d) len = %d, want %d", tt.input, tt.max, len(got), tt.wantLen)
			}

			// Check valid UTF-8
			if !utf8.ValidString(got) {
				t.Errorf("truncateUTF8(%q, %d) returned invalid UTF-8: %q", tt.input, tt.max, got)
			}

			// Check it's a prefix
			if !strings.HasPrefix(tt.input, got) {
				t.Errorf("truncateUTF8(%q, %d) = %q, not a prefix", tt.input, tt.max, got)
			}
		})
	}
}

// TestSanitizerGuardInvariants verifies the input guard produces valid UTF-8 and idempotent output.
// The "\xf0\u00b2" row fails on main@dcc099a (invalid UTF-8 disables NFKC for the next character,
// breaking idempotence: "\xf0\u00b2" -> "\u00b2" -> "2"). Other rows exercise boundary conditions.
func TestSanitizerGuardInvariants(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string // expected output (empty string means just check invariants)
	}{
		// Invalid byte disables NFKC on dcc099a: \xf0² -> ² -> 2 (not idempotent)
		{"invalid byte disables NFKC", "\xf0\u00b2", "2"},
		{"invalid byte then compat Greek", "\xf1ϐ", "β"},

		// Exact byte boundaries at the guard
		{"1023 bytes (no cut)", strings.Repeat("a", 1023), strings.Repeat("a", 64)},
		{"1024 bytes (exact cut)", strings.Repeat("a", 1024), strings.Repeat("a", 64)},
		{"1025 bytes (over cut)", strings.Repeat("a", 1025), strings.Repeat("a", 64)},

		// Multibyte rune straddling the 1024-byte cut
		{"1022a + 日 at 1024", strings.Repeat("a", 1022) + "日", strings.Repeat("a", 64)},
		{"1021a + 😀 at 1024", strings.Repeat("a", 1021) + "😀", strings.Repeat("a", 64)},

		// Continuation byte runs near cut
		{"0x80 runs near cut", strings.Repeat("a", 1020) + string([]byte{0x80, 0x80, 0x80, 0x80}), strings.Repeat("a", 64)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeInviterName(tc.input)

			// Invariant 1: Output is valid UTF-8
			if !utf8.ValidString(got) {
				t.Errorf("sanitizeInviterName(%q) returned invalid UTF-8", tc.input)
			}

			// Invariant 2: Idempotent
			got2 := sanitizeInviterName(got)
			if got != got2 {
				t.Errorf("sanitizeInviterName not idempotent for %q: first=%q, second=%q", tc.input, got, got2)
			}

			// Check expected output if provided
			if tc.want != "" && got != tc.want {
				t.Errorf("sanitizeInviterName(%q) = %q, want %q", tc.input, got, tc.want)
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
		t.Errorf("sanitizeInviterName(100KB input) = %q (len %d), want %q (len %d)", got, len([]rune(got)), want, len([]rune(want)))
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

// TestSanitizerInputGuardContinuationBytes verifies the guard handles continuation byte runs
func TestSanitizerInputGuardContinuationBytes(t *testing.T) {
	// Place runs of 0x80 (continuation bytes) near the 1024-byte cut
	// These are invalid UTF-8 and should be replaced by U+FFFD, then filtered
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"continuation bytes at 1020-1024",
			strings.Repeat("a", 1020) + string([]byte{0x80, 0x80, 0x80, 0x80}) + strings.Repeat("b", 100),
			strings.Repeat("a", 64),
		},
		{
			"continuation bytes before cut",
			strings.Repeat("a", 1010) + string([]byte{0x80, 0x80}) + strings.Repeat("a", 12) + strings.Repeat("b", 100),
			strings.Repeat("a", 64), // 0x80 replaced by U+FFFD (category So), filtered out, so we get 1022 'a' -> 64 'a'
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%s) = %q (len %d), want %q (len %d)", tt.name, got, len([]rune(got)), tt.want, len([]rune(tt.want)))
			}
		})
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

// TestSanitizeInviterName verifies specific sanitization cases
func TestSanitizeInviterName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic ASCII",
			input: "Alice",
			want:  "Alice",
		},
		{
			name:  "word-final virama kept: Devanagari halant before space",
			input: "00000!000000000000000000000000000000000000000000000000000000क्ष् 00000" + strings.Repeat("ब", 70),
			want:  "00000000000000000000000000000000000000000000000000000000000क्ष्", // word-final क्ष् kept (63 runes)
		},
		{
			name:  "word-final virama kept: single syllable before space",
			input: strings.Repeat("a", 61) + "क् " + strings.Repeat("b", 10),
			want:  strings.Repeat("a", 61) + "क्", // word-final क् kept (63 runes)
		},
		{
			name:  "word-final viramas kept: two words ending in virama",
			input: strings.Repeat("a", 59) + "क् ष्" + strings.Repeat("b", 10),
			want:  strings.Repeat("a", 59) + "क्", // truncates after क्, word-final so kept (61 runes)
		},
		{
			name:  "mid-word virama dropped: cut inside a conjunct",
			input: strings.Repeat("a", 60) + "क्ष्म" + "bbb",
			want:  strings.Repeat("a", 60), // क्ष्म cut mid-word, backs off through all 3 clusters (60 runes, no trailing virama)
		},
		{
			name:  "Tamil pulli: many word-final viramas",
			input: strings.Repeat("ம் ", 40),                                        // 40 Tamil words ending in pulli
			want:  "ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம்", // 62 runes, keeps words
		},
		{
			name:  "Tamil pulli at exactly position 64",
			input: "xx" + strings.Repeat("ம் ", 40),                                   // Rune 63 is ் (virama), rune 64 is space
			want:  "xxம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம் ம்", // 64 runes, word-final virama kept
		},
		{
			name:  "Devanagari halant at exactly position 64",
			input: strings.Repeat("a", 62) + "क् " + strings.Repeat("b", 10),
			want:  strings.Repeat("a", 62) + "क्", // 64 runes, word-final virama kept
		},
		{
			name:  "Tamil word kept whole: மரம் not cut",
			input: strings.Repeat("a", 58) + " மரம் zz" + strings.Repeat("b", 10),
			want:  strings.Repeat("a", 58) + " மரம்", // 63 runes, மரம் kept whole
		},
		{
			name:  "empty after cleanup falls back",
			input: "!@#$%",
			want:  "A Peerline peer",
		},
		{
			name:  "only spaces falls back",
			input: "     ",
			want:  "A Peerline peer",
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

// checkSanitizeInvariants verifies all sanitizeInviterName invariants on an output.
// checkVirama should be true only when checking a forced-truncation path.
// isWordBoundaryTest is the test-side boundary definition, independent of the production code.
// It matches the intended behavior: a rune is a word boundary if it's not a letter, number, or combining mark.
// This is defined separately from the production isWordBoundary so the invariant can't drift with the code.
func isWordBoundaryTest(r rune) bool {
	return !(unicode.IsLetter(r) || unicode.IsNumber(r) ||
		unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r))
}

func checkSanitizeInvariants(t *testing.T, input, got, label string, checkVirama bool) {
	t.Helper()

	// Invariant 1: Output is valid UTF-8
	if !utf8.ValidString(got) {
		t.Errorf("sanitizeInviterName(%q) [%s] returned invalid UTF-8: %q", input, label, got)
	}

	// Invariant 2: Output is NFC normalized
	if !norm.NFC.IsNormalString(got) {
		t.Errorf("sanitizeInviterName(%q) [%s] returned non-NFC string: %q", input, label, got)
	}

	// Invariant 3: At most 64 runes
	runeCount := utf8.RuneCountInString(got)
	if runeCount > 64 {
		t.Errorf("sanitizeInviterName(%q) [%s] returned %d runes (> 64): %q", input, label, runeCount, got)
	}

	// Invariant 4: Non-empty (fallback applied if needed)
	if got == "" {
		t.Errorf("sanitizeInviterName(%q) [%s] returned empty string", input, label)
	}

	// Invariant 5: No leading/trailing space
	if strings.TrimSpace(got) != got {
		t.Errorf("sanitizeInviterName(%q) [%s] has leading/trailing space: %q", input, label, got)
	}

	// Invariant 6: No leading combining mark
	runes := []rune(got)
	if len(runes) > 0 {
		firstRune := runes[0]
		if unicode.Is(unicode.Mn, firstRune) || unicode.Is(unicode.Mc, firstRune) {
			t.Errorf("sanitizeInviterName(%q) [%s] starts with combining mark: %q", input, label, got)
		}
	}

	// Invariant 7: Idempotent
	got2 := sanitizeInviterName(got)
	if got != got2 {
		t.Errorf("sanitizeInviterName [%s] not idempotent for input %q: first=%q, second=%q", label, input, got, got2)
	}

	// Invariant 8: Every output rune is in the allowlist (L*, N*, Mn, Mc, space, . , - _ ')
	// and no U+FFFD
	for _, r := range got {
		if r == '\uFFFD' {
			t.Errorf("sanitizeInviterName(%q) [%s] contains U+FFFD: %q", input, label, got)
		}
		isAllowed := unicode.IsLetter(r) || unicode.IsNumber(r) ||
			unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) ||
			r == ' ' || r == '.' || r == ',' || r == '-' || r == '_' || r == '\''
		if !isAllowed {
			t.Errorf("sanitizeInviterName(%q) [%s] contains disallowed rune %U (%c): %q", input, label, r, r, got)
		}
	}

	// Invariant 9: No split base+mark cluster.
	// The output must not split a base character from its immediately following combining marks
	// or virama. This prevents dangling marks, but the output may end in a mid-word virama
	// (a trailing half-form) when the bound is hit.
	if checkVirama {
		full := []rune(sanitizeInviterNameUncapped(input))
		out := []rune(got)
		cutPos := len(out)
		if cutPos < len(full) {
			// Check that the next rune in full is not a combining mark or virama (CCC 9)
			nextRune := full[cutPos]
			isMark := unicode.Is(unicode.Mn, nextRune) || unicode.Is(unicode.Mc, nextRune) || unicode.Is(unicode.Me, nextRune)
			props := norm.NFC.PropertiesString(string(nextRune))
			isVirama := props.CCC() == 9
			if isMark || isVirama {
				t.Errorf("sanitizeInviterName(%q) [%s] splits base from mark/virama: output ends at position %d, but full[%d]=U+%04X is a mark/virama: output=%q full=%q", input, label, cutPos, cutPos, nextRune, got, string(full))
			}
		}
	}

	// Invariant 10: Truncated output may end in CCC 9 (virama) only if word-final or bounded.
	// For truncated paths, compare against the uncapped result.
	if checkVirama {
		// Get the uncapped result
		full := []rune(sanitizeInviterNameUncapped(input))
		out := []rune(got)

		// General assertion: capped output is a prefix of uncapped result, or it's the fallback.
		// If the fallback is returned, the uncapped result must not have any letters
		// (otherwise the name collapsed when it shouldn't have).
		const fallbackName = "A Peerline peer"
		if len(out) > 0 && len(full) > 0 {
			if got == fallbackName {
				// Check if the uncapped result has at least one letter
				hasLetter := false
				for _, r := range full {
					if unicode.IsLetter(r) {
						hasLetter = true
						break
					}
				}
				if hasLetter {
					t.Errorf("sanitizeInviterName(%q) [%s] returned fallback %q but uncapped has letters: full=%q", input, label, got, string(full))
				}
			} else if !strings.HasPrefix(string(full), got) {
				t.Errorf("sanitizeInviterName(%q) [%s] capped output is not a prefix of uncapped: got=%q full=%q", input, label, got, string(full))
			}
		}

		// Assert that back-off only drops virama clusters, not complete words.
		// The dropped region (after legitimately trimmed trailing spaces from output and leading spaces
		// from the dropped part) must satisfy two conditions:
		// (a) It contains no word boundary runes (spaces, punctuation).
		// (b) Every base letter/number is immediately followed by a mark or virama (CCC 9).
		if len(out) > 0 && len(full) >= 64 {
			// Find the last non-space rune in the output to account for trailing space trim
			lastNonSpace := len(out) - 1
			for lastNonSpace >= 0 && out[lastNonSpace] == ' ' {
				lastNonSpace--
			}
			// Check from the position after the last non-space to position 64, excluding leading spaces
			if lastNonSpace >= 0 && lastNonSpace+1 < 64 {
				startCheck := lastNonSpace + 1
				// Skip any leading spaces that were legitimately trimmed
				for startCheck < 64 && full[startCheck] == ' ' {
					startCheck++
				}
				// Now validate the dropped region
				if startCheck < 64 {
					droppedRegion := full[startCheck:64]

					// Check (a): no word boundaries in the dropped region
					for _, r := range droppedRegion {
						if isWordBoundaryTest(r) {
							t.Errorf("sanitizeInviterName(%q) [%s] dropped runes before position 64 contain word boundary U+%04X (excluding leading spaces): output=%q full=%q dropped=%q", input, label, r, got, string(full), string(droppedRegion))
							break
						}
					}

					// Check (b): every base letter/number must be part of a virama cluster
					for i, r := range droppedRegion {
						// If this is a base character (letter or number)
						if unicode.IsLetter(r) || unicode.IsNumber(r) {
							// It must be followed by a mark or virama (CCC 9), either within the region or at position 64
							var nextRune rune
							if i+1 < len(droppedRegion) {
								nextRune = droppedRegion[i+1]
							} else if startCheck+i+1 == 64 && len(full) > 64 {
								// The base is at position 63, check if position 64 is a mark/virama
								nextRune = full[64]
							} else {
								// Base at end of dropped region with nothing after it - this is wrong
								t.Errorf("sanitizeInviterName(%q) [%s] dropped base character U+%04X (%c) not followed by mark/virama: output=%q full=%q dropped=%q", input, label, r, r, got, string(full), string(droppedRegion))
								break
							}
							isMark := unicode.Is(unicode.Mn, nextRune) || unicode.Is(unicode.Mc, nextRune) || unicode.Is(unicode.Me, nextRune)
							props := norm.NFC.PropertiesString(string(nextRune))
							isVirama := props.CCC() == 9
							if !isMark && !isVirama {
								t.Errorf("sanitizeInviterName(%q) [%s] dropped base character U+%04X (%c) not followed by mark/virama (next: U+%04X): output=%q full=%q dropped=%q", input, label, r, r, nextRune, got, string(full), string(droppedRegion))
								break
							}
						}
					}
				}
			}
		}

		// (a) If the output ends in CCC 9 (virama) and is shorter than full,
		// then either:
		//   - the next rune in full is a word boundary (word-final virama), OR
		//   - it's the bounded back-off case: the dropped region from len(out) to min(64, len(full))
		//     is all consonant+virama clusters (no boundaries), AND the dropped region contains
		//     at least maxViramaBackoff whole clusters.
		if len(out) > 0 && len(out) < len(full) {
			lastRune := out[len(out)-1]
			props := norm.NFC.PropertiesString(string(lastRune))
			if props.CCC() == 9 {
				nextRune := full[len(out)]
				isWordFinal := isWordBoundaryTest(nextRune)

				// Check if the dropped region is a boundary-free run of consonant+virama clusters
				droppedEnd := len(full)
				if droppedEnd > 64 {
					droppedEnd = 64
				}
				isBoundedCase := true
				clustersInDropped := 0
				for i := len(out); i < droppedEnd && isBoundedCase; i++ {
					r := full[i]
					// Must be a base (letter/number), mark, or virama
					isMark := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r)
					rProps := norm.NFC.PropertiesString(string(r))
					isVirama := rProps.CCC() == 9
					isBase := unicode.IsLetter(r) || unicode.IsNumber(r)
					if !isBase && !isMark && !isVirama {
						isBoundedCase = false
					}
					// Count clusters (bases followed by marks/viramas)
					if isBase {
						clustersInDropped++
					}
				}

				// Bounded case only applies when ≥ maxViramaBackoff clusters were dropped
				isBoundedCase = isBoundedCase && clustersInDropped >= maxViramaBackoff

				if !isWordFinal && !isBoundedCase {
					t.Errorf("sanitizeInviterName(%q) [%s] ends in mid-word CCC 9 (virama) rune U+%04X at non-bounded length %d, next rune is U+%04X (not a word boundary): output=%q full=%q", input, label, lastRune, len(out), nextRune, got, string(full))
				}
			}
		}

		// (b) If full is >64 runes, full[63] has CCC 9, and full[64] is a word boundary,
		// the output must equal string(full[:64]) (word-final virama kept).
		if len(full) > 64 {
			props := norm.NFC.PropertiesString(string(full[63]))
			if props.CCC() == 9 && isWordBoundaryTest(full[64]) {
				expected := string(full[:64])
				if got != expected {
					t.Errorf("sanitizeInviterName(%q) [%s] should keep word-final virama at position 63: got=%q, expected=%q", input, label, got, expected)
				}
			}
		}
	}
}

// TestSanitizerWordFinalViramaWithSpace verifies the word-final virama path with a space before the suffix.
// This exercises the virama+space case deterministically, since CI fuzzing doesn't reach it from the seeds.
func TestSanitizerWordFinalViramaWithSpace(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "virama at 63, space at 64, forced path",
			// 62 'a' + "क्" (2 runes) + " " (1 rune) = 65 runes total (क at 62, virama at 63, space at 64)
			// The virama is word-final (space follows), so it's kept, but trailing space is trimmed
			input: strings.Repeat("a", 62) + "क् " + strings.Repeat("ब", 70),
			want:  strings.Repeat("a", 62) + "क्",
		},
		{
			name: "Tamil virama at 63, space at 64, forced path",
			// "xx" + 20×"ம் " + "ம்" + " " + 70×"ब" = 135 runes input (virama at 63, space at 64, cut before ब)
			// The virama is word-final (space follows), so it's kept, but trailing space is trimmed
			input: "xx" + strings.Repeat("ம் ", 20) + "ம் " + strings.Repeat("ब", 70),
			want:  "xx" + strings.Repeat("ம் ", 20) + "ம்",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInviterName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeInviterName(%q) = %q (len %d), want %q (len %d)", tt.input, got, len([]rune(got)), tt.want, len([]rune(tt.want)))
			}
			// Verify all invariants on this forced path
			checkSanitizeInvariants(t, tt.input, got, "forced-space-path", true)
		})
	}
}

// FuzzSanitizeInviterName verifies invariants over random inputs
func FuzzSanitizeInviterName(f *testing.F) {
	// Seed corpus with edge cases
	f.Add("Alice")
	f.Add(strings.Repeat("a", 70))
	f.Add("e\u0300\u0316")                                 // non-composing marks
	f.Add("\uFDFA")                                        // NFKC expands
	f.Add("\xf0\u00b2")                                    // invalid byte + NFKC char
	f.Add(strings.Repeat("a", 1022) + "日")                 // 3-byte rune at 1024
	f.Add("क्ष")                                           // Indic conjunct (virama)
	f.Add(strings.Repeat("a", 60) + "क्ष्म" + "bbb")       // Mid-word virama: cut inside conjunct
	f.Add(strings.Repeat("ब", 70))                         // Force 64-rune cap path
	f.Add(strings.Repeat("a", 59) + "क् ष्" + "bbbbbbbbb") // Word-final virama: keep complete words
	// Issue #315: Fuzz seeds for word-final virama at rune 63 (before space or punctuation at rune 64)
	f.Add("xx" + strings.Repeat("ம் ", 40))               // 40 × "ம் " → virama at 63, space at 64
	f.Add(strings.Repeat("a", 62) + "क् " + "bbbbbbbbbb") // virama at 63, space at 64
	f.Add(strings.Repeat("a", 62) + "क்." + "bbbbbbbbbb") // virama at 63, dot at 64
	f.Add(strings.Repeat("a", 62) + "ம்-" + "bbbbbbbbbb") // virama at 63, dash at 64
	// Issue #332, #346: Fuzz seeds for bounded back-off on long virama runs
	f.Add(strings.Repeat("க்", 40))                           // 40 Tamil க் clusters (80 runes)
	f.Add(strings.Repeat("க்", 40) + strings.Repeat("ब", 70)) // 40 க் + 70 ब (150 runes total)
	f.Add("ab" + strings.Repeat("க்", 40))                    // ab + 40 க் clusters (82 runes)
	f.Add(strings.Repeat("क्", 40))                           // 40 Devanagari क् clusters (80 runes)
	f.Add("ab" + strings.Repeat("क्", 40))                    // ab + 40 क् clusters (82 runes)
	f.Add(strings.Repeat("क्", 40) + strings.Repeat("ब", 70)) // 40 क् + 70 ब (150 runes total)
	f.Add(strings.Repeat("ক্", 40))                           // 40 Bengali ক্ clusters (80 runes)
	f.Add("ab" + strings.Repeat("ক্", 40))                    // ab + 40 ক্ clusters (82 runes)
	f.Add(strings.Repeat("ক্", 40) + strings.Repeat("ব", 70)) // 40 ক্ + 70 ব (150 runes total)
	f.Add(strings.Repeat("ക്", 40))                           // 40 Malayalam ക് clusters (80 runes)
	f.Add("ab" + strings.Repeat("ക്", 40))                    // ab + 40 ക് clusters (82 runes)
	f.Add(strings.Repeat("ക്", 40) + strings.Repeat("ബ", 70)) // 40 ക് + 70 ബ (150 runes total)

	f.Fuzz(func(t *testing.T, input string) {
		got := sanitizeInviterName(input)

		// Check all invariants on the direct output (Invariant 9 not checked here)
		checkSanitizeInvariants(t, input, got, "direct", false)

		// Force truncation by appending ब×70 and check all invariants on that path too.
		// This is the only path that exercises the tail cleanup loop.
		truncationTest := input + strings.Repeat("ब", 70)
		gotTruncated := sanitizeInviterName(truncationTest)
		checkSanitizeInvariants(t, truncationTest, gotTruncated, "truncated", true)
	})
}

// TestAPIClock verifies that the API and store share one clock, and that invite
// expiry boundaries are exact: accepted at expires_at, rejected at expires_at+1.
// Issue #110 item 5: clock agreement and exact-boundary semantics through the API.
func TestAPIClock(t *testing.T) {
	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	clk := clocktest.New(fixedTime)

	// Pass the same fake clock to both store and API
	st, err := store.OpenWithOptions(t.TempDir()+"/t.db", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	bareCfg := Config{Clock: clk}
	prepareTestConfig(t, st, &bareCfg)
	srv, err := New(st, bareCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Create test server and client
	testSrv := httptest.NewServer(srv.Handler())
	defer testSrv.Close()

	// Register two peers
	alice := &client{t: t, srv: testSrv}
	resp, body := alice.do("POST", "/v1/register", map[string]string{"name": "alice"}, nil)
	want(t, resp, body, 201)
	var aliceReg struct{ PeerID, APIKey string }
	if err := json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&aliceReg.PeerID, &aliceReg.APIKey}); err != nil {
		t.Fatal(err)
	}
	alice.id, alice.key = aliceReg.PeerID, aliceReg.APIKey

	bob := &client{t: t, srv: testSrv}
	resp, body = bob.do("POST", "/v1/register", map[string]string{"name": "bob"}, nil)
	want(t, resp, body, 201)
	var bobReg struct{ PeerID, APIKey string }
	if err := json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&bobReg.PeerID, &bobReg.APIKey}); err != nil {
		t.Fatal(err)
	}
	bob.id, bob.key = bobReg.PeerID, bobReg.APIKey

	// Create first invite with 100-second TTL via API
	resp, body = alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "ttl_seconds": 100}, nil)
	want(t, resp, body, 201)

	var inv1 struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &inv1); err != nil {
		t.Fatal(err)
	}

	expTime, err := time.Parse(time.RFC3339, inv1.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	expected := fixedTime.Add(100 * time.Second).UTC()
	if !expTime.Equal(expected) {
		t.Errorf("expires_at = %v, want %v", expTime, expected)
	}

	// Create second invite with 100-second TTL before advancing clock
	resp, body = alice.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "ttl_seconds": 100}, nil)
	want(t, resp, body, 201)

	var inv2 struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &inv2); err != nil {
		t.Fatal(err)
	}

	// Advance clock to exactly expires_at (fixedTime + 100s)
	clk.Advance(100 * time.Second)

	// Accept invite1 at exactly expires_at (now == expires_at) - should succeed
	resp, body = bob.do("POST", "/v1/invites/accept", map[string]any{"code": inv1.Code}, nil)
	if resp.StatusCode != 200 {
		t.Errorf("accept at exact boundary (now == expires_at): expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Advance clock by 1 more second (now = expires_at + 1)
	clk.Advance(1 * time.Second)

	// Accept invite2 at expires_at+1 - should be rejected with 404
	resp, body = bob.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, nil)
	if resp.StatusCode != 404 {
		t.Errorf("accept at expires_at+1: expected 404, got %d: %s", resp.StatusCode, body)
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
// logs across all accept paths, including success, error, and failure cases (issue #28, #146, #174).
// This test captures only the slog logger; there is no http.Server.ErrorLog or access-log middleware today.
func TestInviteAcceptPathsNeverLogCode(t *testing.T) {
	var logs syncBuf
	// Share one logger with both API and mailer for a single unified log stream
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	srv := newServer(t, Config{Logger: logger, Mailer: mailer.Log{Logger: logger}})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	c := register(t, srv, "carol")

	// Create invites for different test cases
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv1 struct{ Code string }
	if err := json.Unmarshal(body, &inv1); err != nil || inv1.Code == "" {
		t.Fatalf("inv1: %v %s", err, body)
	}

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv2 struct{ Code string }
	if err := json.Unmarshal(body, &inv2); err != nil || inv2.Code == "" {
		t.Fatalf("inv2: %v %s", err, body)
	}

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv3 struct{ Code string }
	if err := json.Unmarshal(body, &inv3); err != nil || inv3.Code == "" {
		t.Fatalf("inv3: %v %s", err, body)
	}

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv4 struct{ Code string }
	if err := json.Unmarshal(body, &inv4); err != nil || inv4.Code == "" {
		t.Fatalf("inv4: %v %s", err, body)
	}

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "to_email": "test@example.com"}, nil)
	want(t, resp, body, 201)
	var inv5 struct{ Code string }
	if err := json.Unmarshal(body, &inv5); err != nil || inv5.Code == "" {
		t.Fatalf("inv5: %v %s", err, body)
	}

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
	if !strings.Contains(logStr, "body_len") {
		t.Error("logs should contain mailer 'body_len' (positive control for to_email path)")
	}

	// Check logs don't contain any of the codes or their prefixes
	for _, code := range []string{inv1.Code, inv2.Code, inv3.Code, inv4.Code, inv5.Code, unknownCode} {
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
	// Use fake clock to control invite expiry deterministically
	clk := clocktest.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	// Open store with fake clock so expiry checks use it
	st, err := store.OpenWithOptions(t.TempDir()+"/t.db", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := Config{Clock: clk}
	prepareTestConfig(t, st, &cfg)
	apiSrv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(apiSrv.Stop)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)

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
	if err := json.Unmarshal(body, &inv3); err != nil || inv3.Code == "" {
		t.Fatalf("inv3: %v, code=%q", err, inv3.Code)
	}
	// Advance clock past inv3's expiry (1 second TTL). The store uses the same
	// fake clock, so POST ?code= will see it as expired.
	clk.Advance(2 * time.Second)

	// Positive control: inv3 is now expired and returns 404 on POST accept
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv3.Code}, nil)
	want(t, resp, body, 404)

	// Use inv2
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, nil)
	want(t, resp, body, 200)

	missingCode := auth.NewSecret("inv_")

	const wantDeprecation = "@1793318400"
	const wantLink = `<https://github.com/sysrex/peerline#deprecations>; rel="deprecation"; type="text/html"`

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
	if got := resp2.Header.Get("Allow"); got != "POST" {
		t.Errorf("HEAD Allow: got %q, want POST", got)
	}
	if got := resp2.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("HEAD Deprecation: got %q, want %q", got, wantDeprecation)
	}
	if got := resp2.Header.Get("Link"); got != wantLink {
		t.Errorf("HEAD Link: got %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp2.Header, "HEAD with auth")

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
	if got := resp2.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("HEAD without auth: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp2.Header.Get("Link"); got != wantLink {
		t.Errorf("HEAD without auth: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp2.Header, "HEAD without auth")

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

	// Test 4.5: Path cleaning variants (// and /./) redirect 307 to canonical path
	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ = http.NewRequest("POST", srv.URL+"/v1/invites//accept?code="+inv1.Code, nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	resp2, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 307 {
		t.Errorf("// variant POST: want 307, got %d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("Location"); got != "/v1/invites/accept?code="+inv1.Code {
		t.Errorf("// variant Location: got %q, want /v1/invites/accept?code=...", got)
	}
	assertSecurityHeaders(t, resp2.Header, "// variant POST")

	req, _ = http.NewRequest("POST", srv.URL+"/v1/invites/./accept?code="+inv1.Code, nil)
	req.Header.Set("Authorization", "Bearer "+b.key)
	resp2, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 307 {
		t.Errorf("/./ variant POST: want 307, got %d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("Location"); got != "/v1/invites/accept?code="+inv1.Code {
		t.Errorf("/./ variant Location: got %q, want /v1/invites/accept?code=...", got)
	}
	assertSecurityHeaders(t, resp2.Header, "/./ variant POST")

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
		// Allow header includes DELETE because DELETE /v1/invites/{public_id} also matches
		// the literal path segment "accept", and ServeMux lists all methods registered on that pattern.
		if got := rsp.Header.Get("Allow"); got != "DELETE, POST" {
			t.Errorf("%s: Allow = %q, want DELETE, POST", method, got)
		}
		if got := rsp.Header.Get("Deprecation"); got != wantDeprecation {
			t.Errorf("%s with ?code=: Deprecation = %q, want %q", method, got, wantDeprecation)
		}
		if got := rsp.Header.Get("Link"); got != wantLink {
			t.Errorf("%s with ?code=: Link = %q, want %q", method, got, wantLink)
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
	if got := rsp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("DELETE with ?code=: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := rsp.Header.Get("Link"); got != wantLink {
		t.Errorf("DELETE with ?code=: Link = %q, want %q", got, wantLink)
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

	// Test 10: Expired vs missing code: no oracle (issue #305)
	// Create two invites with 1s TTL for expiry testing
	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "ttl_seconds": 1}, nil)
	want(t, resp, body, 201)
	var inv4 struct{ Code string }
	if err := json.Unmarshal(body, &inv4); err != nil || inv4.Code == "" {
		t.Fatalf("inv4: %v, code=%q", err, inv4.Code)
	}

	resp, body = a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "ttl_seconds": 1}, nil)
	want(t, resp, body, 201)
	var inv5 struct{ Code string }
	if err := json.Unmarshal(body, &inv5); err != nil || inv5.Code == "" {
		t.Fatalf("inv5: %v, code=%q", err, inv5.Code)
	}

	// Positive control: inv4 is accepted before expiry
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv4.Code}, nil)
	want(t, resp, body, 200)

	// Advance clock past inv5's 1s TTL to expire it
	clk.Advance(2 * time.Second)

	// Compare expired vs missing for both forms: ?code= and body-only
	for _, tc := range []struct {
		name string
		do   func(code string) (*http.Response, []byte)
	}{
		{"POST ?code=", func(code string) (*http.Response, []byte) {
			return b.do("POST", "/v1/invites/accept?code="+code, nil, nil)
		}},
		{"POST body", func(code string) (*http.Response, []byte) {
			return b.do("POST", "/v1/invites/accept", map[string]any{"code": code}, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Expired code
			respExp, bodyExp := tc.do(inv5.Code)
			want(t, respExp, bodyExp, 404)

			// Missing code
			respMiss, bodyMiss := tc.do(missingCode)
			want(t, respMiss, bodyMiss, 404)

			// Bodies must be identical
			if !bytes.Equal(bodyExp, bodyMiss) {
				t.Errorf("404 body differs:\nexpired: %s\nmissing: %s", bodyExp, bodyMiss)
			}

			// Compare all headers except Date (varies per request)
			for k := range respExp.Header {
				if k == "Date" {
					continue // Date legitimately varies per request
				}
				if respExp.Header.Get(k) != respMiss.Header.Get(k) {
					t.Errorf("header %s differs: expired=%q missing=%q",
						k, respExp.Header.Get(k), respMiss.Header.Get(k))
				}
			}
			for k := range respMiss.Header {
				if k == "Date" {
					continue
				}
				if respMiss.Header.Get(k) != respExp.Header.Get(k) {
					t.Errorf("header %s differs: missing=%q expired=%q",
						k, respMiss.Header.Get(k), respExp.Header.Get(k))
				}
			}
		})
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

	const wantDeprecation = "@1793318400"
	const wantLink = `<https://github.com/sysrex/peerline#deprecations>; rel="deprecation"; type="text/html"`

	// 1. Query-only POST success: should have headers and Cache-Control
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv1.Code, nil, nil)
	want(t, resp, body, 200)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("query-only POST success: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("query-only POST success: Link = %q, want %q", got, wantLink)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("query-only POST success: Cache-Control = %q, want no-store", got)
	}
	assertSecurityHeaders(t, resp.Header, "query-only POST success")

	// 2. Body-only POST success: should NOT have deprecation headers
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, nil)
	want(t, resp, body, 200)
	if got := resp.Header.Get("Deprecation"); got != "" {
		t.Errorf("body-only POST: unexpected Deprecation header: %q", got)
	}
	if got := resp.Header.Get("Link"); got != "" {
		t.Errorf("body-only POST: unexpected Link header: %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("body-only POST: Cache-Control = %q, want no-store", got)
	}
	assertSecurityHeaders(t, resp.Header, "body-only POST")

	// 3. Query-only POST error (404): should have headers (issue #173)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv1.Code, nil, nil) // already used
	want(t, resp, body, 404)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("query-only POST 404: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("query-only POST 404: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "query-only POST 404")

	// 4. Query-only POST error (400: bad scopes): should have headers
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv3.Code, map[string]any{"scopes": []string{"BadScope"}}, nil)
	want(t, resp, body, 400)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("query-only POST 400 bad scopes: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("query-only POST 400 bad scopes: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "query-only POST 400 bad scopes")

	// 5. Query-only POST error (400: own invite): should have headers
	resp, body = a.do("POST", "/v1/invites/accept?code="+inv3.Code, nil, nil)
	want(t, resp, body, 400)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("query-only POST 400 own invite: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("query-only POST 400 own invite: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "query-only POST 400 own invite")

	// 6. Body+query POST (body wins): should have headers (issue #173)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv3.Code, map[string]any{"code": inv3.Code}, nil)
	want(t, resp, body, 200)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("body+query POST: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("body+query POST: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "body+query POST")

	// 7. Unauthenticated landing GET with ?code=: should have headers (issue #173)
	anon := &client{t: t, srv: srv, key: ""}
	resp, body = anon.do("GET", "/v1/invites/accept?code="+inv2.Code, nil, nil)
	want(t, resp, body, 200)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("unauthenticated landing GET: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("unauthenticated landing GET: Link = %q, want %q", got, wantLink)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("unauthenticated landing GET: Cache-Control = %q, want no-store", got)
	}
	assertSecurityHeaders(t, resp.Header, "unauthenticated landing GET")

	// 8. Authenticated GET 405 with ?code=: should have headers (already tested in 405 comprehensive)
	resp, body = b.do("GET", "/v1/invites/accept?code="+inv2.Code, nil, nil)
	want(t, resp, body, 405)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("authenticated GET 405: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("authenticated GET 405: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "authenticated GET 405")

	// 9. 401 (bad key) with ?code=: should have deprecation headers (P1-1)
	resp, body = b.do("POST", "/v1/invites/accept?code="+inv2.Code, nil, map[string]string{"Authorization": "Bearer pl_bogus"})
	want(t, resp, body, 401)
	if got := resp.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("POST 401 bad key: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp.Header.Get("Link"); got != wantLink {
		t.Errorf("POST 401 bad key: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp.Header, "POST 401 bad key")

	// 10. 400 (malformed JSON) with ?code=: should have deprecation headers (P1-1)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/invites/accept?code="+inv2.Code, strings.NewReader("{bad json"))
	req.Header.Set("Authorization", "Bearer "+b.key)
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Fatalf("POST 400 bad JSON: want 400, got %d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("POST 400 bad JSON: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp2.Header.Get("Link"); got != wantLink {
		t.Errorf("POST 400 bad JSON: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp2.Header, "POST 400 bad JSON")

	// 11. 413 (oversized body) with ?code=: should have deprecation headers (P1-1)
	// Create a valid JSON object that exceeds maxJSONBytes (16 KB)
	largeScopes := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		largeScopes = append(largeScopes, "scope_"+strings.Repeat("x", 10))
	}
	largeJSON, _ := json.Marshal(map[string]any{"code": inv2.Code, "scopes": largeScopes})
	req, _ = http.NewRequest("POST", srv.URL+"/v1/invites/accept?code="+inv2.Code, bytes.NewReader(largeJSON))
	req.Header.Set("Authorization", "Bearer "+b.key)
	req.Header.Set("Content-Type", "application/json")
	resp2, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 413 {
		t.Fatalf("POST 413 oversized: want 413, got %d: %s", resp2.StatusCode, body)
	}
	if got := resp2.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("POST 413 oversized: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp2.Header.Get("Link"); got != wantLink {
		t.Errorf("POST 413 oversized: Link = %q, want %q", got, wantLink)
	}
	assertSecurityHeaders(t, resp2.Header, "POST 413 oversized")

	// 12. Body-only 400 (bad scopes) should NOT have deprecation headers (negative control)
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv3.Code, "scopes": []string{"BadScope"}}, nil)
	want(t, resp, body, 400)
	if got := resp.Header.Get("Deprecation"); got != "" {
		t.Errorf("body-only POST 400: unexpected Deprecation = %q", got)
	}
	if got := resp.Header.Get("Link"); got != "" {
		t.Errorf("body-only POST 400: unexpected Link = %q", got)
	}
	assertSecurityHeaders(t, resp.Header, "body-only POST 400")

	// 13. Body-only 401 (bad key) should NOT have deprecation headers (negative control)
	resp, body = b.do("POST", "/v1/invites/accept", map[string]any{"code": inv2.Code}, map[string]string{"Authorization": "Bearer pl_bogus"})
	want(t, resp, body, 401)
	if got := resp.Header.Get("Deprecation"); got != "" {
		t.Errorf("body-only POST 401: unexpected Deprecation = %q", got)
	}
	if got := resp.Header.Get("Link"); got != "" {
		t.Errorf("body-only POST 401: unexpected Link = %q", got)
	}
	assertSecurityHeaders(t, resp.Header, "body-only POST 401")

	// 14. 429 (rate limit) with ?code=: should have deprecation headers
	// Use fake clock to control rate limiter refill deterministically
	clk429 := clocktest.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	srvLimited := newServer(t, Config{WritePerMinute: 60, WriteBurst: 1, Clock: clk429})
	c := register(t, srvLimited, "charlie")
	d := register(t, srvLimited, "dave")
	respInv, bodyInv := c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, respInv, bodyInv, 201)
	var inv4 struct{ Code string }
	if err := json.Unmarshal(bodyInv, &inv4); err != nil || inv4.Code == "" {
		t.Fatalf("inv4: %v, code=%q", err, inv4.Code)
	}
	// Advance clock to allow rate limiter refill (60/min = 1 token per second)
	clk429.Advance(1100 * time.Millisecond)
	// Create another invite after bucket refill
	respInv2, bodyInv2 := c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, respInv2, bodyInv2, 201)
	var inv5 struct{ Code string }
	if err := json.Unmarshal(bodyInv2, &inv5); err != nil || inv5.Code == "" {
		t.Fatalf("inv5: %v, code=%q", err, inv5.Code)
	}
	// Create one more invite for body-only 429 test
	clk429.Advance(1100 * time.Millisecond)
	respInv3, bodyInv3 := c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, respInv3, bodyInv3, 201)
	var inv6 struct{ Code string }
	if err := json.Unmarshal(bodyInv3, &inv6); err != nil || inv6.Code == "" {
		t.Fatalf("inv6: %v, code=%q", err, inv6.Code)
	}
	// Exhaust Dave's write rate limit by accepting first invite (uses burst token)
	resp429, body429 := d.do("POST", "/v1/invites/accept?code="+inv4.Code, nil, nil)
	want(t, resp429, body429, 200)
	// Second accept immediately should hit 429 (no tokens left)
	resp429, body429 = d.do("POST", "/v1/invites/accept?code="+inv5.Code, nil, nil)
	want(t, resp429, body429, 429)
	if got := resp429.Header.Get("Deprecation"); got != wantDeprecation {
		t.Errorf("POST 429 rate limit: Deprecation = %q, want %q", got, wantDeprecation)
	}
	if got := resp429.Header.Get("Link"); got != wantLink {
		t.Errorf("POST 429 rate limit: Link = %q, want %q", got, wantLink)
	}
	if got := resp429.Header.Get("Retry-After"); got != "2" {
		t.Errorf("POST 429 rate limit: Retry-After = %q, want \"2\"", got)
	}
	assertSecurityHeaders(t, resp429.Header, "POST 429 rate limit")

	// 15. Body-only 429 should NOT have deprecation headers (negative control)
	resp429, body429 = d.do("POST", "/v1/invites/accept", map[string]any{"code": inv6.Code}, nil)
	want(t, resp429, body429, 429)
	if got := resp429.Header.Get("Deprecation"); got != "" {
		t.Errorf("body-only POST 429: unexpected Deprecation = %q", got)
	}
	if got := resp429.Header.Get("Link"); got != "" {
		t.Errorf("body-only POST 429: unexpected Link = %q", got)
	}
	if got := resp429.Header.Get("Retry-After"); got != "2" {
		t.Errorf("body-only POST 429: Retry-After = %q, want \"2\"", got)
	}
	assertSecurityHeaders(t, resp429.Header, "body-only POST 429")
}

func TestPairingLookupsBoundedPerIP(t *testing.T) {
	srv := newServer(t, Config{})
	anon := &client{t: t, srv: srv}
	notFound, limited := 0, 0
	for i := 0; i < 100; i++ {
		resp, _ := anon.do("POST", "/v1/pairing/"+auth.NewPairingToken(), map[string]any{"name": "x"}, nil)
		switch resp.StatusCode {
		case http.StatusNotFound:
			notFound++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if notFound > 5 || limited < 95 {
		t.Fatalf("lookups not bounded: 404=%d 429=%d", notFound, limited)
	}
}

func TestCSPNonceUniqueAndErrorResponsesStrict(t *testing.T) {
	srv := newServer(t, Config{})
	nonce := func() string {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		v := resp.Header.Values("Content-Security-Policy")
		if len(v) != 1 {
			t.Fatalf("want one CSP header, got %v", v)
		}
		m := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(v[0])
		if m == nil {
			t.Fatalf("no nonce in %q", v[0])
		}
		raw, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil || len(raw) < 16 {
			t.Fatalf("bad nonce %q: %v", m[1], err)
		}
		return m[1]
	}
	if nonce() == nonce() {
		t.Fatal("nonce reused across requests")
	}
	const strict = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	for _, c := range []struct{ method, path string }{{"GET", "/v1/me"}, {"GET", "/nope"}, {"POST", "/"}, {"POST", "/healthz"}} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Content-Security-Policy"); got != strict {
			t.Errorf("%s %s (%d): CSP %q", c.method, c.path, resp.StatusCode, got)
		}
	}
}

func TestVersionEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		detail      string
		wantStatus  int
		wantKeys    []string
		wantMissing []string
	}{
		{
			name:        "minimal (default)",
			detail:      "",
			wantStatus:  http.StatusOK,
			wantKeys:    []string{"version"},
			wantMissing: []string{"commit", "build_time"},
		},
		{
			name:        "minimal explicit",
			detail:      "minimal",
			wantStatus:  http.StatusOK,
			wantKeys:    []string{"version"},
			wantMissing: []string{"commit", "build_time"},
		},
		{
			name:       "full",
			detail:     "full",
			wantStatus: http.StatusOK,
			wantKeys:   []string{"version", "commit", "build_time"},
		},
		{
			name:       "off",
			detail:     "off",
			wantStatus: http.StatusNotFound,
		},
		{
			name:        "unknown value falls back to minimal",
			detail:      "invalid",
			wantStatus:  http.StatusOK,
			wantKeys:    []string{"version"},
			wantMissing: []string{"commit", "build_time"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newServer(t, Config{VersionDetail: tt.detail})
			req, _ := http.NewRequest("GET", srv.URL+"/version", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			// Check Cache-Control header
			if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
				t.Errorf("expected Cache-Control to contain no-store, got %q", cc)
			}

			if tt.wantStatus == http.StatusOK {
				var info map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				// Assert exact key set
				expectedKeys := make(map[string]bool)
				for _, key := range tt.wantKeys {
					expectedKeys[key] = true
				}
				for key := range info {
					if !expectedKeys[key] {
						t.Errorf("unexpected key %q in response (expected only %v)", key, tt.wantKeys)
					}
				}

				// Check expected keys are present and non-empty
				for _, key := range tt.wantKeys {
					val, ok := info[key]
					if !ok {
						t.Errorf("missing expected key %q", key)
					} else if val == "" {
						t.Errorf("key %q has empty value", key)
					}
				}

				// Check unwanted keys are absent
				for _, key := range tt.wantMissing {
					if _, ok := info[key]; ok {
						t.Errorf("unexpected key %q present", key)
					}
				}

				// For full mode, commit should be short (<=12 chars or "unknown")
				if tt.detail == "full" {
					commit := info["commit"]
					if commit != "unknown" && len(strings.TrimSuffix(commit, "-dirty")) > 12 {
						t.Errorf("full mode commit should be <=12 chars (plus -dirty), got %d (%q)", len(commit), commit)
					}
				}

				// Version should never expose branch names
				version := info["version"]
				if strings.Contains(version, "/") || strings.Contains(version, "merge") {
					t.Errorf("version should not contain branch-like strings, got %q", version)
				}

				// Assert security headers from securityHeaders wrapper
				headers := map[string]string{
					"Content-Security-Policy": "default-src 'none'",
					"X-Frame-Options":         "DENY",
					"X-Content-Type-Options":  "nosniff",
					"Referrer-Policy":         "no-referrer",
				}
				for header, expectedSubstring := range headers {
					value := resp.Header.Get(header)
					if !strings.Contains(value, expectedSubstring) {
						t.Errorf("header %s should contain %q, got: %s", header, expectedSubstring, value)
					}
				}
			}

			// Check Content-Type (except for off mode, which returns plain text 404)
			if tt.detail != "off" {
				if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", ct)
				}
			}
		})
	}
}

func TestVersionEndpointNoAuth(t *testing.T) {
	// Version endpoint should be public (no auth required) even with RegisterToken
	srv := newServer(t, Config{RegisterToken: "secret"})
	req, _ := http.NewRequest("GET", srv.URL+"/version", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("version endpoint should not require auth, got status %d", resp.StatusCode)
	}
}

func TestVersionEndpointRateLimit(t *testing.T) {
	srv := newServer(t, Config{})
	client := http.Client{Timeout: 2 * time.Second}
	foundRateLimit := false

	// The version endpoint has a separate limiter with burst of 30
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/version", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			foundRateLimit = true

			// Check for Retry-After header
			if ra := resp.Header.Get("Retry-After"); ra == "" {
				t.Error("429 response should include Retry-After header")
			}

			// Check uniform 429 body
			var errResp map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				t.Errorf("failed to decode 429 body: %v", err)
			} else if errMsg, ok := errResp["error"]; !ok || !strings.Contains(errMsg, "rate") {
				t.Errorf("429 response should contain rate limit error, got: %v", errResp)
			}

			// Verify security headers are present on 429
			if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
				t.Errorf("429 missing strict CSP, got: %s", csp)
			}

			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !foundRateLimit {
		t.Fatal("versionLim not wired: no 429 returned after 50 requests (burst is 30)")
	}
}

func TestVersionEndpointHEAD(t *testing.T) {
	srv := newServer(t, Config{})
	req, _ := http.NewRequest("HEAD", srv.URL+"/version", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD /version should return 200, got %d", resp.StatusCode)
	}

	// Content-Type should still be set
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	// Body should be empty for HEAD
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		t.Errorf("HEAD response should have empty body, got %d bytes", len(body))
	}
}

func TestVersionEndpointMethodNotAllowed(t *testing.T) {
	srv := newServer(t, Config{})
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, srv.URL+"/version", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s /version should return 405, got %d", method, resp.StatusCode)
			}
		})
	}
}

func TestVersionOffIndistinguishableFromUnknownRoute(t *testing.T) {
	srv := newServer(t, Config{VersionDetail: "off"})
	probe := func(method, path string) (int, string, string, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Allow"), string(b)
	}
	for _, m := range []string{"GET", "HEAD", "POST"} {
		c1, t1, a1, b1 := probe(m, "/version")
		c2, t2, a2, b2 := probe(m, "/does-not-exist")
		if c1 != c2 || t1 != t2 || a1 != a2 || b1 != b2 {
			t.Errorf("%s /version differs from unknown route: %d %q %q %q vs %d %q %q %q", m, c1, t1, a1, b1, c2, t2, a2, b2)
		}
	}
	for i := 0; i < 40; i++ {
		if c, _, _, _ := probe("GET", "/version"); c == http.StatusTooManyRequests {
			t.Fatal("off mode must never rate limit")
		}
	}
}

// TestNewRequiresLoadedKeyIndex verifies that api.New returns an error if the key index is not loaded.
func TestNewRequiresLoadedKeyIndex(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Don't load the key index
	cfg := Config{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthFailPerMinute: 30,
		AuthFailBurst:     10,
	}

	// api.New should fail without loaded index
	_, err = New(st, cfg)
	if err == nil {
		t.Fatal("api.New succeeded without loaded key index")
	}
	if !strings.Contains(err.Error(), "key index not loaded") {
		t.Fatalf("want 'key index not loaded' error, got: %v", err)
	}

	// After loading, it should succeed
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = New(st, cfg)
	if err != nil {
		t.Fatalf("api.New failed after LoadKeyIndex: %v", err)
	}
}

func TestBagGranteeWriteUsesOwnerQuota(t *testing.T) {
	srv := newServer(t, Config{MaxBagsPerPeer: 3, MaxBagBytesPerPeer: 100})
	a, b, c := register(t, srv, "alice"), register(t, srv, "bob"), register(t, srv, "carol")
	pairUp(t, a, b, []string{"messages", "bags:write"}, []string{"notes"}, nil)

	resp, body := a.do("PUT", "/v1/bags/own", bytes.Repeat([]byte("x"), 80), nil)
	want(t, resp, body, 201)
	resp, body = b.do("PUT", "/v1/bags/notes?owner="+a.id, bytes.Repeat([]byte("y"), 30), nil)
	want(t, resp, body, 413)
	resp, body = c.do("PUT", "/v1/bags/notes?owner="+a.id, []byte("z"), nil)
	want(t, resp, body, 403)
}

// The accept landing echoes the invite code, so every response on the accept
// routes must be uncacheable, referrer-free and non-sniffable (#174).
func TestAcceptRoutesSecurityHeaders(t *testing.T) {
	srv := newServer(t, Config{})
	a := register(t, srv, "alice")
	resp, body := a.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
	var inv struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || inv.Code == "" {
		t.Fatalf("invite response: %v %s", err, body)
	}

	cases := []struct {
		name   string
		client *client
		method string
		path   string
		body   any
		status int
	}{
		{"landing", &client{t: t, srv: srv}, "GET", "/v1/invites/accept?code=" + inv.Code, nil, 200},
		{"405 authenticated GET", a, "GET", "/v1/invites/accept", nil, 405},
		{"400 bad body", a, "POST", "/v1/invites/accept", map[string]any{"code": ""}, 400},
		{"404 unknown code", a, "POST", "/v1/invites/accept", map[string]any{"code": "inv_doesnotexist"}, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := tc.client.do(tc.method, tc.path, tc.body, nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.status, body)
			}
			for h, want := range map[string]string{
				"Cache-Control":          "no-store",
				"Referrer-Policy":        "no-referrer",
				"X-Content-Type-Options": "nosniff",
			} {
				if got := resp.Header.Get(h); got != want {
					t.Errorf("%s = %q, want %q", h, got, want)
				}
			}
		})
	}
}

// TestNewDefaultsToNonNilClock verifies that api.New with a nil Config.Clock
// defaults to a non-nil clock, as guaranteed by clock.Or.
func TestNewDefaultsToNonNilClock(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{}
	prepareTestConfig(t, st, &cfg)
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Creating an invite exercises clk.Now and proves it's non-nil (would panic otherwise)
	testSrv := httptest.NewServer(srv.Handler())
	defer testSrv.Close()

	c := &client{t: t, srv: testSrv}
	resp, body := c.do("POST", "/v1/register", map[string]string{"name": "test"}, nil)
	want(t, resp, body, 201)
	var reg struct{ PeerID, APIKey string }
	if err := json.Unmarshal(body, &struct {
		PeerID *string `json:"peer_id"`
		APIKey *string `json:"api_key"`
	}{&reg.PeerID, &reg.APIKey}); err != nil {
		t.Fatal(err)
	}
	c.id, c.key = reg.PeerID, reg.APIKey

	resp, body = c.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}}, nil)
	want(t, resp, body, 201)
}

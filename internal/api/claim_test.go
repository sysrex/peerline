package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

// fakeClaims is an in-memory ClaimStore with the semantics the handlers rely on.
type fakeClaims struct {
	mu    sync.Mutex
	byTok map[string]*ClaimInvite
	fails map[string]int
	grant []string
}

func (f *fakeClaims) byPub(pub string) *ClaimInvite {
	for _, c := range f.byTok {
		if c.PublicID == pub {
			return c
		}
	}
	return nil
}

func cp(c *ClaimInvite) *ClaimInvite { x := *c; return &x }

func (f *fakeClaims) ClaimByToken(_ context.Context, th, who string, nonce []byte, bs, bb []string) (*ClaimInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byTok[th]
	switch {
	case c == nil || c.Inviter == who || c.State == claimStateDeclined:
		return nil, store.ErrNotFound
	case c.State == "offered":
		c.State, c.Claimant, c.Nonce, c.BackScopes, c.BackBags = claimStateClaimed, who, nonce, bs, bb
	case c.Claimant != who:
		return nil, store.ErrNotFound
	}
	return cp(c), nil
}

func (f *fakeClaims) ClaimStatus(_ context.Context, th, who string) (*ClaimInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.byTok[th]; c != nil && c.Claimant == who {
		return cp(c), nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeClaims) InviterView(_ context.Context, pub, who string) (*ClaimInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.byPub(pub); c != nil && c.Inviter == who {
		return cp(c), nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeClaims) ConfirmClaim(_ context.Context, pub, who string, max int, check func(*ClaimInvite) bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byPub(pub)
	if c == nil || c.Inviter != who || c.State != claimStateClaimed {
		return "", store.ErrNotFound
	}
	if check(cp(c)) {
		c.State = claimStateActive
		f.grant = append(f.grant, c.Claimant)
		return c.State, nil
	}
	if f.fails[pub]++; f.fails[pub] >= max {
		c.State = claimStateDeclined
	}
	return c.State, nil
}

func (f *fakeClaims) DeclineClaim(_ context.Context, pub, who string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.byPub(pub); c != nil && c.Inviter == who && c.State != claimStateActive {
		c.State = claimStateDeclined
		return nil
	}
	return store.ErrNotFound
}

type claimEnv struct {
	fake                        *fakeClaims
	inviter, real, thief, other *client
	pub, token                  string
	logs                        *bytes.Buffer
}

func setupClaim(t *testing.T) *claimEnv {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &bytes.Buffer{}
	s := mustNew(t, st, Config{CodePepper: []byte("p"), Logger: slog.New(slog.NewTextHandler(logs, nil))})
	s.lim.pairLim = msg.NewLimiter(1000, 1000)
	f := &fakeClaims{byTok: map[string]*ClaimInvite{}, fails: map[string]int{}}
	s.SetClaimStore(f)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	e := &claimEnv{fake: f, logs: logs, pub: "pub_1", token: "pair_secrettokenvalue123456"}
	e.inviter, e.real, e.thief, e.other = register(t, srv, "inviter"), register(t, srv, "real"), register(t, srv, "thief"), register(t, srv, "other")
	f.byTok[auth.Hash(e.token)] = &ClaimInvite{PublicID: e.pub, Inviter: e.inviter.id, State: "offered", Scopes: []string{"messages"}}
	return e
}

func (e *claimEnv) claim(t *testing.T, c *client) (int, string) {
	t.Helper()
	resp, b := c.do("POST", "/v1/pairing/claim", map[string]string{"token": e.token}, nil)
	var out struct{ Code string }
	json.Unmarshal(b, &out)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("claim response not no-store")
	}
	return resp.StatusCode, out.Code
}

func TestClaimThiefCodeRejectedAndInviterViewHidesCode(t *testing.T) {
	e := setupClaim(t)
	st, thiefCode := e.claim(t, e.thief)
	if st != 200 || thiefCode == "" {
		t.Fatal("thief claim")
	}
	if st, _ := e.claim(t, e.real); st != 404 {
		t.Fatalf("real peer must get 404, got %d", st)
	}
	resp, b := e.inviter.do("GET", "/v1/invites/"+e.pub, nil, nil)
	want(t, resp, b, 200)
	if strings.Contains(string(b), thiefCode) || strings.Contains(string(b), `"code"`) || !strings.Contains(string(b), e.thief.id) {
		t.Fatalf("inviter view: %s", b)
	}
	for _, in := range []map[string]string{{"peer_id": e.real.id, "code": thiefCode}, {"peer_id": e.thief.id}} {
		resp, b = e.inviter.do("POST", "/v1/invites/"+e.pub+"/confirm", in, nil)
		want(t, resp, b, 400)
	}
	if len(e.fake.grant) != 0 {
		t.Fatal("grant written on failed confirm")
	}
	resp, b = e.inviter.do("POST", "/v1/invites/"+e.pub+"/confirm", map[string]string{"peer_id": e.thief.id, "code": "AAAA-AAAA"}, nil)
	want(t, resp, b, 400)
	if !strings.Contains(string(b), claimStateDeclined) {
		t.Fatalf("want declined: %s", b)
	}
	resp, b = e.inviter.do("POST", "/v1/invites/"+e.pub+"/confirm", map[string]string{"peer_id": e.thief.id, "code": thiefCode}, nil)
	want(t, resp, b, 404)
}

func TestClaimConfirmHappyPathIdempotentAndLogsClean(t *testing.T) {
	e := setupClaim(t)
	_, c1 := e.claim(t, e.real)
	st, c2 := e.claim(t, e.real)
	if st != 200 || c1 != c2 || c1 == "" {
		t.Fatalf("claim not idempotent: %d %q %q", st, c1, c2)
	}
	typed := strings.ToLower(strings.ReplaceAll(c1, "-", " "))
	resp, b := e.inviter.do("POST", "/v1/invites/"+e.pub+"/confirm", map[string]string{"peer_id": e.real.id, "code": typed}, nil)
	want(t, resp, b, 200)
	resp, b = e.real.do("POST", "/v1/pairing/status", map[string]string{"token": e.token}, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), claimStateActive) {
		t.Fatal(string(b))
	}
	for _, secret := range []string{e.token, auth.Hash(e.token), c1, strings.ReplaceAll(c1, "-", "")} {
		if strings.Contains(e.logs.String(), secret) {
			t.Fatalf("log contains secret %q", secret)
		}
	}
	if !strings.Contains(e.logs.String(), "invite_claimed") || !strings.Contains(e.logs.String(), "invite_confirm") {
		t.Fatal("audit events missing")
	}
}

// Every non-intended request must produce the same 404, byte for byte.
func TestClaimMissesAreIdentical(t *testing.T) {
	e := setupClaim(t)
	e.claim(t, e.real)
	do := func(c *client, m, p string, body any) func() (int, []byte) {
		return func() (int, []byte) { r, b := c.do(m, p, body, nil); return r.StatusCode, b }
	}
	tok := map[string]string{"token": e.token}
	cases := map[string]func() (int, []byte){
		"status unknown token":    do(e.real, "POST", "/v1/pairing/status", map[string]string{"token": "nope"}),
		"status other, valid tok": do(e.other, "POST", "/v1/pairing/status", tok),
		"status inviter":          do(e.inviter, "POST", "/v1/pairing/status", tok),
		"claim by other":          do(e.other, "POST", "/v1/pairing/claim", tok),
		"claim self":              do(e.inviter, "POST", "/v1/pairing/claim", tok),
		"claim unknown":           do(e.other, "POST", "/v1/pairing/claim", map[string]string{"token": "nope"}),
		"view non-inviter":        do(e.other, "GET", "/v1/invites/"+e.pub, nil),
		"view unknown":            do(e.inviter, "GET", "/v1/invites/nope", nil),
		"confirm non-inviter":     do(e.real, "POST", "/v1/invites/"+e.pub+"/confirm", map[string]string{"peer_id": e.real.id, "code": "x"}),
		"decline non-inviter":     do(e.real, "POST", "/v1/invites/"+e.pub+"/decline", map[string]string{}),
		"confirm unknown":         do(e.inviter, "POST", "/v1/invites/nope/confirm", map[string]string{"peer_id": "x", "code": "x"}),
	}
	var ref []byte
	for name, f := range cases {
		code, b := f()
		if code != 404 {
			t.Fatalf("%s: %d %s", name, code, b)
		}
		if ref == nil {
			ref = b
		} else if string(ref) != string(b) {
			t.Fatalf("%s differs: %s vs %s", name, b, ref)
		}
	}
}

func TestClaimRoutesRequireJSON(t *testing.T) {
	e := setupClaim(t)
	for _, p := range []string{"/v1/pairing/claim", "/v1/pairing/status", "/v1/invites/" + e.pub + "/confirm"} {
		resp, b := e.inviter.do("POST", p, []byte(`{"token":"x"}`), map[string]string{"Content-Type": "text/plain"})
		want(t, resp, b, 415)
	}
}

func TestClaimLimiterIgnoresTokenValidity(t *testing.T) {
	e := setupClaim(t)
	// the same server, but with the real small per-IP budget
	srv := httptest.NewServer(func() *Server {
		st, _ := store.Open(t.TempDir() + "/l.db")
		t.Cleanup(func() { st.Close() })
		s := mustNew(t, st, Config{CodePepper: []byte("p")})
		s.SetClaimStore(e.fake)
		return s
	}().Handler())
	t.Cleanup(srv.Close)
	c := register(t, srv, "limited")
	var last int
	for i := 0; i < 20; i++ {
		r, _ := c.do("POST", "/v1/pairing/status", map[string]string{"token": "nope"}, nil)
		last = r.StatusCode
	}
	if last != 429 {
		t.Fatalf("expected limiter to trip, got %d", last)
	}
	r, b := c.do("POST", "/v1/pairing/status", map[string]string{"token": e.token}, nil)
	want(t, r, b, 429)
}

func TestLegacyJSONRoutesRequireJSON(t *testing.T) {
	srv := newServer(t, Config{})
	c := &client{t: t, srv: srv}
	resp, b := c.do("POST", "/v1/register", []byte(`{"name":"x"}`), map[string]string{"Content-Type": "text/plain"})
	want(t, resp, b, 415)
}

package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

func claimServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := mustNew(t, st, Config{CodePepper: []byte("pepper")})
	s.lim.pairLim = msg.NewLimiter(1000, 1000)
	s.SetClaimStore(st)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func confirmInvite(t *testing.T, inviter *client) (pub, token string) {
	t.Helper()
	resp, b := inviter.do("POST", "/v1/invites", map[string]any{"scopes": []string{"messages"}, "generate_pairing": true, "require_confirm": true}, nil)
	want(t, resp, b, 201)
	var out struct {
		PublicID   string `json:"public_id"`
		PairingURL string `json:"pairing_url"`
	}
	json.Unmarshal(b, &out)
	return out.PublicID, out.PairingURL[strings.LastIndex(out.PairingURL, "/")+1:]
}

func TestClaimEndToEndRealStore(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant := register(t, srv, "inviter"), register(t, srv, "claimant")
	pub, token := confirmInvite(t, inviter)

	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code, State string }
	json.Unmarshal(b, &cl)
	if cl.Code == "" || cl.State != "claimed" || strings.Contains(string(b), "api_key") {
		t.Fatalf("claim: %s", b)
	}

	resp, b = claimant.do("POST", "/v1/pairing/status", map[string]string{"token": token}, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), `"claimed"`) {
		t.Fatal(string(b))
	}

	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	if strings.Contains(string(b), cl.Code) {
		t.Fatal("inviter view leaks code")
	}

	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": cl.Code}, nil)
	want(t, resp, b, 200)
	resp, b = claimant.do("POST", "/v1/pairing/status", map[string]string{"token": token}, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), `"active"`) {
		t.Fatal(string(b))
	}
	resp, b = claimant.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), inviter.id) {
		t.Fatalf("no grant after confirm: %s", b)
	}
}

func TestClaimWrongCodeThriceDeclines(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant := register(t, srv, "inviter"), register(t, srv, "claimant")
	pub, token := confirmInvite(t, inviter)
	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code string }
	json.Unmarshal(b, &cl)

	for i := 0; i < maxCodeFails; i++ {
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA"}, nil)
		want(t, resp, b, 400)
	}
	if !strings.Contains(string(b), "declined") {
		t.Fatalf("want declined: %s", b)
	}
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": cl.Code}, nil)
	want(t, resp, b, 404)
	resp, b = claimant.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if strings.Contains(string(b), inviter.id) {
		t.Fatal("grant written after decline")
	}
}

func TestConfirmInviteRefusesLegacyAcceptAndMissesAreIdentical(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant, other := register(t, srv, "inviter"), register(t, srv, "claimant"), register(t, srv, "other")
	pub, token := confirmInvite(t, inviter)

	anon := &client{t: t, srv: srv}
	for c, body := range map[*client]map[string]any{other: {"scopes": []string{"messages"}}, anon: {"name": "x"}} {
		resp, b := c.do("POST", "/v1/pairing/"+token, body, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("legacy accept of confirm invite: %d %s", resp.StatusCode, b)
		}
	}
	resp, b := other.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if strings.Contains(string(b), inviter.id) {
		t.Fatal("legacy accept wrote a grant")
	}

	resp, b = claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token}, nil)
	want(t, resp, b, 200)

	miss := func(c *client, m, p string, body any) string {
		r, b := c.do(m, p, body, nil)
		if r.StatusCode != 404 {
			t.Fatalf("%s %s: %d %s", m, p, r.StatusCode, b)
		}
		return string(b)
	}
	bodies := []string{
		miss(other, "POST", "/v1/pairing/claim", map[string]string{"token": token}),
		miss(claimant, "POST", "/v1/pairing/claim", map[string]string{"token": "pair_unknown"}),
		miss(inviter, "POST", "/v1/pairing/claim", map[string]string{"token": token}),
		miss(other, "POST", "/v1/pairing/status", map[string]string{"token": token}),
		miss(claimant, "POST", "/v1/pairing/status", map[string]string{"token": "pair_unknown"}),
		miss(other, "GET", "/v1/invites/"+pub, nil),
		miss(inviter, "GET", "/v1/invites/nope", nil),
		miss(other, "POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA"}),
		miss(inviter, "POST", "/v1/invites/nope/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA"}),
		miss(other, "POST", "/v1/invites/"+pub+"/decline", nil),
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("misses differ: %q vs %q", b, bodies[0])
		}
	}
}

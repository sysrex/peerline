package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal invite: %v", err)
	}
	return out.PublicID, out.PairingURL[strings.LastIndex(out.PairingURL, "/")+1:]
}

func TestClaimEndToEndRealStore(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant := register(t, srv, "inviter"), register(t, srv, "claimant")
	pub, token := confirmInvite(t, inviter)

	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code, State string }
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}
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
	var view struct {
		OfferDigest string `json:"offer_digest"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}
	if view.OfferDigest == "" {
		t.Fatal("offer_digest missing from inviter view")
	}

	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": cl.Code, "offer_digest": view.OfferDigest}, nil)
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
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}

	// Get offer digest
	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	var view struct {
		OfferDigest string `json:"offer_digest"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}

	for i := 0; i < maxCodeFails; i++ {
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA", "offer_digest": view.OfferDigest}, nil)
		want(t, resp, b, 400)
	}
	if !strings.Contains(string(b), "declined") {
		t.Fatalf("want declined: %s", b)
	}
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": cl.Code, "offer_digest": view.OfferDigest}, nil)
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
	// Get the offer_digest for confirm calls
	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	var view struct {
		OfferDigest string `json:"offer_digest"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}

	bodies := []string{
		miss(other, "POST", "/v1/pairing/claim", map[string]string{"token": token}),
		miss(claimant, "POST", "/v1/pairing/claim", map[string]string{"token": "pair_unknown"}),
		miss(inviter, "POST", "/v1/pairing/claim", map[string]string{"token": token}),
		miss(other, "POST", "/v1/pairing/status", map[string]string{"token": token}),
		miss(claimant, "POST", "/v1/pairing/status", map[string]string{"token": "pair_unknown"}),
		miss(other, "GET", "/v1/invites/"+pub, nil),
		miss(inviter, "GET", "/v1/invites/nope", nil),
		miss(other, "POST", "/v1/invites/"+pub+"/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA", "offer_digest": view.OfferDigest}),
		miss(inviter, "POST", "/v1/invites/nope/confirm", map[string]string{"peer_id": claimant.id, "code": "AAAA-AAAA", "offer_digest": view.OfferDigest}),
		miss(other, "POST", "/v1/invites/"+pub+"/decline", nil),
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("misses differ: %q vs %q", b, bodies[0])
		}
	}
}

// TestConfirmWithStaleDigestDoesNotDeadlock verifies that confirming with a stale digest
// returns 409 within a short deadline and does not deadlock the store (#310).
func TestConfirmWithStaleDigestDoesNotDeadlock(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant := register(t, srv, "inviter"), register(t, srv, "claimant")
	pub, token := confirmInvite(t, inviter)

	// Claim the invite
	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code string }
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatalf("unmarshal claim response: %v", err)
	}
	if cl.Code == "" {
		t.Fatal("claim returned empty code")
	}

	// Get fresh offer_digest
	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	var view struct {
		OfferDigest string                 `json:"offer_digest"`
		State       string                 `json:"state"`
		Offer       map[string]interface{} `json:"offer"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}
	if view.State != "claimed" {
		t.Fatalf("state: %s, want claimed", view.State)
	}
	if view.OfferDigest == "" {
		t.Fatal("offer_digest is empty")
	}

	// Confirm with a wrong (well-formed) digest under a 2 second timeout
	wrongDigest := "0000000000000000000000000000000000000000000000000000000000000000"

	// Create a client with timeout to ensure regression would fail fast
	timeoutClient := &http.Client{Timeout: 2 * time.Second}

	body, _ := json.Marshal(map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": wrongDigest,
	})
	req, _ := http.NewRequest("POST", srv.URL+"/v1/invites/"+pub+"/confirm", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+inviter.key)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := timeoutClient.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("stale digest confirm failed: %v (elapsed %v)", err, elapsed)
	}
	defer resp.Body.Close()
	b, _ = io.ReadAll(resp.Body)

	// Should get 409 Conflict with fresh view in body
	if resp.StatusCode != 409 {
		t.Fatalf("stale digest: got %d, want 409: %s", resp.StatusCode, b)
	}

	var staleResponse struct {
		OfferDigest string                 `json:"offer_digest"`
		Offer       map[string]interface{} `json:"offer"`
	}
	if err := json.Unmarshal(b, &staleResponse); err != nil {
		t.Fatalf("unmarshal 409 response: %v", err)
	}
	if staleResponse.OfferDigest != view.OfferDigest {
		t.Fatalf("409 body digest: %s, want %s", staleResponse.OfferDigest, view.OfferDigest)
	}
	if staleResponse.Offer == nil {
		t.Fatalf("409 body missing offer object: %s", b)
	}

	// Verify code_fails is still 0 by sending 3 MORE stale digest confirms
	// If the first one had counted, these would auto-decline
	for i := 0; i < 3; i++ {
		r, body := inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
			"peer_id":      claimant.id,
			"code":         cl.Code,
			"offer_digest": wrongDigest,
		}, nil)
		if r.StatusCode != 409 {
			t.Fatalf("stale attempt %d: got %d, want 409: %s", i+1, r.StatusCode, body)
		}
	}

	// Verify no grants were written
	resp, b = claimant.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if strings.Contains(string(b), inviter.id) {
		t.Fatal("grants written after stale digest")
	}

	// Now confirm with correct digest should still succeed (proving code_fails is still 0)
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": view.OfferDigest,
	}, nil)
	want(t, resp, b, 200)

	// Verify grants exist now
	resp, b = claimant.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), inviter.id) {
		t.Fatal("no grants after correct confirm")
	}

	// Verify a parallel /v1/me request does not hang (no deadlock)
	resp, b = inviter.do("GET", "/v1/me", nil, nil)
	want(t, resp, b, 200)
}

// TestActiveReplayWithDifferentPeerReturns404 verifies that replaying an active invite
// with a different peer_id and stale digest returns 404 (#311 item 1, P1-2).
func TestActiveReplayWithDifferentPeerReturns404(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant, other := register(t, srv, "inviter"), register(t, srv, "claimant"), register(t, srv, "other")
	pub, token := confirmInvite(t, inviter)

	// Claim and confirm
	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code string }
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}

	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	var view struct {
		OfferDigest string `json:"offer_digest"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}

	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": view.OfferDigest,
	}, nil)
	want(t, resp, b, 200)

	// Replay with same peer should return 200 active
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": view.OfferDigest,
	}, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), "active") {
		t.Fatalf("replay with same peer: %s", b)
	}

	// Replay with different peer + any digest should return 404
	wrongDigest := "1111111111111111111111111111111111111111111111111111111111111111"
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      other.id,
		"code":         cl.Code,
		"offer_digest": wrongDigest,
	}, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("replay with different peer: got %d %s, want 404", resp.StatusCode, b)
	}

	// Verify grants unchanged (still 2 bidirectional for inviter<->claimant)
	resp, b = inviter.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	var grantList struct {
		Grants []map[string]any `json:"grants"`
	}
	if err := json.Unmarshal(b, &grantList); err != nil {
		t.Fatalf("unmarshal grants: %v", err)
	}
	if len(grantList.Grants) != 2 || !strings.Contains(string(b), claimant.id) || strings.Contains(string(b), other.id) {
		t.Fatalf("grants after wrong peer replay: %s", b)
	}
}

// TestUppercaseHexDigestNormalized verifies that uppercase hex digests are normalized
// to lowercase and match correctly (#311 item 2, P3).
func TestUppercaseHexDigestNormalized(t *testing.T) {
	srv, _ := claimServer(t)
	inviter, claimant := register(t, srv, "inviter"), register(t, srv, "claimant")
	pub, token := confirmInvite(t, inviter)

	// Claim the invite
	resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
	want(t, resp, b, 200)
	var cl struct{ Code string }
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}

	// Get fresh offer_digest (lowercase)
	resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
	want(t, resp, b, 200)
	var view struct {
		OfferDigest string `json:"offer_digest"`
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("unmarshal inviter view: %v", err)
	}

	// Confirm with uppercase version of the digest
	upperDigest := strings.ToUpper(view.OfferDigest)
	resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": upperDigest,
	}, nil)

	// Should succeed (normalized to lowercase)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), "active") {
		t.Fatalf("uppercase digest: %s", b)
	}

	// Verify grants exist
	resp, b = claimant.do("GET", "/v1/grants", nil, nil)
	want(t, resp, b, 200)
	if !strings.Contains(string(b), inviter.id) {
		t.Fatal("no grants after uppercase digest confirm")
	}
}

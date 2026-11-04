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

	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

// apiClaimTestNow is the fixed start time for claim API tests.
var apiClaimTestNow = time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

func claimServer(t *testing.T) (*httptest.Server, *store.Store, *clocktest.Fake) {
	t.Helper()
	clk := clocktest.New(apiClaimTestNow)
	cfg := Config{CodePepper: []byte("pepper"), Clock: clk}
	st, err := store.OpenWithOptions(t.TempDir()+"/t.db", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := mustNew(t, st, cfg)
	s.lim.pairLim = msg.NewLimiter(1000, 1000)
	s.SetClaimStore(st)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st, clk
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
	srv, _, _ := claimServer(t)
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
	srv, _, _ := claimServer(t)
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
	srv, _, _ := claimServer(t)
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
	srv, _, _ := claimServer(t)
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

	body, err := json.Marshal(map[string]string{
		"peer_id":      claimant.id,
		"code":         cl.Code,
		"offer_digest": wrongDigest,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest("POST", srv.URL+"/v1/invites/"+pub+"/confirm", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+inviter.key)
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err = timeoutClient.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("stale digest confirm failed: %v (elapsed %v)", err, elapsed)
	}
	defer resp.Body.Close()
	b, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		t.Fatalf("read response body: %v", errRead)
	}

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
// with a different peer_id and stale digest returns 404 indistinguishable from a miss
// (same body and Content-Type as confirming an unknown public_id) (#311 item 1, P1-2).
func TestActiveReplayWithDifferentPeerReturns404(t *testing.T) {
	srv, _, _ := claimServer(t)
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

	// Get a known miss response (confirm on an unknown public_id) to compare
	unknownPub := "inv_0000000000000000000000000000"
	wrongDigest := "1111111111111111111111111111111111111111111111111111111111111111"
	missResp, missBody := inviter.do("POST", "/v1/invites/"+unknownPub+"/confirm", map[string]string{
		"peer_id":      claimant.id,
		"code":         "AAAA-AAAA",
		"offer_digest": wrongDigest,
	}, nil)
	if missResp.StatusCode != 404 {
		t.Fatalf("known miss: got %d, want 404", missResp.StatusCode)
	}
	missContentType := missResp.Header.Get("Content-Type")

	// Replay with different peer + any digest should return 404 indistinguishable from the miss
	replayResp, replayBody := inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
		"peer_id":      other.id,
		"code":         cl.Code,
		"offer_digest": wrongDigest,
	}, nil)
	if replayResp.StatusCode != 404 {
		t.Fatalf("replay with different peer: got %d %s, want 404", replayResp.StatusCode, replayBody)
	}
	replayContentType := replayResp.Header.Get("Content-Type")

	// Assert the 404 responses are byte-for-byte identical
	if !bytes.Equal(replayBody, missBody) {
		t.Errorf("replay 404 body differs from miss 404:\nreplay: %s\nmiss:   %s", replayBody, missBody)
	}
	if replayContentType != missContentType {
		t.Errorf("replay Content-Type %q != miss Content-Type %q", replayContentType, missContentType)
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
	srv, _, _ := claimServer(t)
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

// TestInviterViewJSONKeys verifies that the inviter view has exactly the expected keys
// for claimed invites (with and without replaces) and unclaimed invites, and that the 409
// stale-digest body equals the GET inviter view plus an "error" key (#326 P2).
func TestInviterViewJSONKeys(t *testing.T) {
	cases := []struct {
		name         string
		setup        func(srv *httptest.Server) (inviter, claimant *client, pub string)
		expectedKeys []string
		test409      bool
	}{
		{
			name: "unclaimed",
			setup: func(srv *httptest.Server) (*client, *client, string) {
				inviter := register(t, srv, "inviter_unclaimed")
				claimant := register(t, srv, "claimant_unclaimed")
				pub, _ := confirmInvite(t, inviter)
				return inviter, claimant, pub
			},
			expectedKeys: []string{"public_id", "state"},
			test409:      false,
		},
		{
			name: "claimed without replaces",
			setup: func(srv *httptest.Server) (*client, *client, string) {
				inviter := register(t, srv, "inviter_no_replaces")
				claimant := register(t, srv, "claimant_no_replaces")
				pub, token := confirmInvite(t, inviter)
				resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
				want(t, resp, b, 200)
				return inviter, claimant, pub
			},
			expectedKeys: []string{"public_id", "state", "claimant", "offer_digest", "offer"},
			test409:      true,
		},
		{
			name: "claimed with replaces",
			setup: func(srv *httptest.Server) (*client, *client, string) {
				inviter := register(t, srv, "inviter_with_replaces")
				claimant := register(t, srv, "claimant_with_replaces")

				// Create an existing grant by accepting a regular invite
				resp, b := inviter.do("POST", "/v1/invites", map[string]any{
					"scopes": []string{"messages"},
				}, nil)
				want(t, resp, b, 201)
				var inv struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(b, &inv); err != nil {
					t.Fatalf("unmarshal invite: %v", err)
				}

				// Claimant accepts it to create the grant
				resp, b = claimant.do("POST", "/v1/invites/accept", map[string]any{
					"code": inv.Code,
				}, nil)
				want(t, resp, b, 200)

				// Create a confirm invite that will replace the existing grant
				pub, token := confirmInvite(t, inviter)
				resp, b = claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
				want(t, resp, b, 200)

				return inviter, claimant, pub
			},
			expectedKeys: []string{"public_id", "state", "claimant", "offer_digest", "offer", "replaces"},
			test409:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := claimServer(t)
			inviter, claimant, pub := tc.setup(srv)

			// Get the inviter view
			resp, b := inviter.do("GET", "/v1/invites/"+pub, nil, nil)
			want(t, resp, b, 200)

			var view map[string]any
			if err := json.Unmarshal(b, &view); err != nil {
				t.Fatalf("unmarshal inviter view: %v", err)
			}

			// Check exact key set at top level
			gotKeys := make([]string, 0, len(view))
			for k := range view {
				gotKeys = append(gotKeys, k)
			}
			if !equalStringSets(tc.expectedKeys, gotKeys) {
				t.Errorf("keys mismatch:\n  want: %v\n  got:  %v", tc.expectedKeys, gotKeys)
			}

			// For claimed invites, verify the 409 stale-digest body equals GET view plus "error"
			if tc.test409 {
				wrongDigest := "0000000000000000000000000000000000000000000000000000000000000000"
				resp409, b409 := inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
					"peer_id":      claimant.id,
					"code":         "AAAA-AAAA",
					"offer_digest": wrongDigest,
				}, nil)
				if resp409.StatusCode != 409 {
					t.Fatalf("expected 409, got %d: %s", resp409.StatusCode, b409)
				}

				var view409 map[string]any
				if err := json.Unmarshal(b409, &view409); err != nil {
					t.Fatalf("unmarshal 409 response: %v", err)
				}

				// The 409 body should have the same keys as GET view, plus "error"
				if _, ok := view409["error"]; !ok {
					t.Errorf("409 response missing error key")
				}

				// Remove "error" key and use reflect.DeepEqual to compare
				delete(view409, "error")

				// Marshal both to JSON and compare for deep equality
				viewJSON, err := json.Marshal(view)
				if err != nil {
					t.Fatalf("marshal GET view: %v", err)
				}
				view409JSON, err := json.Marshal(view409)
				if err != nil {
					t.Fatalf("marshal 409 view: %v", err)
				}

				// Unmarshal both back to map[string]any to normalize for comparison
				var viewNorm, view409Norm map[string]any
				if err := json.Unmarshal(viewJSON, &viewNorm); err != nil {
					t.Fatalf("unmarshal GET view JSON: %v", err)
				}
				if err := json.Unmarshal(view409JSON, &view409Norm); err != nil {
					t.Fatalf("unmarshal 409 view JSON: %v", err)
				}

				// Use reflect.DeepEqual for comparison
				if !deepEqual(viewNorm, view409Norm) {
					t.Errorf("409 body (minus error) != GET view:\n  GET:  %s\n  409:  %s", viewJSON, view409JSON)
				}
			}
		})
	}
}

// equalStringSets checks if two string slices contain the same elements (order-independent).
func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	for _, count := range m {
		if count != 0 {
			return false
		}
	}
	return true
}

// deepEqual compares two values using JSON round-trip normalization.
func deepEqual(a, b any) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

// TestDeclineIdempotentAndActiveReturns404 verifies that declining a claimed invite
// twice returns 200 both times, and that declining an offered or active invite
// returns 404 (#326 P3-2).
func TestDeclineIdempotentAndActiveReturns404(t *testing.T) {
	t.Run("decline claimed twice", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_decline_twice")
		claimant := register(t, srv, "claimant_decline_twice")
		pub, token := confirmInvite(t, inviter)

		// Claim the invite
		resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
		want(t, resp, b, 200)

		// First decline
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/decline", nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("first decline: got %d, want 200: %s", resp.StatusCode, b)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("first decline Content-Type: got %q, want application/json", resp.Header.Get("Content-Type"))
		}
		var result map[string]string
		if err := json.Unmarshal(b, &result); err != nil {
			t.Fatalf("unmarshal first decline response: %v", err)
		}
		if result["state"] != "declined" {
			t.Errorf("first decline state: got %q, want declined", result["state"])
		}

		// Second decline (idempotent)
		resp2, b2 := inviter.do("POST", "/v1/invites/"+pub+"/decline", nil, nil)
		if resp2.StatusCode != 200 {
			t.Fatalf("second decline: got %d, want 200: %s", resp2.StatusCode, b2)
		}
		if resp2.Header.Get("Content-Type") != "application/json" {
			t.Errorf("second decline Content-Type: got %q, want application/json", resp2.Header.Get("Content-Type"))
		}
		var result2 map[string]string
		if err := json.Unmarshal(b2, &result2); err != nil {
			t.Fatalf("unmarshal second decline response: %v", err)
		}
		if result2["state"] != "declined" {
			t.Errorf("second decline state: got %q, want declined", result2["state"])
		}

		// Both responses should be identical
		if string(b) != string(b2) {
			t.Errorf("decline responses differ:\n  first:  %s\n  second: %s", b, b2)
		}
	})

	t.Run("decline offered returns 404", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_decline_offered")
		pub, _ := confirmInvite(t, inviter)

		// Don't claim it, leave it in "offered" state
		// Try to decline an offered invite
		resp, b := inviter.do("POST", "/v1/invites/"+pub+"/decline", nil, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("decline offered invite: got %d, want 404: %s", resp.StatusCode, b)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("decline offered Content-Type: got %q, want application/json", resp.Header.Get("Content-Type"))
		}
	})

	t.Run("decline active returns 404", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_decline_active")
		claimant := register(t, srv, "claimant_decline_active")
		pub, token := confirmInvite(t, inviter)

		// Claim the invite
		resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
		want(t, resp, b, 200)
		var cl struct{ Code string }
		if err := json.Unmarshal(b, &cl); err != nil {
			t.Fatalf("unmarshal claim response: %v", err)
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

		// Confirm the invite to make it active
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
			"peer_id":      claimant.id,
			"code":         cl.Code,
			"offer_digest": view.OfferDigest,
		}, nil)
		want(t, resp, b, 200)

		// Try to decline an active invite
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/decline", nil, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("decline active invite: got %d, want 404: %s", resp.StatusCode, b)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("decline active Content-Type: got %q, want application/json", resp.Header.Get("Content-Type"))
		}
	})
}

// TestDeleteClaimedInvite verifies that DELETE /v1/invites/{public_id} works on
// claimed (pending-confirm) invites and returns 204, but returns 404 on active
// (confirmed) invites (#80 docs).
func TestDeleteClaimedInvite(t *testing.T) {
	t.Run("delete claimed returns 204", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_delete_claimed")
		claimant := register(t, srv, "claimant_delete_claimed")
		pub, token := confirmInvite(t, inviter)

		// Claim the invite (but don't confirm)
		resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
		want(t, resp, b, 200)

		// DELETE should work on claimed invites
		resp, b = inviter.do("DELETE", "/v1/invites/"+pub, nil, nil)
		if resp.StatusCode != 204 {
			t.Fatalf("DELETE claimed invite: got %d, want 204; body: %s", resp.StatusCode, b)
		}
		if len(b) != 0 {
			t.Errorf("DELETE claimed invite: expected empty body, got: %s", b)
		}

		// Verify the invite is gone
		resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("GET after DELETE: got %d, want 404; body: %s", resp.StatusCode, b)
		}
	})

	t.Run("delete declined returns 204", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_delete_declined")
		claimant := register(t, srv, "claimant_delete_declined")
		pub, token := confirmInvite(t, inviter)

		// Claim the invite (but don't confirm)
		resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
		want(t, resp, b, 200)

		// Decline the invite
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/decline", nil, nil)
		want(t, resp, b, 200)

		// DELETE should work on declined invites
		resp, b = inviter.do("DELETE", "/v1/invites/"+pub, nil, nil)
		if resp.StatusCode != 204 {
			t.Fatalf("DELETE declined invite: got %d, want 204; body: %s", resp.StatusCode, b)
		}
		if len(b) != 0 {
			t.Errorf("DELETE declined invite: expected empty body, got: %s", b)
		}

		// Verify the invite is gone
		resp, b = inviter.do("GET", "/v1/invites/"+pub, nil, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("GET after DELETE: got %d, want 404; body: %s", resp.StatusCode, b)
		}
	})

	t.Run("delete active returns 404", func(t *testing.T) {
		srv, _, _ := claimServer(t)
		inviter := register(t, srv, "inviter_delete_active")
		claimant := register(t, srv, "claimant_delete_active")
		pub, token := confirmInvite(t, inviter)

		// Claim the invite
		resp, b := claimant.do("POST", "/v1/pairing/claim", map[string]any{"token": token, "scopes": []string{"messages"}}, nil)
		want(t, resp, b, 200)
		var cl struct{ Code string }
		if err := json.Unmarshal(b, &cl); err != nil {
			t.Fatalf("unmarshal claim response: %v", err)
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

		// Confirm the invite (activate it)
		resp, b = inviter.do("POST", "/v1/invites/"+pub+"/confirm", map[string]string{
			"peer_id":      claimant.id,
			"code":         cl.Code,
			"offer_digest": view.OfferDigest,
		}, nil)
		want(t, resp, b, 200)

		// DELETE should return 404 on active invites
		resp, b = inviter.do("DELETE", "/v1/invites/"+pub, nil, nil)
		if resp.StatusCode != 404 {
			t.Fatalf("DELETE active invite: got %d, want 404; body: %s", resp.StatusCode, b)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("DELETE active Content-Type: got %q, want application/json", resp.Header.Get("Content-Type"))
		}
	})
}

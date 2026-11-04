package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/store"
)

// TestAcceptInviteGrantConflictAPI tests the full HTTP handler path for invite
// accept when a different grant exists. Verifies 409 response, correct JSON body,
// and that grants remain unchanged (#312).
func TestAcceptInviteGrantConflictAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Setup: alice and bob
	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create existing grant alice->bob with "messages" via first pairing
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with different scope "bags_read"
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(code), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept - should get 409
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status code: got %d, want %d", rec.Code, http.StatusConflict)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	expectedMsg := "already paired with different grants; revoke the grant or use a confirm-mode invite"
	if resp["error"] != expectedMsg {
		t.Errorf("error message: got %q, want %q", resp["error"], expectedMsg)
	}

	// Verify grant unchanged via store
	g, err := st.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Fatalf("GetGrant after conflict: %v", err)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "messages" {
		t.Errorf("grant changed: got %v, want [messages]", g.Scopes)
	}

	// Verify by trying to accept again - should still give conflict (invite not consumed)
	req2 := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+bobKey)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Errorf("second attempt: got %d, want %d (invite should still be unused)", rec2.Code, http.StatusConflict)
	}
}

// TestAcceptInviteIdenticalGrantAPI verifies that accepting with identical grants
// returns 200 and consumes the invite (idempotent behavior, #312).
func TestAcceptInviteIdenticalGrantAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create existing grant alice->bob with "messages" via first pairing
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with same scope "messages" (order-insensitive)
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(code), "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts - should succeed with 200
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status code: got %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify by trying to accept again - should fail with 404 (invite consumed)
	req2 := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+bobKey)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second attempt: got %d, want %d (invite should be consumed)", rec2.Code, http.StatusNotFound)
	}
}

// TestAcceptPairingGrantConflictAPI tests the pairing token path (POST /v1/pairing/{token})
// with Bearer auth when a different grant exists. Verifies 409 and unchanged grants (#312).
func TestAcceptPairingGrantConflictAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create existing grant alice->bob with "messages" via first pairing
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite with different scope
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	pairingToken := auth.NewPairingToken()
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(code), auth.Hash(pairingToken), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob tries to accept via pairing token - should get 409
	body, err := json.Marshal(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)
	req.SetPathValue("token", pairingToken)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status code: got %d, want %d (body: %s)", rec.Code, http.StatusConflict, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	expectedMsg := "already paired with different grants; revoke the grant or use a confirm-mode invite"
	if resp["error"] != expectedMsg {
		t.Errorf("error message: got %q, want %q", resp["error"], expectedMsg)
	}

	// Verify grant unchanged
	g, err := st.GetGrant(ctx, "alice", "bob")
	if err != nil {
		t.Fatalf("GetGrant after conflict: %v", err)
	}
	if len(g.Scopes) != 1 || g.Scopes[0] != "messages" {
		t.Errorf("grant changed: got %v, want [messages]", g.Scopes)
	}
}

// TestAcceptPairingUnauthenticatedFirstTimeSucceedsAPI tests the unauthenticated pairing
// path (POST /v1/pairing/{token} without Bearer) for first-time accept.
// This is the normal path: the peer is being registered and no grant exists yet.
func TestAcceptPairingUnauthenticatedFirstTimeSucceedsAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	pairingToken := auth.NewPairingToken()
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(code), auth.Hash(pairingToken), "alice", []string{"messages"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// New peer accepts - should succeed (first time, no existing grant)
	body, err := json.Marshal(map[string]interface{}{
		"name": "NewPeer",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("token", pairingToken)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status code: got %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &respData); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if respData["peer_id"] == nil {
		t.Error("peer_id missing from response")
	}
	if respData["api_key"] == nil {
		t.Error("api_key missing from response")
	}
}

// TestExpiredInviteWithDifferentGrantReturns404API verifies that accepting an expired
// invite returns 404, not 409, even when grants differ (status ordering fix, #312).
func TestExpiredInviteWithDifferentGrantReturns404API(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create existing grant alice->bob with "messages"
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite with different scope that expires in 1 hour
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(code), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Advance clock past expiry
	clk.Advance(2 * time.Hour)

	// Bob tries to accept expired invite - should get 404, not 409
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expired invite: got %d, want %d (body: %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestUsedInviteWithDifferentGrantReturns404API verifies that accepting a used
// invite returns 404, not 409, even when grants differ (status ordering fix, #312).
func TestUsedInviteWithDifferentGrantReturns404API(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	carolKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "carol", "Carol", auth.Hash(carolKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Carol accepts first, getting grant with "messages"
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates invite for Bob with "bags_read"
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(code), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts it
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob accept: got %d, want %d", rec.Code, http.StatusOK)
	}

	// Carol (who has different grant "messages") tries to accept the now-used invite
	// Should get 404, not 409
	req2 := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+carolKey)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotFound {
		t.Errorf("used invite: got %d, want %d (body: %s)", rec2.Code, http.StatusNotFound, rec2.Body.String())
	}
}

// TestExpiredPairingTokenWithDifferentGrantReturns404API verifies that accepting an
// expired pairing token returns 404, not 409, even when grants differ (#312).
func TestExpiredPairingTokenWithDifferentGrantReturns404API(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create existing grant alice->bob with "messages"
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite with different scope that expires in 1 hour
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	pairingToken := auth.NewPairingToken()
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(code), auth.Hash(pairingToken), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Advance clock past expiry
	clk.Advance(2 * time.Hour)

	// Bob tries to accept expired pairing token - should get 404, not 409
	body, err := json.Marshal(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)
	req.SetPathValue("token", pairingToken)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expired pairing token: got %d, want %d (body: %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestUsedPairingTokenWithDifferentGrantReturns404API verifies that accepting a used
// pairing token returns 404, not 409, even when grants differ (#312).
func TestUsedPairingTokenWithDifferentGrantReturns404API(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	carolKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "carol", "Carol", auth.Hash(carolKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Carol accepts first, getting grant with "messages"
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Alice creates pairing invite for Bob with "bags_read"
	exp := clk.Now().Add(time.Hour)
	code := auth.NewSecret("inv_")
	pairingToken := auth.NewPairingToken()
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(code), auth.Hash(pairingToken), "alice", []string{"bags_read"}, nil, exp); err != nil {
		t.Fatal(err)
	}

	// Bob accepts it
	body, err := json.Marshal(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)
	req.SetPathValue("token", pairingToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob accept: got %d, want %d", rec.Code, http.StatusOK)
	}

	// Carol (who has different grant "messages") tries to accept the now-used pairing token
	// Should get 404, not 409
	req2 := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+carolKey)
	req2.SetPathValue("token", pairingToken)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotFound {
		t.Errorf("used pairing token: got %d, want %d (body: %s)", rec2.Code, http.StatusNotFound, rec2.Body.String())
	}
}

// TestDeadLinkByteIdentical404 verifies that used and expired links return exactly
// the same 404 response (body and Content-Type) as an unknown code, so there's no
// grant-state oracle on dead links (#337 item 2).
func TestDeadLinkByteIdentical404(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	bobKey := auth.NewKey()
	carolKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "bob", "Bob", auth.Hash(bobKey), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePeer(ctx, "carol", "Carol", auth.Hash(carolKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Create a grant alice->bob so bob has a different grant for later tests
	code0 := auth.NewSecret("inv_")
	exp0 := clk.Now().Add(time.Hour)
	if err := st.CreateInvite(ctx, auth.Hash(code0), "alice", []string{"messages"}, nil, exp0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(code0), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	// Get baseline 404 for unknown code
	unknownCode := auth.NewSecret("inv_")
	body, _ := json.Marshal(map[string]string{"code": unknownCode})
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bobKey)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown code: got %d, want 404", rec.Code)
	}
	unknownBody := rec.Body.Bytes()
	unknownContentType := rec.Header().Get("Content-Type")

	// Test used invite on /v1/invites/accept
	// Carol accepts an invite with bags_read, then bob (who has messages grant) tries to accept the used invite
	usedCode := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(usedCode), "alice", []string{"bags_read"}, nil, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInvite(ctx, auth.Hash(usedCode), "carol", nil, nil); err != nil {
		t.Fatal(err)
	}

	body2, _ := json.Marshal(map[string]string{"code": usedCode})
	req2 := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+bobKey)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotFound {
		t.Errorf("used invite: got %d, want 404", rec2.Code)
	}
	if !bytes.Equal(rec2.Body.Bytes(), unknownBody) {
		t.Errorf("used invite body differs: got %q, want %q", rec2.Body.String(), string(unknownBody))
	}
	if rec2.Header().Get("Content-Type") != unknownContentType {
		t.Errorf("used invite Content-Type: got %q, want %q", rec2.Header().Get("Content-Type"), unknownContentType)
	}

	// Test expired invite on /v1/invites/accept
	// Create an invite with a different grant (bags_write) and let it expire
	expiredCode := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(expiredCode), "alice", []string{"bags_write"}, nil, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)

	body3, _ := json.Marshal(map[string]string{"code": expiredCode})
	req3 := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body3))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+bobKey)
	rec3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusNotFound {
		t.Errorf("expired invite: got %d, want 404", rec3.Code)
	}
	if !bytes.Equal(rec3.Body.Bytes(), unknownBody) {
		t.Errorf("expired invite body differs: got %q, want %q", rec3.Body.String(), string(unknownBody))
	}
	if rec3.Header().Get("Content-Type") != unknownContentType {
		t.Errorf("expired invite Content-Type: got %q, want %q", rec3.Header().Get("Content-Type"), unknownContentType)
	}

	// Test used pairing token on /v1/pairing/{token}
	usedPairingToken := auth.NewPairingToken()
	usedPairingCode := auth.NewSecret("inv_")
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(usedPairingCode), auth.Hash(usedPairingToken), "alice", []string{"messages"}, nil, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptInviteByPairingToken(ctx, auth.Hash(usedPairingToken), "bob", nil, nil); err != nil {
		t.Fatal(err)
	}

	unknownToken := auth.NewPairingToken()
	body4, _ := json.Marshal(map[string]interface{}{})
	req4 := httptest.NewRequest("POST", "/v1/pairing/"+unknownToken, bytes.NewReader(body4))
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("Authorization", "Bearer "+bobKey)
	req4.SetPathValue("token", unknownToken)
	rec4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec4, req4)

	unknownPairingBody := rec4.Body.Bytes()
	unknownPairingContentType := rec4.Header().Get("Content-Type")

	req5 := httptest.NewRequest("POST", "/v1/pairing/"+usedPairingToken, bytes.NewReader(body4))
	req5.Header.Set("Content-Type", "application/json")
	req5.Header.Set("Authorization", "Bearer "+bobKey)
	req5.SetPathValue("token", usedPairingToken)
	rec5 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec5, req5)

	if rec5.Code != http.StatusNotFound {
		t.Errorf("used pairing token: got %d, want 404", rec5.Code)
	}
	if !bytes.Equal(rec5.Body.Bytes(), unknownPairingBody) {
		t.Errorf("used pairing body differs: got %q, want %q", rec5.Body.String(), string(unknownPairingBody))
	}
	if rec5.Header().Get("Content-Type") != unknownPairingContentType {
		t.Errorf("used pairing Content-Type: got %q, want %q", rec5.Header().Get("Content-Type"), unknownPairingContentType)
	}

	// Test expired pairing token on /v1/pairing/{token}
	expiredPairingToken := auth.NewPairingToken()
	expiredPairingCode := auth.NewSecret("inv_")
	clk.Advance(-1 * time.Hour)
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(expiredPairingCode), auth.Hash(expiredPairingToken), "alice", []string{"messages"}, nil, clk.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)

	req6 := httptest.NewRequest("POST", "/v1/pairing/"+expiredPairingToken, bytes.NewReader(body4))
	req6.Header.Set("Content-Type", "application/json")
	req6.Header.Set("Authorization", "Bearer "+bobKey)
	req6.SetPathValue("token", expiredPairingToken)
	rec6 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec6, req6)

	if rec6.Code != http.StatusNotFound {
		t.Errorf("expired pairing token: got %d, want 404", rec6.Code)
	}
	if !bytes.Equal(rec6.Body.Bytes(), unknownPairingBody) {
		t.Errorf("expired pairing body differs: got %q, want %q", rec6.Body.String(), string(unknownPairingBody))
	}
	if rec6.Header().Get("Content-Type") != unknownPairingContentType {
		t.Errorf("expired pairing Content-Type: got %q, want %q", rec6.Header().Get("Content-Type"), unknownPairingContentType)
	}
}

// TestAPISelfPairingExactBody verifies that self-pairing returns 400 with the exact
// expected error messages, not 409 or another message (#337 item 3).
func TestAPISelfPairingExactBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clk := clocktest.New(time.Unix(1000000, 0))
	st, err := store.OpenWithOptions(":memory:", store.OpenOptions{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srv, err := New(st, Config{
		Logger:                slog.Default(),
		Clock:                 clk,
		MaxOutstandingInvites: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	aliceKey := auth.NewKey()
	if err := st.CreatePeer(ctx, "alice", "Alice", auth.Hash(aliceKey), "", ""); err != nil {
		t.Fatal(err)
	}

	// Test self-pairing on /v1/invites/accept
	code := auth.NewSecret("inv_")
	if err := st.CreateInvite(ctx, auth.Hash(code), "alice", []string{"messages"}, nil, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+aliceKey)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("/v1/invites/accept self-pairing: got %d, want 400", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	expectedMsg := "cannot accept your own invite"
	if resp["error"] != expectedMsg {
		t.Errorf("/v1/invites/accept self-pairing body: got %q, want %q", resp["error"], expectedMsg)
	}

	// Test self-pairing on /v1/pairing/{token} (authenticated)
	pairingToken := auth.NewPairingToken()
	code2 := auth.NewSecret("inv_")
	if err := st.CreateInviteWithPairing(ctx, auth.Hash(code2), auth.Hash(pairingToken), "alice", []string{"messages"}, nil, clk.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	body2, _ := json.Marshal(map[string]interface{}{})
	req2 := httptest.NewRequest("POST", "/v1/pairing/"+pairingToken, bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+aliceKey)
	req2.SetPathValue("token", pairingToken)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusBadRequest {
		t.Errorf("/v1/pairing/{token} self-pairing: got %d, want 400", rec2.Code)
	}

	var resp2 map[string]string
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	expectedMsg2 := "cannot accept your own pairing link"
	if resp2["error"] != expectedMsg2 {
		t.Errorf("/v1/pairing/{token} self-pairing body: got %q, want %q", resp2["error"], expectedMsg2)
	}
}

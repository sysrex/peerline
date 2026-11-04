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

// TestAcceptPairingUnauthenticatedGrantConflictAPI tests the unauthenticated pairing
// path (POST /v1/pairing/{token} without Bearer) when a grant might exist.
// This is an edge case since the peer is being registered, so normally no grant exists.
func TestAcceptPairingUnauthenticatedGrantConflictAPI(t *testing.T) {
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

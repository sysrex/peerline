package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

func TestA2AJSONRPCRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, st := newServerWithAccess(t, Config{})
	store.EnableAuditForTest(st, priv)
	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")
	carol := register(t, srv, "carol")
	pairUp(t, bob, alice, []string{"a2a", "messages"}, nil, nil)

	resp, body := alice.do("POST", "/a2a", rpc("SendMessage", map[string]any{
		"tenant": bob.id, "message": map[string]any{"parts": []any{map[string]string{"text": "hi"}}},
	}), nil)
	want(t, resp, body, 200)
	var sent struct {
		Result struct {
			ID, State string
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &sent); err != nil || sent.Result.ID == "" || sent.Result.State != "submitted" {
		t.Fatalf("send: %s", body)
	}
	resp, body = bob.do("PUT", "/v1/a2a/tasks/"+sent.Result.ID, map[string]any{
		"state": "completed", "artifacts": `{"name":"out"}`,
	}, nil)
	want(t, resp, body, 204)
	resp, body = alice.do("POST", "/a2a", rpc("GetTask", map[string]any{"id": sent.Result.ID}), nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"state":"completed"`) || !strings.Contains(string(body), "out") {
		t.Fatalf("get: %s", body)
	}

	before := rpcCount(t, st)
	resp, body = carol.do("POST", "/a2a", rpc("SendMessage", map[string]any{
		"tenant": bob.id, "message": map[string]any{"parts": []any{map[string]string{"text": "no"}}},
	}), nil)
	want(t, resp, body, 200)
	miss := string(body)
	resp, body = carol.do("POST", "/a2a", rpc("SendMessage", map[string]any{
		"tenant": "p_missing", "message": map[string]any{"parts": []any{map[string]string{"text": "no"}}},
	}), nil)
	want(t, resp, body, 200)
	if miss != string(body) || !strings.Contains(miss, `"code":-32001`) {
		t.Fatalf("miss %s unknown %s", miss, body)
	}
	if rpcCount(t, st) != before {
		t.Fatal("ungranted call wrote an audit record")
	}

	resp, body = alice.do("POST", "/a2a", rpc("NoSuchMethod", map[string]any{}), nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"code":-32601`) {
		t.Fatalf("method: %s", body)
	}
}

func TestA2ARPCRateLimit(t *testing.T) {
	srv, apiSrv, _ := newServerWithAccess(t, Config{})
	alice := register(t, srv, "alice")
	bob := register(t, srv, "bob")
	pairUp(t, bob, alice, []string{"a2a", "messages"}, nil, nil)
	withLimiterOverride(t, apiSrv, func(lm *LimiterManager, newLimiter func(perMinute, burst int) *msg.Limiter) {
		lm.msgLim = newLimiter(1, 1)
	})
	body := rpc("SendMessage", map[string]any{
		"tenant": bob.id, "message": map[string]any{"parts": []any{map[string]string{"text": "hi"}}},
	})
	resp, raw := alice.do("POST", "/a2a", body, nil)
	want(t, resp, raw, 200)
	resp, raw = alice.do("POST", "/a2a", body, nil)
	want(t, resp, raw, 429)
	if resp.Header.Get("Retry-After") != "2" {
		t.Fatalf("retry-after %q", resp.Header.Get("Retry-After"))
	}
}

func rpc(method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": "1", "method": method, "params": params}
}

func rpcCount(t *testing.T, st *store.Store) int {
	t.Helper()
	n, err := store.AuditEventCount(st, "a2a.rpc")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

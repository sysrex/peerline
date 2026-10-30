package mcpbridge

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/store"
)

// Uses real Peerline HTTP handlers and SQLite grants, with only the OAuth
// provider and external callback replaced by deterministic fixtures.
func TestMCPWithRealRelayAcrossIndependentAccounts(t *testing.T) {
	ctx := context.Background()
	accounts := map[string]Account{}
	relays := map[string]*HTTPRelay{}
	stores := map[string]*store.Store{}
	for _, id := range []string{"a", "b"} {
		st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		for _, peer := range []string{"p_dot", "p_bot"} {
			if err := st.CreatePeer(ctx, peer, "same-display-name", auth.Hash("pl_fixture_"+id+peer), "", ""); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := st.LoadKeyIndex(ctx); err != nil {
			t.Fatal(err)
		}
		srv, err := api.New(st, api.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), CodePepper: []byte("fixture-pepper-for-test-only")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(srv.Stop)
		ts := httptest.NewTLSServer(srv.Handler())
		t.Cleanup(ts.Close)
		env := "TEST_E2E_" + strings.ToUpper(id)
		t.Setenv(env, "pl_fixture_"+id+"p_dot")
		a := Account{ID: id, Subject: "sub-" + id, RelayURL: ts.URL, PeerID: "p_dot", APIKeyEnv: env, Peers: map[string]string{"colleague": "p_bot"}, AccessToken: "fixture-token-" + id, AccessTokenExpiresAt: time.Now().Add(time.Hour)}
		accounts["Bearer "+id] = a
		relays[id] = &HTTPRelay{client: ts.Client()}
		stores[id] = st
	}
	relay := multiFixtureRelay{relays}
	bridge := &Server{Auth: rpcAuth{accounts}, Relay: relay, ResourceURL: "https://mcp.example/mcp"}
	send := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_message","arguments":{"peer":"colleague","type":"note","body":"request"}}}`
	// Pair grants are not bypassed by the plugin allowlist.
	w := rpcDo(bridge, "Bearer a", send)
	if !strings.Contains(w.Body.String(), `"isError":true`) {
		t.Fatal(w.Body.String())
	}
	for id, st := range stores {
		code := "fixture-code-" + id
		if err := st.CreateInvite(ctx, auth.Hash(code), "p_bot", []string{"messages"}, nil, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AcceptInvite(ctx, auth.Hash(code), "p_dot", []string{"messages"}, nil); err != nil {
			t.Fatal(err)
		}
		// Same IDs in distinct relay DBs must never collide in event state.
		if err := st.InsertMessage(ctx, &store.Message{From: "p_bot", To: "p_dot", Type: "note", Body: "reply-for-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a", "b"} {
		w = rpcDo(bridge, "Bearer "+id, send)
		if strings.Contains(w.Body.String(), `"isError":true`) {
			t.Fatal(w.Body.String())
		}
		w = rpcDo(bridge, "Bearer "+id, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_inbox","arguments":{}}}`)
		if !strings.Contains(w.Body.String(), "reply-for-"+id) {
			t.Fatal(w.Body.String())
		}
	}
	accts := []Account{accounts["Bearer a"], accounts["Bearer b"]}
	engine, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), accts, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	// Deterministic test transport only. Production always validates public HTTPS.
	delivered := map[string]string{}
	var deliveredMu sync.Mutex
	engine.client = &http.Client{Transport: eventTransport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		response := "{}"
		if v["type"] == "verification" {
			response = string(b)
		} else {
			deliveredMu.Lock()
			delivered[r.URL.Path] = string(b)
			deliveredMu.Unlock()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: http.Header{}}, nil
	})}
	for _, a := range accts {
		p, _ := json.Marshal(map[string]any{"name": "message.created", "arguments": map[string]string{"sender": "p_bot"}, "delivery": map[string]string{"mode": "webhook", "url": "https://callback.example/" + a.ID, "secret": eventSecret()}})
		if _, rpcErr := engine.Call(ctx, a, "events/subscribe", p); rpcErr != nil {
			t.Fatal(rpcErr)
		}
	}
	if err := engine.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if !strings.Contains(delivered["/"+id], "reply-for-"+id) {
			t.Fatal(delivered)
		}
	}
	if err := stores["a"].RevokeGrant(ctx, "p_bot", "p_dot"); err != nil {
		t.Fatal(err)
	}
	w = rpcDo(bridge, "Bearer a", send)
	if !strings.Contains(w.Body.String(), `"isError":true`) {
		t.Fatal("revoked send allowed", w.Body.String())
	}
}

type multiFixtureRelay struct{ relays map[string]*HTTPRelay }

func (m multiFixtureRelay) Inbox(ctx context.Context, a Account, n int64, l int) (InboxPage, error) {
	return m.relays[a.ID].Inbox(ctx, a, n, l)
}
func (m multiFixtureRelay) Send(ctx context.Context, a Account, to string, in SendInput) (json.RawMessage, error) {
	return m.relays[a.ID].Send(ctx, a, to, in)
}
func (m multiFixtureRelay) Grants(ctx context.Context, a Account) (json.RawMessage, error) {
	return m.relays[a.ID].Grants(ctx, a)
}
func (m multiFixtureRelay) CanReceive(ctx context.Context, a Account, from string) (bool, error) {
	return m.relays[a.ID].CanReceive(ctx, a, from)
}

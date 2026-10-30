package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type rpcAuth struct{ accounts map[string]Account }

func (a rpcAuth) Authenticate(r *http.Request) (Account, error) {
	v, ok := a.accounts[r.Header.Get("Authorization")]
	if !ok {
		return Account{}, errors.New("denied")
	}
	return v, nil
}

type rpcRelay struct {
	sent []string
	fail error
}

func (r *rpcRelay) Inbox(_ context.Context, a Account, _ int64, _ int) (InboxPage, error) {
	return InboxPage{Messages: []Message{{ID: 1, From: "p_friend", To: a.PeerID, Body: a.ID}, {ID: 2, From: "p_stranger", To: a.PeerID}}, NextSince: 2}, nil
}
func (r *rpcRelay) Grants(_ context.Context, a Account) (json.RawMessage, error) {
	return json.Marshal(map[string]any{"grants": []relayGrant{{Owner: a.PeerID, Grantee: "p_friend", Scopes: []string{"messages"}}, {Owner: "p_friend", Grantee: a.PeerID, Scopes: []string{"messages"}}}})
}
func (r *rpcRelay) CanReceive(context.Context, Account, string) (bool, error) { return true, nil }
func (r *rpcRelay) Send(_ context.Context, a Account, to string, in SendInput) (json.RawMessage, error) {
	r.sent = append(r.sent, a.ID+":"+to)
	if r.fail != nil {
		return nil, r.fail
	}
	return json.Marshal(Message{ID: 3, From: a.PeerID, To: to, Body: in.Body})
}
func rpcTestServer() (*Server, *rpcRelay) {
	relay := &rpcRelay{}
	return &Server{Auth: rpcAuth{map[string]Account{"Bearer a": {ID: "a", PeerID: "p_a", Peers: map[string]string{"friend": "p_friend"}}, "Bearer b": {ID: "b", PeerID: "p_b", Peers: map[string]string{"friend": "p_friend"}}}}, Relay: relay, ResourceURL: "https://mcp.example/mcp", Challenge: `Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp"`}, relay
}
func rpcDo(s *Server, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://mcp.example/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestRPCIsolationAndInputValidation(t *testing.T) {
	s, r := rpcTestServer()
	for _, account := range []string{"a", "b"} {
		w := rpcDo(s, "Bearer "+account, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_inbox","arguments":{}}}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"to":"p_`+account+`"`) || strings.Contains(w.Body.String(), "p_stranger") {
			t.Fatal(w.Body.String())
		}
	}
	cases := []string{
		`{"name":"send_message","arguments":{"peer":"p_other","type":"note","body":"hi"}}`,
		`{"name":"send_message","arguments":{"peer":"friend","type":"note","body":"hi","account_id":"b"}}`,
		`{"name":"send_message","arguments":{"peer":"friend","type":"INVALID","body":"hi"}}`,
		`{"name":"send_message","arguments":{"peer":"friend","type":"note","body":"` + strings.Repeat("x", 4097) + `"}}`,
	}
	for _, params := range cases {
		rpcDo(s, "Bearer a", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
	}
	if len(r.sent) != 0 {
		t.Fatal("invalid calls performed writes")
	}
	valid := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_message","arguments":{"peer":"friend","type":"note","body":"hi"}}}`
	rpcDo(s, "Bearer b", valid)
	if len(r.sent) != 1 || r.sent[0] != "b:p_friend" {
		t.Fatal(r.sent)
	}
	r.fail = &RelayError{Kind: "transport", Ambiguous: true}
	w := rpcDo(s, "Bearer a", valid)
	if !strings.Contains(w.Body.String(), "do not automatically retry") || len(r.sent) != 2 {
		t.Fatal(w.Body.String(), r.sent)
	}
}
func TestRPCTransportAndDescriptors(t *testing.T) {
	s, r := rpcTestServer()
	w := rpcDo(s, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal(w.Code)
	}
	w = rpcDo(s, "Bearer a", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if strings.Contains(w.Body.String(), `"required":null`) {
		t.Fatal("invalid JSON schema", w.Body.String())
	}
	w = rpcDo(s, "Bearer a", `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)
	if !strings.Contains(w.Body.String(), ProtocolVersion) || strings.Contains(w.Body.String(), `"events"`) {
		t.Fatal(w.Body.String())
	}
	// Notifications never perform writes, even when they name a valid tool.
	rpcDo(s, "Bearer a", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"send_message","arguments":{"peer":"friend","type":"note","body":"hi"}}}`)
	if len(r.sent) != 0 {
		t.Fatal("notification performed write")
	}
	req := httptest.NewRequest("POST", "https://mcp.example/mcp", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	req = httptest.NewRequest("GET", "https://mcp.example/.well-known/oauth-protected-resource/mcp", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = rpcDo(s, "Bearer a", strings.Repeat("x", maxRPCBytes+1))
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}

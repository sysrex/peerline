package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestRelayBindingACLAndSend(t *testing.T) {
	t.Setenv("TEST_RELAY_KEY", "key-a")
	posts := 0
	wrongIdentity := false
	reverseOnly := false
	failSend := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key-a" {
			t.Error("wrong key")
		}
		switch r.URL.Path {
		case "/v1/me":
			if wrongIdentity {
				w.Write([]byte(`{"peer_id":"peer-other"}`))
			} else {
				w.Write([]byte(`{"peer_id":"peer-a"}`))
			}
		case "/v1/grants":
			gs := []relayGrant{{Owner: "peer-a", Grantee: "peer-b", Scopes: []string{"messages"}}}
			if !reverseOnly {
				gs = append(gs, relayGrant{Owner: "peer-b", Grantee: "peer-a", Scopes: []string{"messages"}})
			}
			json.NewEncoder(w).Encode(map[string]any{"grants": gs})
		case "/v1/peers/peer-b/messages":
			posts++
			if failSend {
				w.WriteHeader(500)
				w.Write([]byte(`secret key-a content`))
				return
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"id":1,"from":"peer-a","to":"peer-b","type":"text","body":"hello","created_at":"2026-01-01T00:00:00Z"}`))
		case "/v1/inbox":
			w.Write([]byte(`{"messages":[{"id":1,"from":"peer-b","to":"peer-a","type":"text","body":"hello","created_at":"2026-01-01T00:00:00Z"}],"next_since":1}`))
		default:
			t.Error("unexpected path", r.URL.Path)
		}
	}))
	defer srv.Close()
	relay := NewHTTPRelay(true)
	relay.client = srv.Client()
	a := Account{ID: "a", PeerID: "peer-a", APIKeyEnv: "TEST_RELAY_KEY", RelayURL: srv.URL, Peers: map[string]string{"bob": "peer-b"}}
	ctx := context.Background()
	if _, err := relay.Send(ctx, a, "peer-b", SendInput{Type: "text", Body: "hello"}); err != nil {
		t.Fatal(err)
	}
	page, err := relay.Inbox(ctx, a, 0, 10)
	if err != nil || len(page.Messages) != 1 {
		t.Fatal(err)
	}
	reverseOnly = true
	if _, err := relay.Send(ctx, a, "peer-b", SendInput{Type: "text", Body: "hello"}); err == nil {
		t.Fatal("reverse grant authorized send")
	}
	if posts != 1 {
		t.Fatal("unauthorized send reached relay")
	}
	ok, err := relay.CanReceive(ctx, a, "peer-b")
	if err != nil || !ok {
		t.Fatal("receive direction incorrect", err)
	}
	wrongIdentity = true
	if _, err := relay.Grants(ctx, a); err == nil {
		t.Fatal("wrong key binding accepted")
	}
	wrongIdentity = false
	reverseOnly = false
	failSend = true
	_, err = relay.Send(ctx, a, "peer-b", SendInput{Type: "text", Body: "hello"})
	var re *RelayError
	if !errors.As(err, &re) || !re.Ambiguous || re.Status != 500 || strings.Contains(err.Error(), "key-a") || posts != 2 {
		t.Fatalf("unsafe failure: %+v posts=%d", err, posts)
	}
}
func TestSafeClientBlocksPrivateAndRedirect(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::ffff:127.0.0.1", "2001:db8::1", "64:ff9b::a00:1", "fec0::1", "::a00:1", "100::1", "2001:4860:4860::8888%eth0"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatal("allowed", ip)
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) || !publicIP(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("public address blocked")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("private endpoint reached") }))
	defer srv.Close()
	if _, err := NewSafeHTTPClient(false).Get(srv.URL); err == nil {
		t.Fatal("private target allowed")
	}
	c := NewSafeHTTPClient(true)
	if c.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect allowed")
	}
	for _, u := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?token=x", "https://example.com#fragment"} {
		if _, err := validateHTTPSURL(u); err == nil {
			t.Fatal("invalid URL accepted")
		}
	}
}

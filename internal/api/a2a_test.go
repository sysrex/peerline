package api

import (
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/pair"
)

func TestAgentCardDiscoveryAndGrant(t *testing.T) {
	srv := newServer(t, Config{})
	anon := &client{t: t, srv: srv}
	resp, body := anon.do("GET", "/.well-known/agent-card.json", nil, nil)
	want(t, resp, body, 200)
	if strings.Contains(string(body), "p_") || !strings.Contains(string(body), "relay-message") {
		t.Fatalf("public card: %s", body)
	}
	resp, body = anon.do("GET", "/.well-known/agent-card.json", nil, map[string]string{"A2A-Version": "0.3"})
	want(t, resp, body, 400)

	a := register(t, srv, "alice")
	b := register(t, srv, "bob")
	c := register(t, srv, "carol")
	resp, body = b.do("GET", "/a2a/"+a.id+"/agent-card.json", nil, nil)
	want(t, resp, body, 404)
	resp, missing := b.do("GET", "/a2a/p_does_not_exist/agent-card.json", nil, nil)
	want(t, resp, missing, 404)
	if string(body) != string(missing) {
		t.Fatalf("unpaired %s unknown %s", body, missing)
	}
	resp, body = anon.do("GET", "/a2a/"+a.id+"/agent-card.json", nil, nil)
	want(t, resp, body, 401)

	pairUp(t, a, b, []string{"messages"}, nil, nil)
	resp, body = b.do("GET", "/a2a/"+a.id+"/agent-card.json", nil, nil)
	want(t, resp, body, 404)

	pairUp(t, a, c, []string{"a2a", "messages"}, nil, nil)
	resp, body = c.do("GET", "/a2a/"+a.id+"/agent-card.json", nil, nil)
	want(t, resp, body, 200)
	if !strings.Contains(string(body), `"tenant":"`+a.id+`"`) || !strings.Contains(string(body), "relay-message") {
		t.Fatalf("peer card: %s", body)
	}
	resp, body = c.do("GET", "/a2a/"+a.id+"/agent-card.json", nil, map[string]string{"A2A-Version": "1.0"})
	want(t, resp, body, 200)
}

func TestA2AScopeDoesNotChangeExistingGrants(t *testing.T) {
	scopes, bags, err := pair.Normalize([]string{"messages"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 || scopes[0] != "messages" || len(bags) != 0 {
		t.Fatalf("scopes %v bags %v", scopes, bags)
	}
	if _, _, err := pair.Normalize([]string{"nope"}, nil); err == nil {
		t.Fatal("unknown scope accepted")
	}
	scopes, _, err = pair.Normalize([]string{"a2a", "messages"}, nil)
	if err != nil || len(scopes) != 2 {
		t.Fatalf("a2a scope %v %v", scopes, err)
	}
}

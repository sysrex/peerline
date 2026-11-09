package a2a

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicCardHasNoPeer(t *testing.T) {
	raw, err := json.Marshal(PublicCard("https://relay.example"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, needle := range []string{"p_", "peer_id", "tenant"} {
		if strings.Contains(s, needle) {
			t.Fatalf("public card contains %q: %s", needle, s)
		}
	}
	for _, needle := range []string{`"protocolVersion":"1.0"`, `"protocolBinding":"JSONRPC"`, `"streaming":false`, "relay-message", "https://relay.example/a2a"} {
		if !strings.Contains(s, needle) {
			t.Fatalf("missing %s in %s", needle, s)
		}
	}
	if !SupportedVersion("") || !SupportedVersion("1.0") || SupportedVersion("0.3") {
		t.Fatal("version gate")
	}
}

func TestPeerCardNamesTenant(t *testing.T) {
	raw, _ := json.Marshal(PeerCard("https://relay.example", "p_bob", true))
	if !strings.Contains(string(raw), `"tenant":"p_bob"`) || !strings.Contains(string(raw), "relay-message") {
		t.Fatalf("%s", raw)
	}
}

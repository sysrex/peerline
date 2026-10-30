package pair

import (
	"strings"
	"testing"
)

var pepper = []byte("test-pepper")
var nonce = []byte("0123456789abcdef")

func code(scopes ...string) string {
	return Code(pepper, "pub1", "p_inv", "p_cl", nonce, scopes, nil, nil, nil)
}

func TestCodeKnownAnswer(t *testing.T) {
	if got := code("messages"); got != "43OC-LJAE" {
		t.Fatalf("got %s", got)
	}
}

func TestCodeBindsOfferAndIsStable(t *testing.T) {
	if code("messages") == code("messages", "bags:read") {
		t.Fatal("offer not bound")
	}
	if code("messages") != code("messages") {
		t.Fatal("not deterministic")
	}
	if Code(pepper, "pub1", "p_inv", "p_other", nonce, []string{"messages"}, nil, nil, nil) == code("messages") {
		t.Fatal("claimant not bound")
	}
}

func TestCodeMatchesNormalisation(t *testing.T) {
	c := code("messages")
	if len(c) != 9 || c[4] != '-' {
		t.Fatalf("format %q", c)
	}
	lower := " " + strings.ToLower(c[:4]) + " " + c[5:] + " "
	if !CodeMatches(c, lower) || !CodeMatches(c, c[:4]+c[5:]) {
		t.Fatal("normalisation failed")
	}
	if CodeMatches(c, "AAAA-AAAA") || CodeMatches(c, "") {
		t.Fatal("wrong code matched")
	}
}

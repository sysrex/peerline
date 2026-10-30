package pair

import (
	"testing"

	"github.com/sysrex/peerline/internal/store"
)

func TestAllows(t *testing.T) {
	if Allows(nil, ScopeMessages, "") {
		t.Fatal("nil grant must deny")
	}
	g := &store.Grant{Scopes: []string{ScopeMessages, ScopeBagsRead}, Bags: []string{"notes"}}
	if !Allows(g, ScopeMessages, "") || !Allows(g, ScopeBagsRead, "notes") {
		t.Fatal("should allow")
	}
	if Allows(g, ScopeBagsRead, "other") || Allows(g, ScopeBagsWrite, "notes") {
		t.Fatal("should deny")
	}
}

func TestNormalize(t *testing.T) {
	sc, bg, err := Normalize([]string{"bags:read", "messages", "messages"}, []string{"b", "a"})
	if err != nil || len(sc) != 2 || bg[0] != "a" {
		t.Fatal(sc, bg, err)
	}
	if _, _, err := Normalize([]string{"root"}, nil); err == nil {
		t.Fatal("unknown scope")
	}
}

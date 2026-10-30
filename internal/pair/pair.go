// Package pair defines scopes and the deny-all authorization checks used
// between paired peers. A grant is directional: owner lets grantee act on
// the owner's resources (inbox, bags) within listed scopes and bag names.
package pair

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/sysrex/peerline/internal/store"
)

const (
	ScopeMessages  = "messages"
	ScopeBagsRead  = "bags:read"
	ScopeBagsWrite = "bags:write"
)

var validScopes = []string{ScopeMessages, ScopeBagsRead, ScopeBagsWrite}

var bagNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidBagName reports whether name is an acceptable bag name.
func ValidBagName(name string) bool { return bagNameRE.MatchString(name) }

// Normalize validates and de-duplicates scopes and bag names.
// Bag names without a bags:* scope are rejected to avoid confusing grants.
func Normalize(scopes, bags []string) ([]string, []string, error) {
	var sc, bg []string
	for _, s := range scopes {
		if !slices.Contains(validScopes, s) {
			return nil, nil, fmt.Errorf("unknown scope %q", s)
		}
		if !slices.Contains(sc, s) {
			sc = append(sc, s)
		}
	}
	for _, b := range bags {
		if !ValidBagName(b) {
			return nil, nil, fmt.Errorf("invalid bag name %q", b)
		}
		if !slices.Contains(bg, b) {
			bg = append(bg, b)
		}
	}
	hasBagScope := slices.Contains(sc, ScopeBagsRead) || slices.Contains(sc, ScopeBagsWrite)
	if len(bg) > 0 && !hasBagScope {
		return nil, nil, fmt.Errorf("bags listed without bags:read or bags:write scope")
	}
	if hasBagScope && len(bg) == 0 {
		return nil, nil, fmt.Errorf("bags scope requires an explicit bag allowlist")
	}
	slices.Sort(sc)
	slices.Sort(bg)
	return sc, bg, nil
}

// Allows reports whether g permits scope (and, for bag scopes, the named bag).
// A nil grant denies everything.
func Allows(g *store.Grant, scope, bag string) bool {
	if g == nil || !slices.Contains(g.Scopes, scope) {
		return false
	}
	if scope == ScopeBagsRead || scope == ScopeBagsWrite {
		return slices.Contains(g.Bags, bag)
	}
	return true
}

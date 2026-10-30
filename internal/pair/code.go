package pair

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
)

const codeDomain = "peerline/code/v1"

// Code derives the 8-character short code the claimant reads to the inviter's
// owner. The pepper is a server secret; nonce is random per claim, so the code
// cannot be precomputed from the link. Every field of the offer is bound.
func Code(pepper []byte, publicID, inviterID, claimantID string, nonce []byte, scopes, bags, backScopes, backBags []string) string {
	offer := sha256.Sum256([]byte(strings.Join([]string{
		strings.Join(scopes, ","), strings.Join(bags, ","),
		strings.Join(backScopes, ","), strings.Join(backBags, ","),
	}, "|")))
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(codeDomain))
	for _, f := range [][]byte{[]byte(publicID), []byte(inviterID), []byte(claimantID), nonce, offer[:]} {
		m.Write([]byte{0})
		m.Write(f)
	}
	s := base32.StdEncoding.EncodeToString(m.Sum(nil))[:8]
	return s[:4] + "-" + s[4:]
}

// NormalizeCode upper-cases and strips hyphens and spaces from typed input.
func NormalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
}

// CodeMatches compares a typed code to the expected one in constant time.
func CodeMatches(expected, typed string) bool {
	return subtle.ConstantTimeCompare([]byte(NormalizeCode(expected)), []byte(NormalizeCode(typed))) == 1
}

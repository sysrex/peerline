package pair

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

const codeDomain = "peerline/code/v1"
const offerDigestDomain = "peerline/offer-digest/v1"

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

// OfferDigest computes a hex digest covering the full offer: both directions' scopes/bags,
// claimant peer_id, invite public_id, and any existing grants being replaced.
func OfferDigest(publicID, inviterID, claimantID string, scopes, bags, backScopes, backBags []string, existingInviterScopes, existingInviterBags, existingClaimantScopes, existingClaimantBags []string) string {
	h := sha256.New()
	h.Write([]byte(offerDigestDomain))
	for _, f := range []string{publicID, inviterID, claimantID} {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	for _, part := range [][]string{scopes, bags, backScopes, backBags, existingInviterScopes, existingInviterBags, existingClaimantScopes, existingClaimantBags} {
		h.Write([]byte{0})
		h.Write([]byte(strings.Join(part, ",")))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// OfferDigestMatches compares expected and provided digests in constant time.
func OfferDigestMatches(expected, provided string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

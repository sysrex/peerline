// Package auth handles peer registration keys and Bearer authentication.
//
// API keys are 256-bit random secrets shown to the caller exactly once.
// Only a SHA-256 hash is stored; because keys are high-entropy, a fast hash
// is sufficient (no password-stretching needed) and enables indexed lookup.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	KeyPrefix         = "pl_"
	InvitePrefix      = "inv_"
	PairingPrefix     = "pair_"
	EmailVerifyPrefix = "eml_"
)

// NewID returns a random peer id like "p_<16 hex>".
func NewID() string { return "p_" + randHex(8) }

// NewKey returns a fresh plaintext API key.
func NewKey() string { return KeyPrefix + randB64(32) }

// NewSecret returns a random URL-safe secret (used for invite codes).
func NewSecret(prefix string) string { return prefix + randB64(24) }

// NewPairingToken returns a random pairing token.
func NewPairingToken() string { return PairingPrefix + randB64(24) }

// Hash returns the hex SHA-256 of a secret.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}
func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }
func randB64(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

// BearerToken extracts the token from an Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	t := strings.TrimSpace(h[len(p):])
	return t, t != ""
}

type ctxKey struct{}

// WithPeer stores the authenticated peer id in ctx.
func WithPeer(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// PeerID returns the authenticated peer id from ctx.
func PeerID(ctx context.Context) string { s, _ := ctx.Value(ctxKey{}).(string); return s }

// Lookup resolves a key hash to a peer id.
type Lookup func(ctx context.Context, keyHash string) (peerID string, err error)

// Middleware enforces Bearer auth; unauthenticated requests get 401.
func Middleware(lookup Lookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := BearerToken(r)
		if !ok || !strings.HasPrefix(tok, KeyPrefix) {
			unauthorized(w)
			return
		}
		id, err := lookup(r.Context(), Hash(tok))
		if err != nil || id == "" {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPeer(r.Context(), id)))
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="peerline"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized"}`))
}

// ConstantEqual compares two secrets in constant time.
func ConstantEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

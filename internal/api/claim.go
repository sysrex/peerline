package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

// Claim states returned to clients.
const (
	claimStateClaimed  = "claimed"
	claimStateActive   = "active"
	claimStateDeclined = "declined"
	maxCodeFails       = 3
)

// ClaimInvite is a confirm-mode invite as the claim handlers see it.
type ClaimInvite struct {
	PublicID, Inviter, State string
	Claimant, ClaimantName   string
	Scopes, Bags             []string
	BackScopes, BackBags     []string
	Nonce                    []byte
}

// ClaimStore is the persistence the claim/confirm handlers need; the store's
// confirm-mode layer provides it. Every method returns store.ErrNotFound for
// unknown, expired, foreign or wrong-state invites, so handlers cannot leak which.
type ClaimStore interface {
	// ClaimByToken claims an offered invite for claimant, or returns the existing
	// claim if claimant already holds it. Self-claim is ErrNotFound.
	ClaimByToken(ctx context.Context, tokenHash, claimant string, nonce []byte, backScopes, backBags []string) (*ClaimInvite, error)
	// ClaimStatus returns the invite only to its claimant.
	ClaimStatus(ctx context.Context, tokenHash, claimant string) (*ClaimInvite, error)
	// InviterView returns the invite only to its inviter.
	InviterView(ctx context.Context, publicID, inviter string) (*ClaimInvite, error)
	// ConfirmClaim runs check on a claimed invite in one transaction. On true it
	// writes the grants and activates it; on false it counts a failure and declines
	// at maxCodeFails. Returns the resulting state.
	ConfirmClaim(ctx context.Context, publicID, inviter string, maxFails int, check func(*ClaimInvite) bool) (string, error)
	DeclineClaim(ctx context.Context, publicID, inviter string) error
}

// SetClaimStore enables the claim/confirm routes. Call before Handler.
func (s *Server) SetClaimStore(c ClaimStore) { s.claims = c }

// claimRoutes registers on the outer mux because the unauthenticated
// POST /v1/pairing/{token} would otherwise match before the /v1/ subtree.
func (s *Server) claimRoutes(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	if s.claims == nil {
		return
	}
	h := wrap(s.claimHandlers())
	for _, p := range []string{"POST /v1/pairing/claim", "POST /v1/pairing/status", "GET /v1/invites/{public_id}",
		"POST /v1/invites/{public_id}/confirm", "POST /v1/invites/{public_id}/decline"} {
		mux.Handle(p, h)
	}
}

func (s *Server) claimHandlers() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/pairing/claim", s.claim)
	m.HandleFunc("POST /v1/pairing/status", s.claimStatus)
	m.HandleFunc("GET /v1/invites/{public_id}", s.rateLimitAuth(s.inviteView))
	m.HandleFunc("POST /v1/invites/{public_id}/confirm", s.rateLimitAuth(s.confirmClaim))
	m.HandleFunc("POST /v1/invites/{public_id}/decline", s.rateLimitAuth(s.declineClaim))
	return m
}

func (s *Server) claimCode(c *ClaimInvite) string {
	return pair.Code(s.cfg.CodePepper, c.PublicID, c.Inviter, c.Claimant, c.Nonce, c.Scopes, c.Bags, c.BackScopes, c.BackBags)
}

// claimBody charges the per-IP pairing budget before any lookup, so a 429 never depends on the token.
func (s *Server) claimBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if !s.lim.pairLim.Allow(rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return false
	}
	return decode(w, r, v)
}

// claimResult maps store errors; every ErrNotFound is the same 404.
func (s *Server) claimResult(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	default:
		s.internal(w, err)
	}
	return false
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token  string   `json:"token"`
		Scopes []string `json:"scopes"`
		Bags   []string `json:"bags"`
	}
	if !s.claimBody(w, r, &in) {
		return
	}
	sc, bg, err := pair.Normalize(in.Scopes, in.Bags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := s.claims.ClaimByToken(r.Context(), auth.Hash(in.Token), auth.PeerID(r.Context()), auth.NewNonce(), sc, bg)
	if !s.claimResult(w, err) {
		return
	}
	s.log.Info("invite_claimed", "public_id", c.PublicID, "inviter", c.Inviter, "claimant", c.Claimant)
	writeJSON(w, http.StatusOK, map[string]any{
		"public_id": c.PublicID, "inviter_id": c.Inviter, "state": c.State,
		"scopes": c.Scopes, "bags": c.Bags, "code": s.claimCode(c),
	})
}

func (s *Server) claimStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !s.claimBody(w, r, &in) {
		return
	}
	c, err := s.claims.ClaimStatus(r.Context(), auth.Hash(in.Token), auth.PeerID(r.Context()))
	if !s.claimResult(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_id": c.PublicID, "state": c.State})
}

// inviteView never includes the code: the inviter must obtain it from the claimant's owner.
func (s *Server) inviteView(w http.ResponseWriter, r *http.Request) {
	c, err := s.claims.InviterView(r.Context(), r.PathValue("public_id"), auth.PeerID(r.Context()))
	if !s.claimResult(w, err) {
		return
	}
	out := map[string]any{"public_id": c.PublicID, "state": c.State}
	if c.Claimant != "" {
		out["claimant"] = map[string]any{"peer_id": c.Claimant, "untrusted": map[string]string{"name": sanitizeInviterName(c.ClaimantName)}}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) confirmClaim(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PeerID string `json:"peer_id"`
		Code   string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	pub := r.PathValue("public_id")
	state, err := s.claims.ConfirmClaim(r.Context(), pub, auth.PeerID(r.Context()), maxCodeFails, func(c *ClaimInvite) bool {
		idOK := subtle.ConstantTimeCompare([]byte(in.PeerID), []byte(c.Claimant)) == 1
		return pair.CodeMatches(s.claimCode(c), in.Code) && idOK
	})
	if !s.claimResult(w, err) {
		return
	}
	s.log.Info("invite_confirm", "public_id", pub, "inviter", auth.PeerID(r.Context()), "state", state)
	if state == claimStateActive {
		writeJSON(w, http.StatusOK, map[string]string{"state": state})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer_id or code mismatch", "state": state})
}

func (s *Server) declineClaim(w http.ResponseWriter, r *http.Request) {
	if !s.claimResult(w, s.claims.DeclineClaim(r.Context(), r.PathValue("public_id"), auth.PeerID(r.Context()))) {
		return
	}
	s.log.Info("invite_declined", "public_id", r.PathValue("public_id"), "inviter", auth.PeerID(r.Context()))
	writeJSON(w, http.StatusOK, map[string]string{"state": claimStateDeclined})
}

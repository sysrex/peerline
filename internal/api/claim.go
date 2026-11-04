package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

// Claim states returned to clients.
const (
	claimStateClaimed  = store.ClaimClaimed
	claimStateActive   = store.ClaimActive
	claimStateDeclined = store.ClaimDeclined
	maxCodeFails       = 3
)

// ClaimInvite is a confirm-mode invite as the claim handlers see it.
type ClaimInvite = store.Claim

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
	// ConfirmClaim runs check on a claimed invite in one transaction. CheckOK writes
	// the grants and activates it; CheckCodeFail/CheckPeerIDFail count toward maxFails;
	// CheckDigestStale does not count. Returns the resulting state and optionally a fresh claim.
	// claimantPeerID is used for constant-time comparison on active replay.
	ConfirmClaim(ctx context.Context, publicID, inviter string, claimantPeerID string, maxFails int, check func(*ClaimInvite) (store.CheckResult, *ClaimInvite)) (string, *ClaimInvite, error)
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

func (s *Server) offerDigest(c *ClaimInvite) string {
	var eis, eib, ecs, ecb []string
	if c.Replaces != nil {
		if c.Replaces.InviterToClaimant != nil {
			eis, eib = c.Replaces.InviterToClaimant.Scopes, c.Replaces.InviterToClaimant.Bags
		}
		if c.Replaces.ClaimantToInviter != nil {
			ecs, ecb = c.Replaces.ClaimantToInviter.Scopes, c.Replaces.ClaimantToInviter.Bags
		}
	}
	return pair.OfferDigest(c.PublicID, c.Inviter, c.Claimant, c.Scopes, c.Bags, c.BackScopes, c.BackBags, eis, eib, ecs, ecb)
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

// buildInviterViewJSON builds the JSON representation of a claimed invite for the inviter,
// including claimant details, offer_digest, the offered scopes/bags in both directions,
// and (for claimed state only) any existing grants being replaced. Used by both GET
// /v1/invites/{public_id} and the 409 stale-digest response.
func (s *Server) buildInviterViewJSON(c *ClaimInvite) map[string]any {
	out := map[string]any{
		"public_id":    c.PublicID,
		"state":        c.State,
		"claimant":     map[string]any{"peer_id": c.Claimant, "untrusted": map[string]string{"name": sanitizeInviterName(c.ClaimantName)}},
		"offer_digest": s.offerDigest(c),
		"offer": map[string]any{
			"inviter_to_claimant": map[string]any{"scopes": c.Scopes, "bags": c.Bags},
			"claimant_to_inviter": map[string]any{"scopes": c.BackScopes, "bags": c.BackBags},
		},
	}
	// Show replaces only for claimed invites (not active), since after activation it would show the just-written grants
	if c.State == store.ClaimClaimed && c.Replaces != nil {
		replaces := map[string]any{}
		if c.Replaces.InviterToClaimant != nil {
			replaces["inviter_to_claimant"] = map[string]any{
				"scopes": c.Replaces.InviterToClaimant.Scopes,
				"bags":   c.Replaces.InviterToClaimant.Bags,
			}
		}
		if c.Replaces.ClaimantToInviter != nil {
			replaces["claimant_to_inviter"] = map[string]any{
				"scopes": c.Replaces.ClaimantToInviter.Scopes,
				"bags":   c.Replaces.ClaimantToInviter.Bags,
			}
		}
		out["replaces"] = replaces
	}
	return out
}

// inviteView never includes the code: the inviter must obtain it from the claimant's owner.
func (s *Server) inviteView(w http.ResponseWriter, r *http.Request) {
	c, err := s.claims.InviterView(r.Context(), r.PathValue("public_id"), auth.PeerID(r.Context()))
	if !s.claimResult(w, err) {
		return
	}
	out := map[string]any{"public_id": c.PublicID, "state": c.State}
	if c.Claimant != "" {
		out = s.buildInviterViewJSON(c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) confirmClaim(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PeerID      string `json:"peer_id"`
		Code        string `json:"code"`
		OfferDigest string `json:"offer_digest"`
	}
	if !decode(w, r, &in) {
		return
	}

	// Validate offer_digest is present and well-formed (64 hex chars) before evaluating code
	if in.OfferDigest == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "offer_digest required: GET /v1/invites/{public_id} and echo offer_digest",
		})
		return
	}
	if len(in.OfferDigest) != 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "offer_digest must be 64 hex characters",
		})
		return
	}
	for _, c := range in.OfferDigest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "offer_digest must be hex",
			})
			return
		}
	}

	pub := r.PathValue("public_id")
	// Normalize offer_digest to lowercase for comparison
	normalizedDigest := strings.ToLower(in.OfferDigest)

	state, freshClaim, err := s.claims.ConfirmClaim(r.Context(), pub, auth.PeerID(r.Context()), in.PeerID, maxCodeFails, func(c *ClaimInvite) (store.CheckResult, *ClaimInvite) {
		// Check digest FIRST, before evaluating code (prevents code oracle)
		// Use normalized (lowercase) digest for comparison
		digestOK := pair.OfferDigestMatches(s.offerDigest(c), normalizedDigest)
		if !digestOK {
			// Return c (already loaded in this transaction) for 409 response
			// DO NOT call InviterView here - it would open a second transaction and deadlock with SetMaxOpenConns(1)
			return store.CheckDigestStale, c
		}

		// Only check code and peer_id if digest matches
		idOK := subtle.ConstantTimeCompare([]byte(in.PeerID), []byte(c.Claimant)) == 1
		if !idOK {
			return store.CheckPeerIDFail, nil
		}

		codeOK := pair.CodeMatches(s.claimCode(c), in.Code)
		if !codeOK {
			return store.CheckCodeFail, nil
		}

		return store.CheckOK, nil
	})

	// Handle stale digest (does not count toward failures)
	if state == claimStateClaimed && freshClaim != nil {
		s.log.Info("invite_confirm_stale_digest", "public_id", pub, "inviter", auth.PeerID(r.Context()))
		resp := s.buildInviterViewJSON(freshClaim)
		resp["error"] = "offer changed: GET /v1/invites/{public_id} for current offer_digest"
		writeJSON(w, http.StatusConflict, resp)
		return
	}

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

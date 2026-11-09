package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

var signingKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s *Server) signingKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/me/signing-keys", s.rateLimitWrite(s.putSigningKey))
	mux.HandleFunc("DELETE /v1/me/signing-keys/{kid}", s.rateLimitWrite(s.deleteSigningKey))
	mux.HandleFunc("GET /v1/peers/{peer_id}/signing-keys", s.rateLimitAuth(s.listSigningKeys))
}

func (s *Server) putSigningKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		KID       string `json:"kid"`
		PubKey    string `json:"pubkey"`
		Signature string `json:"signature"`
		ValidFrom int64  `json:"valid_from"`
		ValidTo   int64  `json:"valid_to"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !signingKeyID.MatchString(in.KID) {
		writeErr(w, http.StatusBadRequest, "invalid kid")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(in.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "pubkey must be a raw Ed25519 public key")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		writeErr(w, http.StatusBadRequest, "invalid signature")
		return
	}
	validFrom := in.ValidFrom
	if validFrom == 0 {
		validFrom = s.clk.Now().Unix()
	}
	if in.ValidTo != 0 && in.ValidTo <= validFrom {
		writeErr(w, http.StatusBadRequest, "valid_to must be after valid_from")
		return
	}
	if !ed25519.Verify(pub, signingKeyRegistrationMessage(auth.PeerID(r.Context()), in.KID, validFrom), sig) {
		writeErr(w, http.StatusBadRequest, "proof of possession failed")
		return
	}
	me := auth.PeerID(r.Context())
	if s.signingKeyLim != nil && !s.signingKeyLim.Allow(me) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if err := s.st.RegisterSigningKey(r.Context(), me, in.KID, pub, validFrom, in.ValidTo); err != nil {
		if errors.Is(err, store.ErrSigningKeyExists) || errors.Is(err, store.ErrTooManySigningKeys) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		s.internal(w, err)
		return
	}
	sum := sha256.Sum256(pub)
	s.log.Info("signing_key.registered", "event", "signing_key.registered", "peer_id", me, "kid", in.KID, "pubkey_sha256", hex.EncodeToString(sum[:]))
	writeJSON(w, http.StatusCreated, map[string]any{
		"kid": in.KID, "pubkey": base64.StdEncoding.EncodeToString(pub),
		"valid_from": validFrom, "valid_to": in.ValidTo,
	})
}

func (s *Server) deleteSigningKey(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())
	kid := r.PathValue("kid")
	if err := s.st.RevokeSigningKey(r.Context(), me, kid, s.clk.Now().Unix()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "signing key not found")
			return
		}
		s.internal(w, err)
		return
	}
	s.log.Info("signing_key.revoked", "event", "signing_key.revoked", "peer_id", me, "kid", kid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())
	peerID := r.PathValue("peer_id")
	if me != peerID {
		g, err := s.st.GetGrant(r.Context(), peerID, me)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, err)
			return
		}
		if !pair.Allows(g, pair.ScopeMessages, "") {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
	}
	keys, err := s.st.ListSigningKeys(r.Context(), peerID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"kid": k.KID, "pubkey": base64.StdEncoding.EncodeToString(k.PubKey),
			"valid_from": k.ValidFrom, "valid_to": k.ValidTo,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func signingKeyRegistrationMessage(peerID, kid string, validFrom int64) []byte {
	return []byte(fmt.Sprintf("peerline-key-registration|%s|%s|%d", peerID, kid, validFrom))
}

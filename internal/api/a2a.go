package api

import (
	"errors"
	"net/http"

	"github.com/sysrex/peerline/internal/a2a"
	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

func (s *Server) a2aRoutes(public *http.ServeMux) {
	public.HandleFunc("GET /.well-known/agent-card.json", s.rateLimitGet(s.publicAgentCard))
	public.Handle("GET /a2a/{peer_id}/agent-card.json", s.authMiddleware(http.HandlerFunc(s.rateLimitAuth(s.peerAgentCard))))
}

func (s *Server) publicAgentCard(w http.ResponseWriter, r *http.Request) {
	if !a2a.SupportedVersion(r.Header.Get("A2A-Version")) {
		writeErr(w, http.StatusBadRequest, "version not supported")
		return
	}
	writeJSON(w, http.StatusOK, a2a.PublicCard(s.publicBase(r)))
}

func (s *Server) peerAgentCard(w http.ResponseWriter, r *http.Request) {
	if !a2a.SupportedVersion(r.Header.Get("A2A-Version")) {
		writeErr(w, http.StatusBadRequest, "version not supported")
		return
	}
	me := auth.PeerID(r.Context())
	peerID := r.PathValue("peer_id")
	g, err := s.st.GetGrant(r.Context(), peerID, me)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	if !pair.Allows(g, pair.ScopeA2A, "") || !pair.Allows(g, pair.ScopeMessages, "") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, a2a.PeerCard(s.publicBase(r), peerID, true))
}

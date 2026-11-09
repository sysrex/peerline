package api

import (
	"errors"
	"net/http"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/store"
)

func (s *Server) a2aTaskRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/a2a/tasks/{id}", s.rateLimitAuth(s.getA2ATask))
	mux.HandleFunc("PUT /v1/a2a/tasks/{id}", s.rateLimitWrite(s.answerA2ATask))
}

func (s *Server) getA2ATask(w http.ResponseWriter, r *http.Request) {
	task, err := s.st.GetA2ATask(r.Context(), r.PathValue("id"), auth.PeerID(r.Context()))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": task.ID, "context_id": task.ContextID, "state": task.State,
	})
}

func (s *Server) answerA2ATask(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State     string `json:"state"`
		Message   string `json:"message"`
		Artifacts string `json:"artifacts"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := s.st.AnswerA2ATask(r.Context(), r.PathValue("id"), auth.PeerID(r.Context()), in.State, in.Message, in.Artifacts)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if errors.Is(err, store.ErrA2ATerminal) || errors.Is(err, store.ErrA2ANotCancelable) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, store.ErrA2ATooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

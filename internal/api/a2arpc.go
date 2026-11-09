package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

func (s *Server) a2aRPCRoute(mux *http.ServeMux) {
	mux.Handle("POST /a2a", s.authMiddleware(http.HandlerFunc(s.a2aRPC)))
}

func (s *Server) a2aRPC(w http.ResponseWriter, r *http.Request) {
	if v := r.Header.Get("A2A-Version"); v != "" && v != "1.0" {
		writeJSONRPC(w, nil, nil, &jsonRPCError{Code: -32002, Message: "version not supported"})
		return
	}
	me := auth.PeerID(r.Context())
	if s.lim != nil && s.lim.msgLim != nil && !s.lim.msgLim.Allow(me) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	var req jsonRPCRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONRPC(w, nil, nil, &jsonRPCError{Code: -32600, Message: "invalid request"})
		return
	}
	result, rpcErr := s.dispatchA2A(r, me, req)
	if rpcErr == nil {
		rawReq, _ := json.Marshal(req.Params)
		rawRes, _ := json.Marshal(result)
		leaf, err := json.Marshal(map[string]string{
			"method": req.Method, "request_sha256": shortHash(rawReq), "response_sha256": shortHash(rawRes),
		})
		if err == nil {
			_ = s.st.NoteA2ACall(r.Context(), me, leaf)
		}
	}
	writeJSONRPC(w, req.ID, result, rpcErr)
}

func (s *Server) dispatchA2A(r *http.Request, me string, req jsonRPCRequest) (any, *jsonRPCError) {
	switch req.Method {
	case "SendMessage":
		return s.a2aSend(r, me, req.Params)
	case "GetTask":
		return s.a2aGet(r, me, req.Params)
	case "ListTasks":
		return s.a2aList(r, me)
	case "CancelTask":
		return s.a2aCancel(r, me, req.Params)
	default:
		return nil, &jsonRPCError{Code: -32601, Message: "method not found"}
	}
}

func (s *Server) a2aSend(r *http.Request, me string, params json.RawMessage) (any, *jsonRPCError) {
	var in struct {
		Tenant  string          `json:"tenant"`
		Message json.RawMessage `json:"message"`
	}
	if json.Unmarshal(params, &in) != nil || in.Tenant == "" || len(in.Message) == 0 {
		return nil, &jsonRPCError{Code: -32602, Message: "invalid params"}
	}
	if !s.a2aGranted(r, in.Tenant, me) {
		return nil, &jsonRPCError{Code: -32001, Message: "not found"}
	}
	if len(in.Message) > store.A2AMaxEnvelope {
		return nil, &jsonRPCError{Code: -32602, Message: "envelope too large"}
	}
	id, err := newTaskID()
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
	}
	if err := s.st.CreateA2ATask(r.Context(), id, id, me, in.Tenant, string(in.Message), "", 0); err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
	}
	msg := &store.Message{From: me, To: in.Tenant, Type: "a2a.message", Body: string(in.Message)}
	if err := s.st.InsertMessage(r.Context(), msg); err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
	}
	return map[string]any{"id": id, "state": "submitted", "contextId": id}, nil
}

func (s *Server) a2aGet(r *http.Request, me string, params json.RawMessage) (any, *jsonRPCError) {
	var in struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(params, &in) != nil || in.ID == "" {
		return nil, &jsonRPCError{Code: -32602, Message: "invalid params"}
	}
	task, err := s.st.GetA2ATask(r.Context(), in.ID, me)
	if err != nil {
		return nil, &jsonRPCError{Code: -32001, Message: "not found"}
	}
	return map[string]any{"id": task.ID, "state": task.State, "artifacts": task.Artifacts}, nil
}

func (s *Server) a2aList(r *http.Request, me string) (any, *jsonRPCError) {
	tasks, err := s.st.ListA2ATasks(r.Context(), me, 50)
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
	}
	out := make([]any, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, map[string]any{"id": t.ID, "state": t.State})
	}
	return map[string]any{"tasks": out}, nil
}

func (s *Server) a2aCancel(r *http.Request, me string, params json.RawMessage) (any, *jsonRPCError) {
	var in struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(params, &in) != nil || in.ID == "" {
		return nil, &jsonRPCError{Code: -32602, Message: "invalid params"}
	}
	err := s.st.AnswerA2ATask(r.Context(), in.ID, me, "canceled", "", "")
	if errors.Is(err, store.ErrNotFound) {
		return nil, &jsonRPCError{Code: -32001, Message: "not found"}
	}
	if errors.Is(err, store.ErrA2ANotCancelable) || errors.Is(err, store.ErrA2ATerminal) {
		return nil, &jsonRPCError{Code: -32003, Message: err.Error()}
	}
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
	}
	return map[string]any{"id": in.ID, "state": "canceled"}, nil
}

func (s *Server) a2aGranted(r *http.Request, owner, caller string) bool {
	g, err := s.st.GetGrant(r.Context(), owner, caller)
	if err != nil {
		return false
	}
	return pair.Allows(g, pair.ScopeA2A, "") && pair.Allows(g, pair.ScopeMessages, "")
}

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func newTaskID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "task_" + hex.EncodeToString(b[:]), nil
}

type jsonRPCRequest struct {
	ID     any             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSONRPC(w http.ResponseWriter, id, result any, rpcErr *jsonRPCError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	writeJSON(w, http.StatusOK, resp)
}

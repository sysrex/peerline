// Package api wires the HTTP routes for Peerline.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
)

const (
	MaxBagBytes      = 64 << 10
	maxJSONBytes     = 16 << 10
	defaultInviteTTL = 24 * time.Hour
	maxInviteTTL     = 7 * 24 * time.Hour
)

type Config struct {
	// RegisterToken, if non-empty, must be sent as X-Peerline-Register-Token to register.
	RegisterToken string
	MsgPerMinute  int
	MsgBurst      int
	Logger        *slog.Logger
}

type Server struct {
	st     *store.Store
	cfg    Config
	msgLim *msg.Limiter
	regLim *msg.Limiter
	log    *slog.Logger
}

func New(st *store.Store, cfg Config) *Server {
	if cfg.MsgPerMinute <= 0 {
		cfg.MsgPerMinute = 30
	}
	if cfg.MsgBurst <= 0 {
		cfg.MsgBurst = 10
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{st: st, cfg: cfg, log: cfg.Logger,
		msgLim: msg.NewLimiter(cfg.MsgPerMinute, cfg.MsgBurst),
		regLim: msg.NewLimiter(10, 5)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/register", s.register)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /v1/me", s.me)
	authed.HandleFunc("POST /v1/invites", s.createInvite)
	authed.HandleFunc("POST /v1/invites/accept", s.acceptInvite)
	authed.HandleFunc("GET /v1/grants", s.listGrants)
	authed.HandleFunc("DELETE /v1/grants/{peer_id}", s.revokeGrant)
	authed.HandleFunc("POST /v1/peers/{peer_id}/messages", s.sendMessage)
	authed.HandleFunc("GET /v1/inbox", s.inbox)
	authed.HandleFunc("GET /v1/bags/{name}", s.getBag)
	authed.HandleFunc("PUT /v1/bags/{name}", s.putBag)
	mux.Handle("/v1/", auth.Middleware(func(ctx context.Context, h string) (string, error) {
		p, err := s.st.PeerByKeyHash(ctx, h)
		if err != nil {
			return "", err
		}
		return p.ID, nil
	}, authed))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---- auth ----

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.regLim.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if s.cfg.RegisterToken != "" && !auth.ConstantEqual(r.Header.Get("X-Peerline-Register-Token"), s.cfg.RegisterToken) {
		writeErr(w, http.StatusForbidden, "registration token required")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "name required (max 64 chars)")
		return
	}
	id, key := auth.NewID(), auth.NewKey()
	if err := s.st.CreatePeer(r.Context(), id, in.Name, auth.Hash(key)); err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("peer registered", "peer_id", id)
	writeJSON(w, http.StatusCreated, map[string]string{
		"peer_id": id, "name": in.Name, "api_key": key,
		"note": "api_key is shown once; store it securely",
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"peer_id": auth.PeerID(r.Context())})
}

// ---- pairing ----

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scopes     []string `json:"scopes"`
		Bags       []string `json:"bags"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, bg, err := pair.Normalize(in.Scopes, in.Bags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(sc) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one scope required")
		return
	}
	ttl := defaultInviteTTL
	if in.TTLSeconds > 0 {
		ttl = min(time.Duration(in.TTLSeconds)*time.Second, maxInviteTTL)
	}
	code := auth.NewSecret("inv_")
	exp := time.Now().Add(ttl).UTC()
	if err := s.st.CreateInvite(r.Context(), auth.Hash(code), auth.PeerID(r.Context()), sc, bg, exp); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"code": code, "scopes": sc, "bags": bg, "expires_at": exp.Format(time.RFC3339),
		"note": "single use; share out of band with the peer you want to pair with",
	})
}

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code   string   `json:"code"`
		Scopes []string `json:"scopes"` // optional reciprocal grant to the inviter
		Bags   []string `json:"bags"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, bg, err := pair.Normalize(in.Scopes, in.Bags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	me := auth.PeerID(r.Context())
	g, err := s.st.AcceptInvite(r.Context(), auth.Hash(in.Code), me, sc, bg)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "invite invalid, used, or expired")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusBadRequest, "cannot accept your own invite")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	resp := map[string]any{"peer_id": g.Owner, "granted_to_you": g}
	if len(sc) > 0 {
		resp["granted_by_you"] = store.Grant{Owner: me, Grantee: g.Owner, Scopes: sc, Bags: bg}
	}
	s.log.Info("pairing accepted", "owner", g.Owner, "grantee", me)
	writeJSON(w, 200, resp)
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	gs, err := s.st.ListGrants(r.Context(), auth.PeerID(r.Context()))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"grants": gs})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	err := s.st.RevokeGrant(r.Context(), auth.PeerID(r.Context()), r.PathValue("peer_id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no grant to that peer")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- messages ----

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	me, to := auth.PeerID(r.Context()), r.PathValue("peer_id")
	g, err := s.st.GetGrant(r.Context(), to, me)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	// Same response for unknown and unpaired peers: no peer enumeration.
	if !pair.Allows(g, pair.ScopeMessages, "") {
		writeErr(w, http.StatusForbidden, "not permitted")
		return
	}
	if !s.msgLim.Allow(me) {
		w.Header().Set("Retry-After", "2")
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var in msg.Input
	if !decode(w, r, &in) {
		return
	}
	if err := in.Validate(); err != nil {
		code := http.StatusBadRequest
		if len(in.Body) > msg.MaxBodyBytes {
			code = http.StatusRequestEntityTooLarge
		}
		writeErr(w, code, err.Error())
		return
	}
	if in.ReplyTo != nil {
		ok, err := s.st.MessageVisible(r.Context(), *in.ReplyTo, me)
		if err != nil {
			s.internal(w, err)
			return
		}
		if !ok {
			writeErr(w, http.StatusBadRequest, "reply_to not found")
			return
		}
	}
	m := &store.Message{From: me, To: to, Type: in.Type, Body: in.Body, ReplyTo: in.ReplyTo}
	if err := s.st.InsertMessage(r.Context(), m); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var since int64
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "since must be a non-negative message id")
			return
		}
		since = n
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeErr(w, http.StatusBadRequest, "limit must be 1..200")
			return
		}
		limit = n
	}
	ms, err := s.st.Inbox(r.Context(), auth.PeerID(r.Context()), since, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	next := since
	if len(ms) > 0 {
		next = ms[len(ms)-1].ID
	}
	writeJSON(w, 200, map[string]any{"messages": ms, "next_since": next})
}

// ---- bags ----

func etag(v int64) string { return fmt.Sprintf(`"v%d"`, v) }

func parseETag(s string) (int64, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "W/")
	if len(s) < 4 || s[0] != '"' || s[len(s)-1] != '"' || s[1] != 'v' {
		return 0, false
	}
	n, err := strconv.ParseInt(s[2:len(s)-1], 10, 64)
	return n, err == nil && n > 0
}

// bagTarget resolves owner (default: caller) and checks the scope for cross-peer access.
func (s *Server) bagTarget(w http.ResponseWriter, r *http.Request, scope string) (owner, name string, ok bool) {
	me := auth.PeerID(r.Context())
	name = r.PathValue("name")
	if !pair.ValidBagName(name) {
		writeErr(w, http.StatusBadRequest, "invalid bag name")
		return "", "", false
	}
	owner = r.URL.Query().Get("owner")
	if owner == "" || owner == me {
		return me, name, true
	}
	g, err := s.st.GetGrant(r.Context(), owner, me)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return "", "", false
	}
	if !pair.Allows(g, scope, name) {
		writeErr(w, http.StatusForbidden, "not permitted")
		return "", "", false
	}
	return owner, name, true
}

func (s *Server) getBag(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := s.bagTarget(w, r, pair.ScopeBagsRead)
	if !ok {
		return
	}
	b, err := s.st.GetBag(r.Context(), owner, name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "bag not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	tag := etag(b.Version)
	w.Header().Set("ETag", tag)
	w.Header().Set("Last-Modified", b.UpdatedAt.Format(http.TimeFormat))
	w.Header().Set("X-Peerline-Updated-By", b.UpdatedBy)
	if inm := r.Header.Get("If-None-Match"); inm != "" && (inm == "*" || strings.Contains(inm, tag)) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b.Content)))
	w.WriteHeader(200)
	w.Write(b.Content)
}

func (s *Server) putBag(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := s.bagTarget(w, r, pair.ScopeBagsWrite)
	if !ok {
		return
	}
	ifVersion := int64(-1)
	if im := r.Header.Get("If-Match"); im != "" {
		v, ok := parseETag(im)
		if !ok {
			writeErr(w, http.StatusPreconditionFailed, "bad If-Match")
			return
		}
		ifVersion = v
	} else if r.Header.Get("If-None-Match") == "*" {
		ifVersion = 0
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBagBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "bag exceeds 64KiB")
		return
	}
	v, err := s.st.PutBag(r.Context(), owner, name, body, auth.PeerID(r.Context()), ifVersion)
	if errors.Is(err, store.ErrConflict) {
		if v > 0 {
			w.Header().Set("ETag", etag(v))
		}
		writeErr(w, http.StatusPreconditionFailed, "version mismatch")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", etag(v))
	code := http.StatusOK
	if v == 1 {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"owner": owner, "name": name, "version": v, "etag": etag(v)})
}

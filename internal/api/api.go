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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sysrex/peerline/internal/auth"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/pair"
	"github.com/sysrex/peerline/internal/store"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxBagBytes      = 64 << 10
	maxJSONBytes     = 16 << 10
	defaultInviteTTL = 1 * time.Hour
	maxInviteTTL     = 7 * 24 * time.Hour
	maxInviteTTLSec  = 604800 // 7 days in seconds, checked before multiplication
)

type Config struct {
	// RegisterToken, if non-empty, must be sent as X-Peerline-Register-Token to register.
	RegisterToken string
	MsgPerMinute  int
	MsgBurst      int
	Logger        *slog.Logger

	// Mailer sends invite and message-notification emails. Nil = dev mode
	// (log the email, never fail the request).
	Mailer mailer.Sender
	// PublicURL is the externally reachable base URL used in emailed accept
	// links (e.g. https://peerline.example.com). If empty, it is derived from
	// the request (fine for local dev; set it in production).
	PublicURL string
	// Email send limits: per inviting peer and per recipient address, per hour.
	EmailPerHour     int
	EmailBurst       int
	EmailRcptPerHour int
	// NotifyPerHour / NotifyBurst limit message-notification emails per
	// recipient peer. Separate from the invite limiters.
	NotifyPerHour int
	NotifyBurst   int
	// TrustedProxies is a list of CIDR ranges (e.g. "10.0.0.0/8") from which
	// X-Forwarded-For headers are honored. If empty, X-Forwarded-For is ignored.
	TrustedProxies []string
	// MaxOutstandingInvites is the per-peer limit on active (non-expired, unused) invites.
	MaxOutstandingInvites int
	// RetentionSeconds is how long (in seconds) to keep used invites before purging.
	// Default is 30 days (2592000 seconds). Set to 0 for the default.
	RetentionSeconds int64
}

type Server struct {
	st          *store.Store
	cfg         Config
	lim         *LimiterManager
	maint       *MaintenanceManager
	log         *slog.Logger
	trustedNets []*net.IPNet
	now         func() time.Time // clock for invite expiry; defaults to time.Now

	// Test-only hook: called after invite creation, before email limit check
	testInviteCreatedHook func(peerID string)
}

func New(st *store.Store, cfg Config) (*Server, error) {
	if cfg.MsgPerMinute <= 0 {
		cfg.MsgPerMinute = 30
	}
	if cfg.MsgBurst <= 0 {
		cfg.MsgBurst = 10
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Mailer == nil {
		cfg.Mailer = mailer.Log{Logger: cfg.Logger}
	}
	if cfg.EmailPerHour <= 0 {
		cfg.EmailPerHour = 20
	}
	if cfg.EmailBurst <= 0 {
		cfg.EmailBurst = 5
	}
	if cfg.EmailRcptPerHour <= 0 {
		cfg.EmailRcptPerHour = 3
	}
	if cfg.NotifyPerHour <= 0 {
		cfg.NotifyPerHour = 20
	}
	if cfg.NotifyBurst <= 0 {
		cfg.NotifyBurst = 5
	}
	if cfg.MaxOutstandingInvites <= 0 {
		cfg.MaxOutstandingInvites = 10
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")

	trustedNets, err := ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("invalid trusted proxy configuration: %w", err)
	}

	// Log parsed trusted networks at startup
	if len(trustedNets) > 0 {
		var prefixes []string
		for _, n := range trustedNets {
			prefixes = append(prefixes, n.String())
		}
		cfg.Logger.Info("trusted proxy networks configured", "prefixes", strings.Join(prefixes, ", "))
	} else if len(cfg.TrustedProxies) == 0 {
		cfg.Logger.Warn("no trusted proxies configured: X-Forwarded-For will be ignored")
	}

	s := &Server{
		st:          st,
		cfg:         cfg,
		log:         cfg.Logger,
		lim:         NewLimiterManager(cfg),
		trustedNets: trustedNets,
		now:         time.Now,
	}

	// Start maintenance tasks
	s.maint = NewMaintenanceManager(context.Background(), st, cfg.Logger, cfg.RetentionSeconds)

	return s, nil
}

// Stop gracefully stops background tasks.
func (s *Server) Stop() {
	if s.lim != nil {
		s.lim.Stop()
	}
	if s.maint != nil {
		s.maint.Stop()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// {$} is an exact match for "/". A bare "GET /" would swallow every other path.
	mux.HandleFunc("GET /{$}", s.rateLimitGet(s.home))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/register", s.register)
	// Registered on the outer mux so it is not behind Bearer auth. The more
	// specific pattern wins over the /v1/ subtree below.
	mux.HandleFunc("GET /v1/public/stats", s.rateLimitGet(s.publicStats))

	authed := http.NewServeMux()
	authed.HandleFunc("GET /v1/me", s.rateLimitAuth(s.me))
	authed.HandleFunc("PUT /v1/me", s.updateMe)
	authed.HandleFunc("POST /v1/me/verify-email", s.verifyEmail)
	authed.HandleFunc("POST /v1/invites", s.createInvite)
	authed.HandleFunc("GET /v1/invites", s.rateLimitAuth(s.listInvites))
	authed.HandleFunc("DELETE /v1/invites/{id}", s.deleteInvite)
	authed.HandleFunc("POST /v1/invites/accept", s.acceptInvite)
	authed.HandleFunc("GET /v1/grants", s.rateLimitAuth(s.listGrants))
	authed.HandleFunc("DELETE /v1/grants/{peer_id}", s.revokeGrant)
	authed.HandleFunc("POST /v1/peers/{peer_id}/messages", s.sendMessage)
	authed.HandleFunc("GET /v1/inbox", s.rateLimitAuth(s.inbox)) // polling-friendly rate limit
	authed.HandleFunc("GET /v1/bags/{name}", s.rateLimitAuth(s.getBag))
	authed.HandleFunc("PUT /v1/bags/{name}", s.putBag)
	authed.HandleFunc("POST /v1/pairing/{token}", s.acceptPairing) // authenticated pairing acceptance
	authMW := auth.Middleware(func(ctx context.Context, h string) (string, error) {
		p, err := s.st.PeerByKeyHash(ctx, h)
		if err != nil {
			return "", err
		}
		return p.ID, nil
	}, authed)
	mux.Handle("/v1/", authMW)
	// The emailed accept link: only unauthenticated GET shows instructions.
	// Authenticated GET returns 405; only POST accepts the invite.
	mux.HandleFunc("GET /v1/invites/accept", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("Allow", "POST")
			writeErr(w, http.StatusMethodNotAllowed, "use POST to accept the invite")
			return
		}
		s.acceptLanding(w, r)
	})
	// Pairing endpoints: GET shows details, POST accepts (optionally creating a new peer)
	mux.HandleFunc("GET /v1/pairing/{token}", s.rateLimitGet(s.getPairing))
	mux.HandleFunc("POST /v1/pairing/{token}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authMW.ServeHTTP(w, r)
			return
		}
		s.acceptPairingUnauthenticated(w, r)
	})
	return securityHeaders(mux)
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

// ---- auth ----

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	// Check register token first, before charging rate limit
	if s.cfg.RegisterToken != "" && !auth.ConstantEqual(r.Header.Get("X-Peerline-Register-Token"), s.cfg.RegisterToken) {
		writeErr(w, http.StatusForbidden, "registration token required")
		return
	}

	// Now charge the rate limiter after token validation
	if !s.lim.regLim.Allow(rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	var in struct {
		Name        string `json:"name"`
		NotifyEmail string `json:"notify_email"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "name required (max 64 chars)")
		return
	}
	notify, err := normalizeNotifyEmail(in.NotifyEmail)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "notify_email: invalid email address")
		return
	}

	// Generate verification token if email is set
	token := ""
	if notify != "" {
		token = auth.NewSecret("eml_")
	}

	id, key := auth.NewID(), auth.NewKey()
	if err := s.st.CreatePeer(r.Context(), id, in.Name, auth.Hash(key), notify, token); err != nil {
		s.internal(w, err)
		return
	}

	// Send verification email if address is set
	if notify != "" && token != "" {
		verifyURL := s.publicBase(r) + "/v1/me/verify-email?token=" + url.QueryEscape(token)
		msg := s.verificationEmail(id, notify, verifyURL)
		ctx := context.WithoutCancel(r.Context())
		if err := s.cfg.Mailer.Send(ctx, msg); err != nil {
			s.log.Error("verification email failed", "peer", id, "err", err)
			// Continue - verification can be resent
		} else {
			s.log.Info("verification email sent", "peer", id)
		}
	}

	s.log.Info("peer registered", "peer_id", id, "notify_email_set", notify != "")
	resp := map[string]any{
		"peer_id":      id,
		"name":         in.Name,
		"api_key":      key,
		"notify_email": notify,
		"verified":     false,
		"note":         "api_key is shown once; store it securely",
	}
	if notify != "" {
		resp["note"] = "api_key is shown once; store it securely. Check your email for a verification link to enable notifications."
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := auth.PeerID(r.Context())
	email, verified, _, err := s.st.GetNotifyEmailWithStatus(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "peer not found")
			return
		}
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id":      id,
		"notify_email": email,
		"verified":     verified,
	})
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		NotifyEmail *string `json:"notify_email"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.NotifyEmail == nil {
		writeErr(w, http.StatusBadRequest, "notify_email required")
		return
	}
	email, err := normalizeNotifyEmail(*in.NotifyEmail)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "notify_email: invalid email address")
		return
	}
	me := auth.PeerID(r.Context())

	// Generate verification token if setting email
	token := ""
	if email != "" {
		token = auth.NewSecret("eml_")
	}

	if err := s.st.SetNotifyEmail(r.Context(), me, email, token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "peer not found")
			return
		}
		s.internal(w, err)
		return
	}

	// Send verification email if address is set
	if email != "" && token != "" {
		verifyURL := s.publicBase(r) + "/v1/me/verify-email?token=" + url.QueryEscape(token)
		msg := s.verificationEmail(me, email, verifyURL)
		// Detach from client cancellation
		ctx := context.WithoutCancel(r.Context())
		if err := s.cfg.Mailer.Send(ctx, msg); err != nil {
			s.log.Error("verification email failed", "peer", me, "err", err)
			// Continue - verification can be resent
		} else {
			s.log.Info("verification email sent", "peer", me)
		}
	}

	s.log.Info("notify email updated", "peer_id", me, "set", email != "", "verified", false)

	// Return current status
	currentEmail, verified, _, err := s.st.GetNotifyEmailWithStatus(r.Context(), me)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id":      me,
		"notify_email": currentEmail,
		"verified":     verified,
		"note":         "Check your email for a verification link to enable notifications",
	})
}

// normalizeNotifyEmail returns "" to clear, or one bare address.
func normalizeNotifyEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	return mailer.ValidAddress(raw)
}

// verificationEmail creates the email body for email address verification.
func (s *Server) verificationEmail(peerID, to, verifyURL string) mailer.Message {
	var b strings.Builder
	b.WriteString("Verify your email address to enable Peerline message notifications.\n\n")
	fmt.Fprintf(&b, "Peer: %s\n\n", peerID)
	b.WriteString("Click the link below or open it in your bot's HTTP client:\n\n")
	fmt.Fprintf(&b, "  %s\n\n", verifyURL)
	fmt.Fprintf(&b, "  curl -X POST -H \"Authorization: Bearer $PEERLINE_API_KEY\" \\\n    '%s'\n\n", verifyURL)
	b.WriteString("If you didn't set this address, ignore this email.\n")
	return mailer.Message{
		To:      to,
		Subject: "Peerline: Verify your email address",
		Body:    b.String(),
	}
}

// verifyEmail handles email verification via token.
func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeErr(w, http.StatusBadRequest, "token required")
		return
	}
	me := auth.PeerID(r.Context())
	if err := s.st.VerifyNotifyEmail(r.Context(), me, token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusBadRequest, "invalid or expired token")
			return
		}
		s.internal(w, err)
		return
	}
	s.log.Info("email verified", "peer_id", me)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "verified",
		"note":   "Email verified successfully. You will now receive message notifications.",
	})
}

// ---- pairing ----

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scopes          []string `json:"scopes"`
		Bags            []string `json:"bags"`
		TTLSeconds      int      `json:"ttl_seconds"`
		ToEmail         string   `json:"to_email"`         // optional: email the accept link + code
		GeneratePairing bool     `json:"generate_pairing"` // optional: generate shareable pairing link
	}
	if !decode(w, r, &in) {
		return
	}
	var to string
	if in.ToEmail != "" {
		a, err := mailer.ValidAddress(in.ToEmail)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "to_email: invalid email address")
			return
		}
		to = a
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

	// Validate TTL before any multiplication to prevent overflow
	// Default: 1h for regular invites, 24h for email invites
	ttl := defaultInviteTTL
	if to != "" {
		ttl = 24 * time.Hour
	}
	if in.TTLSeconds > 0 {
		if in.TTLSeconds > maxInviteTTLSec {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("ttl_seconds must not exceed %d (7 days)", maxInviteTTLSec))
			return
		}
		ttl = time.Duration(in.TTLSeconds) * time.Second
	}

	me := auth.PeerID(r.Context())

	// If both generate_pairing and to_email are specified, reject the request
	// (pairing links are not emailed)
	if in.GeneratePairing && to != "" {
		writeErr(w, http.StatusBadRequest, "cannot combine generate_pairing with to_email")
		return
	}

	code := auth.NewSecret("inv_")
	exp := s.now().Add(ttl).UTC()
	var pairingToken string
	var publicID string

	// Create invite first with atomic cap check (#53)
	if in.GeneratePairing {
		pairingToken = auth.NewPairingToken()
		publicID, err = s.st.CreateInviteWithPairingAtomic(r.Context(), auth.Hash(code), auth.Hash(pairingToken), me, sc, bg, exp, s.cfg.MaxOutstandingInvites)
		if errors.Is(err, store.ErrTooManyInvites) {
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many outstanding invites (limit %d); revoke or wait for expiry", s.cfg.MaxOutstandingInvites))
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
	} else {
		publicID, err = s.st.CreateInviteAtomic(r.Context(), auth.Hash(code), me, sc, bg, exp, s.cfg.MaxOutstandingInvites)
		if errors.Is(err, store.ErrTooManyInvites) {
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many outstanding invites (limit %d); revoke or wait for expiry", s.cfg.MaxOutstandingInvites))
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
	}

	// Test hook for deterministic concurrency testing
	if s.testInviteCreatedHook != nil {
		s.testInviteCreatedHook(me)
	}

	// Check email rate limit AFTER creating invite (#53)
	// If limit fails, delete the invite and return error
	if to != "" {
		rk := strings.ToLower(to)
		// Check both limiters are ready before consuming from either (avoid partial spend)
		if !s.lim.mailLim.Ready(me) || !s.lim.rcptLim.Ready(rk) {
			// Delete the invite we just created
			if delErr := s.st.DeleteInvite(r.Context(), publicID, me); delErr != nil {
				s.cfg.Logger.Error("failed to delete invite after rate limit check", "public_id", publicID, "error", delErr)
				s.internal(w, fmt.Errorf("rate limit check failed and invite cleanup failed: %w", delErr))
				return
			}
			w.Header().Set("Retry-After", "600")
			writeErr(w, http.StatusTooManyRequests, "invite email rate limited; try later or create an invite without to_email and share the code yourself")
			return
		}
		// Both ready, now consume from both (Ready→Allow has a race, but delete handles it)
		if !s.lim.mailLim.Allow(me) || !s.lim.rcptLim.Allow(rk) {
			// This should not happen if Ready checks passed, but handle it
			if delErr := s.st.DeleteInvite(r.Context(), publicID, me); delErr != nil {
				s.cfg.Logger.Error("failed to delete invite after rate limit consume", "public_id", publicID, "error", delErr)
				s.internal(w, fmt.Errorf("rate limit consume failed and invite cleanup failed: %w", delErr))
				return
			}
			w.Header().Set("Retry-After", "600")
			writeErr(w, http.StatusTooManyRequests, "invite email rate limited; try later or create an invite without to_email and share the code yourself")
			return
		}
	}

	// Response shape depends on generate_pairing
	if pairingToken != "" {
		// Pairing-only response: only pairing_url and public_id, no code or accept_url
		pairingURL := s.publicBase(r) + "/v1/pairing/" + url.PathEscape(pairingToken)
		resp := map[string]any{
			"public_id":   publicID,
			"pairing_url": pairingURL,
			"scopes":      sc,
			"bags":        bg,
			"expires_at":  exp.Format(time.RFC3339),
			"note":        "single use; share pairing_url with any agent (registered or not) to complete pairing",
		}
		writeJSON(w, http.StatusCreated, resp)
		return
	}

	// Standard invite response with code, accept_url, and public_id
	acceptURL := s.publicBase(r) + "/v1/invites/accept?code=" + url.QueryEscape(code)
	resp := map[string]any{
		"public_id":  publicID,
		"code":       code,
		"scopes":     sc,
		"bags":       bg,
		"expires_at": exp.Format(time.RFC3339),
		"accept_url": acceptURL,
		"note":       "single use; share out of band with the peer you want to pair with",
	}
	if to != "" {
		status := "sent"
		if s.cfg.Mailer.Mode() == "log" {
			status = "logged"
		}
		m := inviteEmail(s.inviterName(r.Context(), me), me, to, code, s.publicBase(r), sc, bg, exp)
		// Detach from client cancellation; the SMTP sender has its own timeout.
		if err := s.cfg.Mailer.Send(context.WithoutCancel(r.Context()), m); err != nil {
			s.log.Error("invite email failed", "inviter", me, "err", err)
			status = "failed"
		} else {
			s.log.Info("invite email", "inviter", me, "status", status)
		}
		resp["email"] = map[string]string{"to": to, "status": status, "mode": s.cfg.Mailer.Mode()}
		resp["note"] = "single use; emailed to " + to + " (code also returned here as a fallback/debug aid)"
		if status == "failed" {
			resp["note"] = "invite created but the email could not be sent; share the code out of band"
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) publicBase(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) inviterName(ctx context.Context, id string) string {
	n, err := s.st.PeerName(ctx, id)
	if err != nil {
		return "A Peerline peer"
	}
	return sanitizeInviterName(n)
}

// sanitizeInviterName applies NFKC normalization and filters characters that can be used
// for prompt injection or homoglyph attacks. Allows Unicode letters (L*), numbers (N*),
// combining marks (Mn, Mc) with constraints, spaces (including tab/newline mapped to space),
// and basic ASCII punctuation (. , - _ ').
//
// Filters:
//   - All Cf format characters (including zero-width and bidi controls)
//   - Variation selectors (both standard and extended ranges, plus unicode property)
//   - Hangul fillers (U+115F, U+1160, U+3164, U+FFA0)
//   - Tag characters (U+E0000–U+E007F)
//   - Invisible Mn characters (U+034F, U+180B-180D, U+180F, U+17B4-17B5)
//   - Other_Default_Ignorable_Code_Point property
//   - Zl and Zp line/paragraph separators (U+2028, U+2029)
//
// Combining mark constraints (counted in decomposed NFD form, issue #84):
//   - Only allowed directly after a letter or number
//   - Maximum 3 marks per base character (counted in NFD; visible result)
//   - Marks after space, punctuation, or at start are dropped
//
// Whitespace handling:
//   - Tab, newline, and all unicode.IsSpace chars become a single space
//   - Repeated spaces are collapsed
//
// Length limit:
//   - Maximum 64 runes counted on the final NFC (composed) output
//   - Precomposed characters (e.g., é = U+00E9) count as 1 rune
//   - Hangul syllables (e.g., 한 = U+D55C) count as 1 rune each
//   - Truncation respects grapheme cluster boundaries: if cutting at 64 runes
//     would split a base from non-composing marks, backs off to exclude the
//     entire trailing cluster
//
// Returns "A Peerline peer" if the result is empty after filtering.
//
// Note: Cross-script homoglyphs (e.g., Cyrillic а vs Latin a) are not fully solvable here
// and require application-level awareness or visual similarity detection.
func sanitizeInviterName(name string) string {
	const (
		maxRunes        = 64
		maxMarksPerBase = 3 // Issue #84 specifies 3 marks per base (issue #63 asked for 2 but #84 is the live tracker)
		fallbackName    = "A Peerline peer"
		maxInputBytes   = 1024 // Guard against unbounded normalization work
	)

	// Guard: truncate raw input to maxInputBytes on a UTF-8 rune boundary
	// to prevent huge stored names from causing unbounded NFKC/NFD work
	if len(name) > maxInputBytes {
		name = name[:maxInputBytes]
		// Back off to a rune boundary: step back while the last byte is not a rune start
		for len(name) > 0 && !utf8.RuneStart(name[len(name)-1]) {
			name = name[:len(name)-1]
		}
	}

	// Apply NFKC normalization first (compatibility decomposition + canonical composition)
	// This normalizes fullwidth/halfwidth chars, ligatures, compatibility forms
	nfkc := norm.NFKC.String(name)

	// Then apply NFD (canonical decomposition) to separate all base+mark combinations
	// This ensures we can accurately count and limit marks per base character
	nfd := norm.NFD.String(nfkc)

	var out strings.Builder
	lastWasSpace := false
	marksAfterBase := 0
	lastWasBaseChar := false // tracks if last was letter/number (valid base for marks)

	for _, r := range nfd {
		// Filter Hangul fillers: U+115F, U+1160, U+3164, U+FFA0
		if r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 {
			continue
		}

		// Filter variation selectors: U+FE00–U+FE0F (standard), U+E0100–U+E01EF (extended)
		// Also filter via unicode property for completeness
		if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || unicode.Is(unicode.Variation_Selector, r) {
			continue
		}

		// Filter all Cf (format) category: includes bidi controls, zero-width chars, etc.
		if unicode.Is(unicode.Cf, r) {
			continue
		}

		// Filter Zl (line separator) and Zp (paragraph separator): U+2028, U+2029
		// These are unicode.IsSpace but should be removed, not converted to space
		if unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			continue
		}

		// Filter tag characters: U+E0000–U+E007F
		if r >= 0xE0000 && r <= 0xE007F {
			continue
		}

		// Filter invisible Mn characters and default ignorables
		// U+034F COMBINING GRAPHEME JOINER, U+180B-180D Mongolian free variation selectors,
		// U+180F, U+17B4-17B5 Khmer inherent vowels
		if r == 0x034F || (r >= 0x180B && r <= 0x180D) || r == 0x180F || r == 0x17B4 || r == 0x17B5 {
			continue
		}
		if unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
			continue
		}

		// Check if this is a combining mark (Mn or Mc)
		isMark := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r)

		if isMark {
			// Only allow marks after a base character (letter/number)
			// and limit to maxMarksPerBase per base character
			if lastWasBaseChar && marksAfterBase < maxMarksPerBase {
				out.WriteRune(r)
				marksAfterBase++
				// Keep lastWasBaseChar true so we stay in this mark sequence
			}
			// Otherwise drop the mark
		} else if unicode.IsLetter(r) || unicode.IsNumber(r) {
			// Base character: letter or number
			out.WriteRune(r)
			lastWasSpace = false
			lastWasBaseChar = true
			marksAfterBase = 0 // Reset mark counter for new base
		} else if unicode.IsSpace(r) || r == '\t' || r == '\n' || r == '\r' {
			// Map all whitespace (including tab/newline) to single space
			if !lastWasSpace && out.Len() > 0 {
				out.WriteRune(' ')
				lastWasSpace = true
				lastWasBaseChar = false
				marksAfterBase = 0
			}
		} else if r == '.' || r == ',' || r == '-' || r == '_' || r == '\'' {
			// Basic ASCII punctuation
			out.WriteRune(r)
			lastWasSpace = false
			lastWasBaseChar = false // punctuation is not a valid base for marks
			marksAfterBase = 0
		} else {
			// Other characters: reset state but don't write
			lastWasBaseChar = false
			marksAfterBase = 0
		}
	}

	// Apply NFC (canonical composition) to the filtered result
	// This recomposes base+mark sequences into precomposed forms where possible
	result := norm.NFC.String(strings.TrimSpace(out.String()))

	// Return fallback if result is empty
	if result == "" {
		return fallbackName
	}

	// Apply length cap to NFC output (64 runes of final composed form)
	// This ensures precomposed characters (é), Hangul syllables (한), etc. count as 1 rune each
	runes := []rune(result)
	if len(runes) > maxRunes {
		// Truncate at maxRunes, but check if this splits a grapheme cluster.
		// NFC does not guarantee boundaries: e.g., e+grave+combining-mark-below doesn't compose,
		// so cutting after 'e' leaves dangling marks.
		// If the next rune (at position maxRunes) is a combining mark, back off to drop
		// the entire trailing base+marks cluster.
		truncated := runes[:maxRunes]
		if len(runes) > maxRunes {
			nextRune := runes[maxRunes]
			if unicode.Is(unicode.Mn, nextRune) || unicode.Is(unicode.Mc, nextRune) || unicode.Is(unicode.Me, nextRune) {
				// Backed-off: scan backwards to find the base character and drop it too
				for i := len(truncated) - 1; i >= 0; i-- {
					r := truncated[i]
					isMark := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r)
					if !isMark {
						// Found the base, truncate before it
						truncated = truncated[:i]
						break
					}
				}
			}
		}
		result = string(truncated)
	}

	// Trim trailing spaces that may have been left by the 64-rune truncation
	result = strings.TrimRight(result, " ")

	return result
}

func inviteEmail(inviter, inviterID, to, code, publicBase string, scopes, bags []string, exp time.Time) mailer.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (Peerline peer %s) invited one of your bots to pair on Peerline,\n", inviter, inviterID)
	b.WriteString("a deny-all relay that lets bots on different accounts exchange short messages.\n\n")
	fmt.Fprintf(&b, "Scopes granted to you: %s\n", strings.Join(scopes, ", "))
	if len(bags) > 0 {
		fmt.Fprintf(&b, "Bags: %s\n", strings.Join(bags, ", "))
	}
	fmt.Fprintf(&b, "Expires: %s (single use)\n\n", exp.Format(time.RFC3339))
	b.WriteString("Accept with your bot's own Peerline API key (POST with code in body):\n\n")
	fmt.Fprintf(&b, "  curl -X POST -H \"Authorization: Bearer $PEERLINE_API_KEY\" \\\n")
	fmt.Fprintf(&b, "    -H \"Content-Type: application/json\" \\\n")
	fmt.Fprintf(&b, "    -d '{\"code\":\"%s\"}' \\\n", code)
	fmt.Fprintf(&b, "    '%s/v1/invites/accept'\n\n", publicBase)
	fmt.Fprintf(&b, "Or give your bot this one-time code to paste:\n\n  %s\n\n", code)
	b.WriteString("Accepting only lets your bot act within the scopes above on the inviter's side;\nnothing of yours is shared unless you grant scopes back.\n")
	b.WriteString("If you don't recognise the inviter, ignore this email. The code expires on its own.\n")
	return mailer.Message{To: to, Subject: "Peerline: " + inviter + " invited your bot to pair", Body: b.String()}
}

var inviteCodeRE = regexp.MustCompile(`^inv_[A-Za-z0-9_-]{16,64}$`)

// acceptLanding answers an unauthenticated GET of the emailed link. It never
// touches the invite (so mail scanners and previews cannot burn it).
func (s *Server) acceptLanding(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !inviteCodeRE.MatchString(code) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Peerline: missing or malformed invite code.\n")
		return
	}
	u := s.publicBase(r) + "/v1/invites/accept"
	fmt.Fprintf(w, "Peerline invite\n\nAccept with your bot's Peerline API key (use POST with code in body):\n\n"+
		"  curl -X POST -H \"Authorization: Bearer $PEERLINE_API_KEY\" \\\n"+
		"    -H \"Content-Type: application/json\" \\\n"+
		"    -d '{\"code\":\"%s\"}' \\\n"+
		"    '%s'\n\n"+
		"Optionally grant scopes back in the same call: {\"code\":\"%s\",\"scopes\":[\"messages\"]}.\n"+
		"Or paste the one-time code into your bot: %s\n\nNothing has been accepted yet.\n", code, u, code, code)
}

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code   string   `json:"code"`
		Scopes []string `json:"scopes"` // optional reciprocal grant to the inviter
		Bags   []string `json:"bags"`
	}
	// Body is optional when the code comes from the query string (?code=).
	if r.ContentLength != 0 {
		if !decode(w, r, &in) {
			return
		}
	}
	q := r.URL.Query()
	queryOnlyCode := false
	if qc := q.Get("code"); qc != "" {
		if in.Code != "" && in.Code != qc {
			writeErr(w, http.StatusBadRequest, "code in body and query differ")
			return
		}
		if in.Code == "" {
			queryOnlyCode = true
		}
		in.Code = qc
	}
	if in.Code == "" {
		writeErr(w, http.StatusBadRequest, "code required (JSON body or ?code=)")
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
	// RFC 9745 deprecation headers for query-string-only code path (legacy).
	// TODO: confirm-mode invites (#3) will return 404 on this path.
	if queryOnlyCode {
		w.Header().Set("Deprecation", "@1767225600") // 2026-01-01 00:00:00 UTC
		w.Header().Set("Link", `<https://github.com/sysrex/peerline#email-invites>; rel="deprecation"; type="text/html"`)
	}
	resp := map[string]any{"peer_id": g.Owner, "granted_to_you": g}
	if len(sc) > 0 {
		resp["granted_by_you"] = store.Grant{Owner: me, Grantee: g.Owner, Scopes: sc, Bags: bg}
	}
	s.log.Info("pairing accepted", "owner", g.Owner, "grantee", me)
	writeJSON(w, 200, resp)
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request) {
	me := auth.PeerID(r.Context())

	// Parse and validate pagination parameters (Architect item 7)
	limit := 50
	offset := 0
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed <= 0 || parsed > 200 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer between 1 and 200")
			return
		}
		limit = parsed
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		parsed, err := strconv.Atoi(offsetStr)
		if err != nil || parsed < 0 {
			writeErr(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = parsed
	}

	invites, err := s.st.ListInvitesByPeer(r.Context(), me, limit, offset)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"invites": invites})
}

func (s *Server) deleteInvite(w http.ResponseWriter, r *http.Request) {
	publicID := r.PathValue("id")
	if publicID == "" {
		writeErr(w, http.StatusBadRequest, "missing public_id")
		return
	}

	me := auth.PeerID(r.Context())
	err := s.st.DeleteInvite(r.Context(), publicID, me)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "invite not found or already used")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("invite revoked", "peer", me, "public_id", publicID)
	w.WriteHeader(http.StatusNoContent)
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	if !s.lim.msgLim.Allow(me) {
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
	// Only after the grant check and a successful insert. A denied, invalid,
	// or unstored message must not wake the recipient. Mail failure and the
	// notify rate limit do not change this 201: the inbox write already happened.
	s.notifyNewMessage(r.Context(), m)
	writeJSON(w, http.StatusCreated, m)
}

// apiKeyInBody matches Peerline API keys (pl_ + secret). Peer ids are p_ + hex
// and do not match. Used to keep stored secrets out of notification previews.
var apiKeyInBody = regexp.MustCompile(`pl_[A-Za-z0-9_-]{8,}`)

const notifyPreviewMax = 200

func (s *Server) notifyNewMessage(ctx context.Context, m *store.Message) {
	// The message is already stored. Don't drop the wake-up if the client hangs up.
	ctx = context.WithoutCancel(ctx)

	// Only send to verified emails
	email, err := s.st.GetVerifiedNotifyEmail(ctx, m.To)
	if err != nil {
		s.log.Error("notify email lookup", "recipient", m.To, "message_id", m.ID, "err", err)
		return
	}
	if email == "" {
		return // No verified email set
	}

	// Check both per-peer and per-address rate limits
	normalizedAddr := strings.ToLower(email)
	if !s.lim.notifyLim.Allow(m.To) {
		s.log.Warn("notify email rate limited (per-peer)", "recipient", m.To, "message_id", m.ID)
		return
	}
	if !s.lim.notifyAddrLim.Allow(normalizedAddr) {
		s.log.Warn("notify email rate limited (per-address)", "address", normalizedAddr, "recipient", m.To, "message_id", m.ID)
		return
	}

	status := "sent"
	if s.cfg.Mailer.Mode() == "log" {
		status = "logged"
	}
	if err := s.cfg.Mailer.Send(ctx, s.notifyEmail(m, email)); err != nil {
		s.log.Error("notify email failed", "recipient", m.To, "message_id", m.ID, "err", err)
		return
	}
	s.log.Info("notify email", "recipient", m.To, "message_id", m.ID, "status", status)
}

func (s *Server) notifyEmail(m *store.Message, to string) mailer.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\n", m.From)
	fmt.Fprintf(&b, "To: %s\n", m.To)
	fmt.Fprintf(&b, "Message id: %d\n", m.ID)
	fmt.Fprintf(&b, "Type: %s\n", m.Type)
	fmt.Fprintf(&b, "Created: %s\n\n", m.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Preview:\n%s\n", bodyPreview(m.Body, s.cfg.RegisterToken, notifyPreviewMax))
	b.WriteString("\nRead the full message from your Peerline inbox (GET /v1/inbox).\n\n")
	b.WriteString("---\n")
	fmt.Fprintf(&b, "You received this notification because peer %s sent a message to peer %s, and %s has this email set as their verified notification address. To stop receiving these notifications, clear your notify_email via PUT /v1/me.\n", m.From, m.To, m.To)
	return mailer.Message{
		To:      to,
		Subject: "Peerline: new message from " + m.From,
		Body:    b.String(),
	}
}

// bodyPreview is an excerpt of the message body. It drops ASCII controls
// (except tab and newline), redacts API keys and a register token of at least
// 8 characters, and stays within max runes.
func bodyPreview(body, registerToken string, max int) string {
	if max < 1 {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, body)
	if len(registerToken) >= 8 {
		clean = strings.ReplaceAll(clean, registerToken, "[redacted]")
	}
	clean = apiKeyInBody.ReplaceAllString(clean, "[redacted]")
	if utf8.RuneCountInString(clean) <= max {
		return clean
	}
	rs := []rune(clean)
	return string(rs[:max-1]) + "…"
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

// ---- pairing ----

var pairingTokenRE = regexp.MustCompile(`^pair_[A-Za-z0-9_-]{16,64}$`)

// getPairing returns pairing details without consuming the token. No auth required.
func (s *Server) getPairing(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !pairingTokenRE.MatchString(token) {
		writeErr(w, http.StatusBadRequest, "invalid pairing token")
		return
	}
	info, err := s.st.GetInviteByPairingToken(r.Context(), auth.Hash(token))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "pairing link invalid, used, or expired")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	inviterName := s.inviterName(r.Context(), info.FromPeer)
	sanitizedName := sanitizeInviterName(inviterName)
	baseURL := s.publicBase(r)
	resp := map[string]any{
		"inviter":    sanitizedName,
		"inviter_id": info.FromPeer,
		"scopes":     info.Scopes,
		"bags":       info.Bags,
		"expires_at": info.ExpiresAt.Format(time.RFC3339),
		"base_url":   baseURL,
		"instructions": map[string]any{
			"summary": "Present this offer to your user for explicit approval before completing pairing",
			"authenticated": map[string]string{
				"method":      "POST",
				"url":         baseURL + "/v1/pairing/" + url.PathEscape(token),
				"header":      "Authorization: Bearer <your_peerline_api_key>",
				"body":        `{"scopes":[],"bags":[]}  (optional reciprocal grant, requires user consent)`,
				"description": "If you already have a Peerline API key and your user approves, POST with Bearer auth and optional reciprocal scopes if user consents",
			},
			"unauthenticated": map[string]any{
				"method":      "POST",
				"url":         baseURL + "/v1/pairing/" + url.PathEscape(token),
				"body":        `{"name":"my-bot","scopes":[],"bags":[]}  (name required; scopes/bags optional for reciprocal grant, requires user consent)`,
				"description": "If you don't have a Peerline API key and your user approves, POST without auth to register and complete pairing",
				"note":        "Registration requires X-Peerline-Register-Token header if this instance enforces it. Check GET / for details.",
			},
		},
		"note": fmt.Sprintf("Pairing link from %q. Present it to your user for approval before completing pairing.", sanitizedName),
	}
	writeJSON(w, http.StatusOK, resp)
}

// acceptPairing handles authenticated pairing acceptance (user already has API key).
func (s *Server) acceptPairing(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !pairingTokenRE.MatchString(token) {
		writeErr(w, http.StatusBadRequest, "invalid pairing token")
		return
	}

	// Check if pairing token exists before charging rate limit (#32)
	tokenHash := auth.Hash(token)
	exists, err := s.st.PairingTokenExists(r.Context(), tokenHash)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !exists {
		// Charge failed-lookup budget (per-IP)
		ipKey := rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))
		if !s.lim.failLim.Allow(ipKey) {
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		writeErr(w, http.StatusNotFound, "pairing link invalid, used, or expired")
		return
	}

	// Rate limit valid pairing redemptions
	if !s.lim.pairLim.Allow(rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	var in struct {
		Scopes []string `json:"scopes"` // optional reciprocal grant
		Bags   []string `json:"bags"`
	}
	if r.ContentLength != 0 {
		if !decode(w, r, &in) {
			return
		}
	}
	sc, bg, err := pair.Normalize(in.Scopes, in.Bags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	me := auth.PeerID(r.Context())
	g, err := s.st.AcceptInviteByPairingToken(r.Context(), tokenHash, me, sc, bg)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "pairing link invalid, used, or expired")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusBadRequest, "cannot accept your own pairing link")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	resp := map[string]any{"peer_id": g.Owner, "granted_to_you": g}
	if len(sc) > 0 {
		resp["granted_by_you"] = store.Grant{Owner: me, Grantee: g.Owner, Scopes: sc, Bags: bg}
	}
	s.log.Info("pairing accepted (authenticated)", "owner", g.Owner, "grantee", me)
	writeJSON(w, http.StatusOK, resp)
}

// acceptPairingUnauthenticated handles pairing acceptance for unregistered agents.
// It registers the peer, then accepts the pairing, all in one atomic operation.
func (s *Server) acceptPairingUnauthenticated(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !pairingTokenRE.MatchString(token) {
		writeErr(w, http.StatusBadRequest, "invalid pairing token")
		return
	}

	// Check register token first, before charging any rate limit
	if s.cfg.RegisterToken != "" && !auth.ConstantEqual(r.Header.Get("X-Peerline-Register-Token"), s.cfg.RegisterToken) {
		writeErr(w, http.StatusForbidden, "registration token required")
		return
	}

	// Check if pairing token exists before charging rate limit (#32)
	tokenHash := auth.Hash(token)
	exists, err := s.st.PairingTokenExists(r.Context(), tokenHash)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !exists {
		// Charge failed-lookup budget (per-IP)
		ipKey := rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))
		if !s.lim.failLim.Allow(ipKey) {
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		writeErr(w, http.StatusNotFound, "pairing link invalid, used, or expired")
		return
	}

	// Rate limit valid pairing redemptions
	if !s.lim.pairLim.Allow(rateLimitKey(clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets))) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	var in struct {
		Name   string   `json:"name"`   // required for registration
		Scopes []string `json:"scopes"` // optional reciprocal grant
		Bags   []string `json:"bags"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeErr(w, http.StatusBadRequest, "name required (max 64 chars)")
		return
	}
	sc, bg, err := pair.Normalize(in.Scopes, in.Bags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Atomically register and accept the pairing in one transaction
	id, key := auth.NewID(), auth.NewKey()
	g, err := s.st.RegisterAndAcceptByPairing(r.Context(), tokenHash, id, in.Name, auth.Hash(key), "", "", sc, bg)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "pairing link invalid, used, or expired")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusBadRequest, "cannot accept your own pairing link")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	s.log.Info("peer registered and paired", "peer_id", id, "inviter", g.Owner)
	resp := map[string]any{
		"peer_id":        id,
		"api_key":        key,
		"name":           in.Name,
		"paired_with":    g.Owner,
		"granted_to_you": g,
		"note":           "api_key is shown once; store it securely",
	}
	if len(sc) > 0 {
		resp["granted_by_you"] = store.Grant{Owner: id, Grantee: g.Owner, Scopes: sc, Bags: bg}
	}
	writeJSON(w, http.StatusCreated, resp)
}

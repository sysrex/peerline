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
		// This should have been caught at startup, log and continue with empty list
		cfg.Logger.Warn("invalid trusted proxy CIDR, ignoring", "err", err)
		trustedNets = nil
	}

	s := &Server{
		st:          st,
		cfg:         cfg,
		log:         cfg.Logger,
		lim:         NewLimiterManager(cfg),
		trustedNets: trustedNets,
	}

	// Start maintenance tasks
	s.maint = NewMaintenanceManager(context.Background(), st, cfg.Logger, cfg.RetentionSeconds)

	return s
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
	authed.HandleFunc("POST /v1/invites", s.createInvite)
	authed.HandleFunc("GET /v1/invites", s.rateLimitAuth(s.listInvites))
	authed.HandleFunc("DELETE /v1/invites/{id}", s.deleteInvite)
	authed.HandleFunc("POST /v1/invites/accept", s.acceptInvite)
	authed.HandleFunc("GET /v1/invites/accept", s.acceptInvite) // emailed magic link (Bearer required)
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
	// The emailed accept link: with a Bearer key it accepts (same flow as
	// POST); without one (a human clicking, or a link scanner) it only shows
	// instructions and never consumes the invite.
	mux.HandleFunc("GET /v1/invites/accept", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authMW.ServeHTTP(w, r)
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
	id, key := auth.NewID(), auth.NewKey()
	if err := s.st.CreatePeer(r.Context(), id, in.Name, auth.Hash(key), notify); err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("peer registered", "peer_id", id, "notify_email_set", notify != "")
	writeJSON(w, http.StatusCreated, map[string]string{
		"peer_id": id, "name": in.Name, "api_key": key, "notify_email": notify,
		"note": "api_key is shown once; store it securely",
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := auth.PeerID(r.Context())
	email, err := s.st.NotifyEmail(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "peer not found")
			return
		}
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"peer_id": id, "notify_email": email})
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
	if err := s.st.SetNotifyEmail(r.Context(), me, email); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "peer not found")
			return
		}
		s.internal(w, err)
		return
	}
	s.log.Info("notify email updated", "peer_id", me, "set", email != "")
	s.me(w, r)
}

// normalizeNotifyEmail returns "" to clear, or one bare address.
func normalizeNotifyEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	return mailer.ValidAddress(raw)
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

	// Check per-owner invite cap BEFORE spending email budget (#53)
	count, err := s.st.CountOutstandingInvites(r.Context(), me)
	if err != nil {
		s.internal(w, err)
		return
	}
	if count >= s.cfg.MaxOutstandingInvites {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("too many outstanding invites (limit %d); revoke or wait for expiry", s.cfg.MaxOutstandingInvites))
		return
	}

	// Email rate limit check (after cap check, before creating invite)
	if to != "" {
		rk := strings.ToLower(to)
		if !s.lim.mailLim.Ready(me) || !s.lim.rcptLim.Ready(rk) || !s.lim.mailLim.Allow(me) || !s.lim.rcptLim.Allow(rk) {
			w.Header().Set("Retry-After", "600")
			writeErr(w, http.StatusTooManyRequests, "invite email rate limited; try later or create an invite without to_email and share the code yourself")
			return
		}
	}

	code := auth.NewSecret("inv_")
	// API layer is not clock-injected yet; uses wall time directly
	exp := time.Now().Add(ttl).UTC()
	var pairingToken string
	var publicID string

	// Atomically check invite cap and create invite
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
		m := inviteEmail(s.inviterName(r.Context(), me), me, to, code, acceptURL, sc, bg, exp)
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
// combining marks (Mn, Mc), spaces, and basic ASCII punctuation (. , - _ ').
// Filters all Cf format characters (including zero-width and bidi controls), variation selectors,
// Hangul fillers, and tag characters. Collapses repeated spaces and trims the result.
// Max length 64 runes (not bytes).
//
// Note: Cross-script homoglyphs (e.g., Cyrillic а vs Latin a) are not fully solvable here
// and require application-level awareness or visual similarity detection.
func sanitizeInviterName(name string) string {
	const maxRunes = 64

	// Apply NFKC normalization (compatibility decomposition + canonical composition)
	// This normalizes fullwidth/halfwidth chars, ligatures, compatibility forms
	normalized := norm.NFKC.String(name)

	var out strings.Builder
	lastWasSpace := false
	runeCount := 0

	for _, r := range normalized {
		// Filter Hangul fillers: U+115F, U+1160, U+3164, U+FFA0
		if r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0 {
			continue
		}

		// Filter variation selectors: U+FE00–U+FE0F (standard), U+E0100–U+E01EF (extended)
		if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) {
			continue
		}

		// Filter all Cf (format) category: includes bidi controls, zero-width chars, etc.
		if unicode.Is(unicode.Cf, r) {
			continue
		}

		// Filter tag characters: U+E0000–U+E007F
		if r >= 0xE0000 && r <= 0xE007F {
			continue
		}

		// Allow: Unicode letters (L*), numbers (N*), combining marks (Mn, Mc), space, and basic ASCII punctuation
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) {
			out.WriteRune(r)
			lastWasSpace = false
			runeCount++
		} else if r == ' ' {
			// Collapse repeated spaces
			if !lastWasSpace && out.Len() > 0 {
				out.WriteRune(' ')
				lastWasSpace = true
				runeCount++
			}
		} else if r == '.' || r == ',' || r == '-' || r == '_' || r == '\'' {
			// Basic ASCII punctuation
			out.WriteRune(r)
			lastWasSpace = false
			runeCount++
		}

		// Stop if we exceed max runes
		if runeCount >= maxRunes {
			break
		}
	}

	return strings.TrimSpace(out.String())
}

func inviteEmail(inviter, inviterID, to, code, acceptURL string, scopes, bags []string, exp time.Time) mailer.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (Peerline peer %s) invited one of your bots to pair on Peerline,\n", inviter, inviterID)
	b.WriteString("a deny-all relay that lets bots on different accounts exchange short messages.\n\n")
	fmt.Fprintf(&b, "Scopes granted to you: %s\n", strings.Join(scopes, ", "))
	if len(bags) > 0 {
		fmt.Fprintf(&b, "Bags: %s\n", strings.Join(bags, ", "))
	}
	fmt.Fprintf(&b, "Expires: %s (single use)\n\n", exp.Format(time.RFC3339))
	b.WriteString("Accept with your bot's own Peerline API key (opening the link in a browser\nonly shows instructions; it does not accept):\n\n")
	fmt.Fprintf(&b, "  %s\n\n", acceptURL)
	fmt.Fprintf(&b, "  curl -X POST -H \"Authorization: Bearer $PEERLINE_API_KEY\" \\\n    '%s'\n\n", acceptURL)
	fmt.Fprintf(&b, "Or give your bot this one-time code:\n\n  %s\n\n", code)
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
	u := s.publicBase(r) + "/v1/invites/accept?code=" + url.QueryEscape(code)
	fmt.Fprintf(w, "Peerline invite\n\nThis link must be opened by your bot with its Peerline API key:\n\n"+
		"  curl -X POST -H \"Authorization: Bearer $PEERLINE_API_KEY\" '%s'\n\n"+
		"Optionally grant scopes back in the same call with a JSON body, e.g. {\"scopes\":[\"messages\"]}.\n"+
		"Or paste the one-time code into your bot: %s\n\nNothing has been accepted yet.\n", u, code)
}

func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code   string   `json:"code"`
		Scopes []string `json:"scopes"` // optional reciprocal grant to the inviter
		Bags   []string `json:"bags"`
	}
	// Body is optional when the code comes from the emailed link (?code=).
	if r.Method == http.MethodPost && r.ContentLength != 0 {
		if !decode(w, r, &in) {
			return
		}
	}
	q := r.URL.Query()
	if qc := q.Get("code"); qc != "" {
		if in.Code != "" && in.Code != qc {
			writeErr(w, http.StatusBadRequest, "code in body and query differ")
			return
		}
		in.Code = qc
	}
	if r.Method == http.MethodGet {
		in.Scopes, in.Bags = splitCSV(q.Get("scopes")), splitCSV(q.Get("bags"))
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
	email, err := s.st.NotifyEmail(ctx, m.To)
	if err != nil {
		s.log.Error("notify email lookup", "recipient", m.To, "message_id", m.ID, "err", err)
		return
	}
	if email == "" {
		return
	}
	if !s.lim.notifyLim.Allow(m.To) {
		s.log.Warn("notify email rate limited", "recipient", m.To, "message_id", m.ID)
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
	b.WriteString("\nRead the full message from your Peerline inbox (GET /v1/inbox).\n")
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
	g, err := s.st.RegisterAndAcceptByPairing(r.Context(), tokenHash, id, in.Name, auth.Hash(key), "", sc, bg)
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

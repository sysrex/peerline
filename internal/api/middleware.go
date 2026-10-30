package api

import (
	"net/http"

	"github.com/sysrex/peerline/internal/auth"
)

// securityHeaders adds security-hardening HTTP headers to all responses.
// The home page sets its own CSP with a nonce; API routes get a strict policy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		// API routes get a strict CSP. The home page (/) overrides this with a nonce-based policy.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		next.ServeHTTP(w, r)
	})
}

// rateLimitGet wraps a handler with light GET endpoint rate limiting (per-IP).
func (s *Server) rateLimitGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets)
		key := rateLimitKey(ip)
		if !s.lim.getLim.Allow(key) {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		h(w, r)
	}
}

// rateLimitAuth wraps an authenticated handler with rate limiting per peer ID.
func (s *Server) rateLimitAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID := auth.PeerID(r.Context())
		if !s.lim.authLim.Allow(peerID) {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		h(w, r)
	}
}

// rateLimitVersion wraps /version with a dedicated rate limiter (per-IP).
// Separate from getLim so monitors don't drain the shared bucket.
func (s *Server) rateLimitVersion(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.trustedNets)
		key := rateLimitKey(ip)
		if !s.lim.versionLim.Allow(key) {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		h(w, r)
	}
}

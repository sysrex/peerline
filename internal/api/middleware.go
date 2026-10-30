package api

import (
	"net/http"

	"github.com/sysrex/peerline/internal/auth"
)

// securityHeaders adds security-hardening HTTP headers to all responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// rateLimitGet wraps a handler with light GET endpoint rate limiting (per-IP).
func (s *Server) rateLimitGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), s.trustedNets)
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

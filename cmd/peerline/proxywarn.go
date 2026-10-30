package main

import "log/slog"

// warnTrustedProxies logs a warning when PEERLINE_TRUSTED_PROXIES is unset or empty.
// When running behind a reverse proxy without configuring trusted proxies,
// all clients share the proxy's IP address, causing rate limits to be exhausted
// by any single client.
func warnTrustedProxies(log *slog.Logger, raw string) {
	if raw == "" {
		log.Warn("PEERLINE_TRUSTED_PROXIES unset: X-Forwarded-For headers are ignored; client IPs will be taken from RemoteAddr only")
	}
}

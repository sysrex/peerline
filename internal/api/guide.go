package api

import "net/http"

// guideVersion changes whenever guideSteps changes.
const guideVersion = 1

// guideSteps holds only step ids, enums and origin-relative route templates.
// It deliberately has no free prose for an agent to follow.
var guideSteps = []map[string]any{
	{"id": "register", "method": "POST", "route": "/v1/register", "auth": "none", "owner_approval": true},
	{"id": "inspect_pairing", "method": "GET", "route": "/v1/pairing/{token}", "auth": "none", "owner_approval": false},
	{"id": "accept_pairing", "method": "POST", "route": "/v1/pairing/{token}", "auth": "bearer", "owner_approval": true},
	{"id": "create_invite", "method": "POST", "route": "/v1/invites", "auth": "bearer", "owner_approval": true},
	{"id": "accept_invite", "method": "POST", "route": "/v1/invites/accept", "auth": "bearer", "owner_approval": true},
	{"id": "list_grants", "method": "GET", "route": "/v1/grants", "auth": "bearer", "owner_approval": false},
	{"id": "send_message", "method": "POST", "route": "/v1/peers/{peer_id}/messages", "auth": "bearer", "owner_approval": false},
	{"id": "read_inbox", "method": "GET", "route": "/v1/inbox", "auth": "bearer", "owner_approval": false},
}

// guide is static: identical on every request and for every Host header.
func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"guide_version": guideVersion,
		"steps":         guideSteps,
		"help":          "https://github.com/sysrex/peerline/blob/main/skill/SKILL.md",
	})
}

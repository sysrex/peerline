package a2a

// PublicCard is the gateway card. It names no peer.
func PublicCard(base string) map[string]any {
	return map[string]any{
		"name":                "Peerline",
		"description":         "Deny-all relay between paired agents",
		"version":             "1.0.0",
		"supportedInterfaces": []any{interfaceEntry(base+"/a2a", "")},
		"capabilities": map[string]any{
			"streaming":         false,
			"pushNotifications": false,
			"extendedAgentCard": true,
		},
		"securitySchemes": map[string]any{
			"bearer": map[string]any{"type": "http", "scheme": "bearer"},
		},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills":             []any{relaySkill()},
	}
}

// PeerCard is the card for one peer the caller is allowed to use.
// tenant is the peer id. Skills are only those the grant allows.
func PeerCard(base, peerID string, relay bool) map[string]any {
	card := PublicCard(base)
	card["name"] = "Peerline peer"
	card["supportedInterfaces"] = []any{interfaceEntry(base+"/a2a", peerID)}
	if relay {
		card["skills"] = []any{relaySkill()}
	} else {
		card["skills"] = []any{}
	}
	return card
}

func interfaceEntry(url, tenant string) map[string]any {
	e := map[string]any{
		"url":             url,
		"protocolBinding": "JSONRPC",
		"protocolVersion": "1.0",
	}
	if tenant != "" {
		e["tenant"] = tenant
	}
	return e
}

func relaySkill() map[string]any {
	return map[string]any{
		"id":          "relay-message",
		"name":        "Relay message",
		"description": "Deliver a short message to a paired peer",
	}
}

// SupportedVersion reports whether the A2A-Version header is acceptable.
// An empty header is the discovery default and is accepted.
func SupportedVersion(header string) bool {
	return header == "" || header == "1.0"
}

# A2A gateway

Peerline publishes one public agent card and hides every peer until a grant exists.

`GET /.well-known/agent-card.json` needs no authentication. The card describes the JSON-RPC binding at `/a2a`, protocol version 1.0, bearer auth, and a single relay skill. It contains no peer id.

`GET /a2a/{peer_id}/agent-card.json` needs `Authorization: Bearer <api_key>`. The caller must hold a grant from that peer for both `a2a` and `messages`. Anyone else gets 404, whether the peer exists or not, with the same body. The card's interface `tenant` is that peer id, and the skill list is the relay skill.

Send `A2A-Version: 1.0`. Any other value is rejected. Omitting the header is accepted on discovery.

`a2a` is a grant scope alongside `messages`, `bags:read`, and `bags:write`. Existing grants are unchanged. A `messages` grant does not open the gateway.

The card is hand-rolled. The JSON-RPC methods are a separate change. This avoids a new A2A module for a static document and four methods.

# Shareable Pairing Links - Security Analysis

## Overview

Shareable pairing links enable agents without email (Hermes, Claude Duo, OpenClaw) to pair with Peerline using a single URL. This document analyzes the security properties and trade-offs.

## Security Properties

### 1. No Secrets in URL

The pairing URL format is: `https://peerline.example.com/v1/pairing/pair_<token>`

What it **DOES NOT** contain:
- ❌ API keys (neither existing nor newly generated)
- ❌ Register token (required for registration)
- ❌ Invite code (the underlying invite code is separate)
- ❌ Any user data, messages, or bag contents

What it **DOES** contain:
- ✅ A random pairing token (192 bits, hashed in database)
- ✅ The inviter name in the GET response (untrusted text)

### 2. Token Properties

**Generation:**
- 192-bit random token (`pair_` prefix + 24 bytes base64url)
- Same entropy as invite codes and API keys
- Generated via `crypto/rand`

**Storage:**
- Stored as SHA-256 hash in database
- Never logged in plaintext
- Indexed for fast lookup

**Lifecycle:**
- Single-use (consumed on first successful accept)
- Expires after 1h by default (max 7d; `ttl_seconds` above 604800 returns 400). Pairing links cannot use `to_email`, so the 24h default for emailed invite codes does not apply.
- Cannot be reused after acceptance
- Unused invites are removed by the hourly maintenance sweep after expiry; used invites are kept for the retention window after expiry

### 3. What GET /v1/pairing/{token} Exposes

When an agent (or anyone) GETs a pairing link, they receive:

```json
{
  "inviter": "alice-bot",           // Display name (user-controlled string)
  "inviter_id": "p_abc123...",      // Peer ID (already public to paired peers)
  "scopes": ["messages"],           // What access is being offered
  "bags": [],                       // Which bags (if any)
  "expires_at": "2026-10-31T...",   // When it expires
  "instructions": { ... }           // How to accept
}
```

**Why this is safe:**
1. **No historical data:** Accepting grants access to *future* messages/bags only
2. **No enumeration:** Peer IDs are not guessable; you need the pairing link
3. **Informed consent:** Agent sees exactly what it's accepting before committing
4. **Deny-all default:** Even after pairing, no data flows without explicit grants

### 4. Accept Flow Security

**Unauthenticated (register + accept):**
```bash
POST /v1/pairing/{token}
Content-Type: application/json
X-Peerline-Register-Token: <if required>

{"name":"my-bot","scopes":["messages"]}
```

- ✅ Still requires register token if instance enforces it
- ✅ Rate limited (same as normal registration)
- ✅ Name validation (max 64 chars, required)
- ✅ Scope validation (only valid scopes accepted)
- ✅ Returns new API key once (never logged, shown once)

**Authenticated (existing peer):**
```bash
POST /v1/pairing/{token}
Authorization: Bearer <existing_key>
Content-Type: application/json

{"scopes":["messages"]}
```

- ✅ Same auth as all other Peerline endpoints
- ✅ Cannot accept own pairing link (rejected with 400)
- ✅ Reciprocal grant is optional

### 5. Comparison to Email Invites

| Property | Email Invite | Pairing Link |
|----------|-------------|--------------|
| Requires email access | Yes | No |
| Contains invite code | Yes | No (separate token) |
| Can be forwarded | Yes | Yes |
| Single-use | Yes | Yes |
| Expiring | Yes | Yes |
| Shows inviter info | Yes | Yes |
| Safe to inspect | Yes (with caveats) | Yes |
| Rate limited | Yes | Yes |

**Key insight:** Pairing links have *the same* exposure risk as email invites. If Alice emails Bob an invite and Bob forwards it to Carol, Carol can accept it (first wins). Pairing links have the identical property.

## Threat Model

### What pairing links protect against

✅ **Credential theft:** API keys never in URL  
✅ **Register token leak:** Never in URL, still enforced on accept  
✅ **Brute force:** 192-bit tokens, hashed storage  
✅ **Replay attacks:** Single-use tokens  
✅ **Expired invites:** Time-bound like invites  
✅ **Self-pairing:** Rejected at accept time  

### What they DON'T protect against

❌ **Link forwarding:** If Alice gives Bob a pairing link and Bob shares it publicly, the first person to accept wins. This is identical to email invites.

❌ **Inviter impersonation:** If Eve tricks Alice into creating a pairing link for Eve, Alice grants Eve access. This is social engineering, not a technical vulnerability.

❌ **MitM on HTTP:** Use HTTPS. Peerline speaks HTTP; put it behind a TLS terminator.

## When to Use (and Not Use)

### ✅ Good use cases

- Pairing with agents that don't have email
- Dev/test environments where you want a quick pairing flow
- Documented APIs where you want to show agents how to pair
- Personal use where you control both ends

### ❌ Not recommended for

- Highly sensitive integrations where you need absolute control over who accepts
- Production systems where a leaked link could be problematic
- Cases where you can't trust the human carrying the link

**Alternative:** Use traditional invite codes exchanged over a secure channel, or email invites if both sides have email.

## Mitigations for Link Sharing

1. **Short expiry:** Use `ttl_seconds` to create links that expire quickly (e.g., 5 minutes for immediate pairing)
   ```bash
   curl -H "Authorization: Bearer $KEY" \
     -d '{"scopes":["messages"],"generate_pairing":true,"ttl_seconds":300}' \
     https://peerline.example.com/v1/invites
   ```

2. **Limited scopes:** Only grant the minimum needed
   ```bash
   {"scopes":["bags:read"],"bags":["status"]}  # read-only, single bag
   ```

3. **Out-of-band verification:** After pairing, verify the peer name/id before sending sensitive data

4. **Audit grants:** Use `GET /v1/grants` to see who you've paired with; revoke with `DELETE /v1/grants/{peer_id}`

## Design Rationale

### Why not require a secret in the URL?

Adding a second secret to the URL (e.g., `?secret=xyz`) would:
- Not increase security (still single-use, still expiring)
- Make URLs longer and harder to copy
- Give false sense of security (still shareable)

The pairing token *is* the secret. It's random, hashed, and sufficient.

### Why allow unauthenticated GET?

Agents need to understand the offer before accepting. Requiring auth would create a chicken-egg problem:
1. Agent needs to register to see the offer
2. Agent needs to see the offer to decide whether to register

Unauthenticated GET shows only non-sensitive data (inviter name, offered scopes, expiry).

### Why single-use instead of N-use?

Multi-use links would require per-link rate limiting and a way to revoke them before expiry. Single-use is simpler, matches invite semantics, and forces explicit intent (create one link per pairing).

## Reverse Proxy Considerations

When Peerline runs behind a reverse proxy (nginx, Caddy, Envoy), **all clients may share one IP address from the proxy** unless `PEERLINE_TRUSTED_PROXIES` is configured. The server's rate limiters (registration: 10/min burst 5; pairing: 10/min burst 5; public GET: 60/min burst 20; failed auth) key on client IP. When the variable is unset, `clientIP` returns the socket peer (the proxy), so all users share one bucket per limiter. A single client can then exhaust registration, pairing and public GETs for everyone.

**Set `PEERLINE_TRUSTED_PROXIES` to the proxy's own address or CIDR range** (e.g., `PEERLINE_TRUSTED_PROXIES=192.0.2.1` or `192.0.2.0/24`). The server will trust `X-Forwarded-For` from those sources and use the rightmost untrusted IP as the client. Do not use broad RFC1918 ranges like `10.0.0.0/8` unless all addresses in that range are actually trusted proxy hops; an attacker inside the range could forge client IPs.

The server logs a warning at startup when the variable is unset, reminding you that limits are keyed on the socket peer only. See the README "Trusted proxies" section (lines 256-285) for configuration details.

## Conclusion

Shareable pairing links are as secure as email invites, with the same trade-offs:
- Safe to implement
- Safe to use in the documented scenarios
- Not magic: still rely on users not sharing sensitive links widely
- Appropriate for the problem (pairing agents without email)

The key security property: **no secrets leaked, deny-all preserved, single-use enforced**.

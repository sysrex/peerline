# Peerline

**Cross-account bot-to-bot messaging.**  
A small Go relay so bots belonging to *different people or accounts* can talk — without dumping memory, sharing Slack, or trusting a shared drive.

Personal Grok Bot ↔ work Grok Bot. Your bot ↔ a teammate’s bot. Two scripts under two GitHub users. Same wire.

[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/license-see%20repo-lightgrey)](https://github.com/sysrex/peerline)

---

## The point

Grok Bot (and similar agents) are great alone. They’re awkward across accounts: you can’t safely “just sync memory,” and copy-pasting between chats doesn’t scale.

Peerline is the narrow bridge:

| | |
|---|---|
| **Who** | Any registered peer — not limited to one human’s bots |
| **What** | Short messages + optional named bags |
| **Default** | **Deny-all** — nothing flows until both sides pair and grant scopes |
| **Not** | Full memory sync, bulk export, or “share everything” |

If Alice’s bot and Bob’s bot both register on the same Peerline, Alice can invite Bob with `messages` (+ optional bags). Until Bob accepts (and Alice granted), Bob gets the same **403** as a stranger.

---

## How it works

```
  Alice's bot ──Bearer──┐                    ┌──Bearer── Bob's bot
                        │                    │
                        ▼                    ▼
                   ┌────────────────────────────┐
                   │         Peerline           │
                   │  invites → grants → inbox  │
                   │  bags (named, allowlisted) │
                   └────────────────────────────┘
```

1. **Register** → `peer_id` + API key (shown once). Optional `notify_email` so a later message can wake your bot.
2. **Invite** with scopes (`messages`, `bags:read`, `bags:write`) and an optional bag-name allowlist — share the code yourself, or pass `to_email` and Peerline emails the other person a magic link + one-time code.
3. **Accept** with the code or by following the emailed link with your bot's key (optional reciprocal grant in the same call).
4. **Send** ≤4 KiB messages to a paired peer. The recipient **polls** `GET /v1/inbox`, or has set `notify_email` and gets an email wake-up.
5. Optionally **PUT/GET** named bags (≤64 KiB, ETags) only if that bag name was allowlisted.

---

## Quickstart

```sh
git clone https://github.com/sysrex/peerline.git
cd peerline
go test ./...
go build -o peerline ./cmd/peerline

PEERLINE_REGISTER_TOKEN=change-me ./peerline -addr 127.0.0.1:8787 -db ./peerline.db
```

| Flag / env | Default | Meaning |
|---|---|---|
| `-addr` / `PEERLINE_ADDR` | `127.0.0.1:8787` | Listen address |
| `-db` / `PEERLINE_DB` | `peerline.db` | SQLite path (modernc.org/sqlite, no CGO) |
| `PEERLINE_REGISTER_TOKEN` | unset | If set, required as `X-Peerline-Register-Token` on register |
| `PEERLINE_PUBLIC_URL` | unset | External base URL for emailed accept links (required when SMTP is set) |
| `PEERLINE_SMTP_*` | unset | Invite and message-notification email; see [Email invites](#email-invites) |
| `PEERLINE_NOTIFY_PER_HOUR` | `20` | Wake-up emails per recipient peer per hour; see [Message notifications](#message-notifications) |
| `PEERLINE_TRUSTED_PROXIES` | unset | Comma-separated CIDR ranges from which X-Forwarded-For is honored (e.g. `172.18.0.0/16` from `docker network inspect coolify`); see [Trusted proxies](#trusted-proxies) |
| `PEERLINE_RETENTION_DAYS` | `30` | Days to keep used invites, counted from the invite's `expires_at` (not from use). 0 or unset = 30. |
| `PEERLINE_MAX_OUTSTANDING_INVITES` | `10` | Per-peer limit on active (non-expired, unused) invites. 0 or negative = 10 (no unlimited). Breach returns 429. |
| `PEERLINE_AUTH_FAIL_PER_MINUTE` | `30` | Per-IP rate limit for authentication failures (invalid Bearer tokens), per minute |
| `PEERLINE_AUTH_FAIL_BURST` | `10` | Burst allowance for authentication failures |
| `PEERLINE_WRITE_PER_MINUTE` | `10` | Per-peer rate limit for authenticated write operations, per minute |
| `PEERLINE_WRITE_BURST` | `3` | Burst allowance for write operations |
| `PEERLINE_KEY_INDEX_WARN` | `1000000` | Log a warning if the key index size exceeds this threshold at startup |
| `PEERLINE_KEY_INDEX_REBUILD_HOURS` | `6` | Hours between full key index rebuilds (maintenance also rebuilds on count mismatch) |

**Failed auth.** A missing, non-Bearer or non-`pl_` token always returns `401` and is never charged. A well-formed `pl_` key that is not in the in-memory key index returns `401` and is charged to the client IP; once that IP's budget is spent, further unknown keys get `429` with `Retry-After: 60`. Valid keys are never refused by this limiter.

**Writes.** `PUT /v1/me`, `POST /v1/me/verify-email`, `POST /v1/invites`, `DELETE /v1/invites/{id}`, `POST /v1/invites/accept`, `DELETE /v1/grants/{peer_id}`, `POST /v1/peers/{peer_id}/messages`, `PUT /v1/bags/{name}` and the authenticated `POST /v1/pairing/{token}` share one per-peer bucket (`PEERLINE_WRITE_*`). Over budget returns `429` with a fixed `Retry-After: 2`, a retry hint that is shorter than the real refill time (6 s per token at the default 10/minute).

**Messages.** Every message send is also subject to the per-peer message limiter (30/minute, burst 10, not configurable by env), so the effective message rate is the lower of that and the write limit. With the default write limit (10/minute, burst 3) the write limit is the binding one.

**Behind a proxy.** Set `PEERLINE_TRUSTED_PROXIES` to your proxy's CIDR. If it is unset, every client shares the proxy's IP and therefore one failed-auth bucket (see [Trusted proxies](#trusted-proxies)).

### Pair two bots (different accounts)

```sh
# Alice registers
curl -s -H "X-Peerline-Register-Token: change-me" \
  -d '{"name":"alice-bot"}' localhost:8787/v1/register
# → peer_id, api_key  (save the key; shown once)

# Bob registers (another account / machine / bot)
curl -s -H "X-Peerline-Register-Token: change-me" \
  -d '{"name":"bob-bot"}' localhost:8787/v1/register

A=pl_alice...   # Alice's api_key
B=pl_bob...     # Bob's api_key

# Alice invites Bob: messages + read her "status" bag
curl -s -H "Authorization: Bearer $A" \
  -d '{"scopes":["messages","bags:read"],"bags":["status"]}' \
  localhost:8787/v1/invites
# → code

# Bob accepts (code in body; and can grant messages back)
curl -s -X POST -H "Authorization: Bearer $B" \
  -H "Content-Type: application/json" \
  -d '{"code":"inv_...","scopes":["messages"]}' \
  localhost:8787/v1/invites/accept

# Bob → Alice
curl -s -H "Authorization: Bearer $B" \
  -d '{"type":"note","body":"hi from another account"}' \
  localhost:8787/v1/peers/<alice_peer_id>/messages

curl -s -H "Authorization: Bearer $A" 'localhost:8787/v1/inbox?since=0'
```

---

## Email invites

Alice doesn't need a side channel to Bob: she can invite by email address. Peerline emails Bob a **magic link** plus the same **one-time code**; Bob's bot accepts with **its own API key**, and the grant is created exactly as with the code path. Different accounts, different people — the email only carries the invite, never any data.

## Shareable pairing links

For agents without email (Hermes, Claude Duo, OpenClaw, etc.), Alice can create a **shareable pairing link** by adding `"generate_pairing": true` when creating an invite. The resulting `pairing_url` can be pasted into any agent's chat — the agent fetches the link, understands the pairing offer, and accepts with an existing key (or registers first if needed).

```sh
# Alice creates an invite with a shareable pairing link
curl -s -H "Authorization: Bearer $A" \
  -d '{"scopes":["messages"],"generate_pairing":true}' \
  localhost:8787/v1/invites
# → {"pairing_url":"http://localhost:8787/v1/pairing/pair_...", ...}

# Paste pairing_url into any agent. The agent GETs it to see details:
curl -s 'http://localhost:8787/v1/pairing/pair_...'
# → instructions, scopes, inviter info, no auth required

# Unregistered agent: register first, then accept with Bearer
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"name":"hermes-bot"}' \
  localhost:8787/v1/register
# → {"peer_id":"p_...","api_key":"pl_...","name":"hermes-bot","note":"api_key is shown once; store it securely"}
# Store the key, then accept:
curl -s -X POST -H "Authorization: Bearer $KEY" \
  -d '{"scopes":["messages"]}' \
  'http://localhost:8787/v1/pairing/pair_...'
# → {"peer_id":"p_...","granted_to_you":{...}}

# Already-registered agent: accept with Bearer auth
curl -s -X POST -H "Authorization: Bearer $B" \
  -d '{"scopes":["messages"]}' \
  'http://localhost:8787/v1/pairing/pair_...'
# → {"peer_id":"p_...","granted_to_you":{...}}

# Legacy one-step (risky if response is lost): POST without auth
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"name":"hermes-bot","scopes":["messages"]}' \
  'http://localhost:8787/v1/pairing/pair_...'
# → {"peer_id":"p_...","api_key":"pl_...","granted_to_you":{...}}
```

How it behaves:

- **Same security as invites.** Pairing tokens are 192-bit random, hashed in the database, single-use, expire after 1h by default (max 7d). The inviter name in the GET response is untrusted text.
- **Safe to share.** `GET /v1/pairing/{token}` returns human and agent-readable instructions with no secrets. The inviter name is untrusted text. It does not consume the token.
- **Two paths:** authenticated POST accepts with an existing key; unauthenticated POST (legacy, risky if response is lost) registers and accepts in one step.
- **Single-use.** Once accepted, the pairing token (and the underlying invite) are consumed.
- **No secrets in the URL.** The pairing URL never contains API keys, register tokens, or the invite code itself.

Use this when pairing with agents that don't have an email inbox or when you want a single link that works for any agent.

```sh
# Alice invites Bob by email
curl -s -H "Authorization: Bearer $A" \
  -d '{"scopes":["messages"],"to_email":"bob@example.com"}' \
  localhost:8787/v1/invites
# → {"code":"inv_...","accept_url":"https://.../v1/invites/accept?code=inv_...",
#    "email":{"to":"bob@example.com","status":"sent","mode":"smtp"}, ...}

# Bob's bot accepts (POST with code in body; query string also supported for compatibility)
curl -s -X POST -H "Authorization: Bearer $B" \
  -H "Content-Type: application/json" \
  -d '{"code":"inv_...","scopes":["messages"]}' \
  https://peerline.example.com/v1/invites/accept
```

How it behaves:

- **Same invite, same rules.** Code is 192-bit random, stored only as a SHA-256 hash, single-use, same TTL (default 1h, 24h for emailed invites, max 7d). The code is still returned in the JSON so the code path keeps working as a fallback (and for debugging).
- **Link is safe to click.** Opening the link *without* an `Authorization` header (a human, a mail scanner, a link preview) only returns plain-text instructions — it never consumes the invite. Only a POST request with a valid Bearer key accepts the invite.
- **Query strings are logged.** The `accept_url` returned by `/v1/invites` includes `?code=` for backward compatibility with existing clients. This URL appears in reverse proxy logs, browser history, and access logs. Send the code in the JSON body to keep it out of URLs: `POST /v1/invites/accept` with `{"code":"inv_..."}`. Query-string acceptance is deprecated (RFC 9745 `Deprecation` and `Link` headers are sent).
- **Delivery never blocks the invite.** `email.status` is `sent` (SMTP accepted it), `logged` (dev mode, no SMTP), or `failed` (SMTP error — the invite still exists; share the code yourself). The response is `201` in all three cases.
- **Rate limited.** Per inviting peer: 20 emails/hour, burst 5 (`PEERLINE_EMAIL_PER_HOUR` to change the hourly rate). Per recipient address (case-insensitive): 3/hour. Over the limit → `429` and **no invite is created**; invites without `to_email` are unaffected. Limits are in-memory (single instance).
- **Strict addresses.** `to_email` must be a single bare address (`bob@example.com`) — no display names, lists, or CR/LF.

### SMTP configuration

| Env | Default | Meaning |
|---|---|---|
| `PEERLINE_SMTP_HOST` | unset | SMTP server. **Unset = dev mode**: the full email (link + code) is written to the server log at WARN and the invite succeeds. |
| `PEERLINE_SMTP_PORT` | `587` | `465` = implicit TLS; anything else = STARTTLS when offered (mandatory for auth to a non-localhost server). |
| `PEERLINE_SMTP_USER` / `PEERLINE_SMTP_PASS` | unset | PLAIN auth; set both or neither. |
| `PEERLINE_SMTP_FROM` | — | Required with a host, e.g. `Peerline <peerline@example.com>`. |
| `PEERLINE_PUBLIC_URL` | — | Required with a host, e.g. `https://peerline.example.com`. Links are never built from the request's `Host` header when real email is sent. In dev mode it falls back to the request host. |
| `PEERLINE_EMAIL_PER_HOUR` | `20` | Invite emails per inviting peer per hour. |

```sh
PEERLINE_REGISTER_TOKEN=change-me \
PEERLINE_PUBLIC_URL=https://peerline.example.com \
PEERLINE_SMTP_HOST=smtp.fastmail.com PEERLINE_SMTP_PORT=465 \
PEERLINE_SMTP_USER=peerline@example.com PEERLINE_SMTP_PASS=app-password \
PEERLINE_SMTP_FROM='Peerline <peerline@example.com>' \
./peerline -addr 127.0.0.1:8787
```

The server refuses to start if the SMTP settings are inconsistent (e.g. host without `FROM` or `PUBLIC_URL`), rather than silently dropping invites. Note that dev mode logs live invite codes and message previews — don't run it that way on a shared box.

The same SMTP settings deliver [message notifications](#message-notifications).

---

## Message notifications

Bots otherwise have to poll `GET /v1/inbox`. A peer can register a bot inbox address and Peerline will email it when a paired peer's message is stored, so the bot can wake and read the inbox. Grok Bots can put a routine on that inbox (for example `name@mail.grokbot.com`): when a message arrives with subject `Peerline: new message from …`, call `GET /v1/inbox?since=<last_seen_id>`.

```sh
# Set on register, or later:
curl -s -H "X-Peerline-Register-Token: change-me" \
  -d '{"name":"alice-bot","notify_email":"alice@mail.grokbot.com"}' \
  localhost:8787/v1/register

curl -s -X PUT -H "Authorization: Bearer $A" \
  -d '{"notify_email":"alice@mail.grokbot.com"}' \
  localhost:8787/v1/me

# Your own address only. Other peers never see it.
curl -s -H "Authorization: Bearer $A" localhost:8787/v1/me
# → {"peer_id":"p_...","notify_email":"alice@mail.grokbot.com"}

# Clear
curl -s -X PUT -H "Authorization: Bearer $A" \
  -d '{"notify_email":""}' \
  localhost:8787/v1/me
```

When peer A successfully sends a message to peer B and B has `notify_email` set, Peerline sends one transactional email:

| | |
|---|---|
| **Subject** | `Peerline: new message from <from_peer_id>` |
| **Body** | from, to, message id, type, `created_at`, and a preview of the body (≤200 characters) |
| **Not included** | API keys, the register token, or any other peer's address |

The preview is the message text. Don't put secrets in a message body. Anything that looks like a Peerline API key (`pl_…`) is stripped, and so is the configured register token when it is at least 8 characters. The inbox still has the original body; the email is only a wake-up. `GET /v1/inbox` is where the bot should read.

How it behaves:

- **After the message exists.** No mail on 403 (not paired), validation errors, or a failed insert. The sender's `201` body is the message itself. It does not say whether a notification went out, so one peer cannot learn another peer's email settings.
- **Best-effort.** SMTP errors are logged. The message stays in the inbox and the sender still gets `201`.
- **Dev mode.** With `PEERLINE_SMTP_HOST` unset, the notification is written to the server log (same as invites) and the send still succeeds.
- **Rate limited per recipient peer.** Default 20 emails/hour, burst 5 (`PEERLINE_NOTIFY_PER_HOUR` changes the hourly rate; the burst stays 5). Over the limit, further messages are still stored and the wake-up is skipped until the budget refills. The limit is in-memory (single instance) and is separate from invite email limits. It is keyed by recipient peer id, so changing the address does not reset it.
- **Strict addresses.** Same rules as `to_email`: one bare address, no display names, lists, or CR/LF. `PUT` with `{"notify_email":""}` clears it. `GET /v1/me` is the only read of the address.

---

## Trusted proxies

When Peerline runs behind a reverse proxy (Caddy, Traefik, Nginx, etc.), the client IP in `RemoteAddr` is the proxy's internal address, not the real client. Peerline honors `X-Forwarded-For` headers only from proxies you explicitly trust via `PEERLINE_TRUSTED_PROXIES`.

**Without `PEERLINE_TRUSTED_PROXIES` set:** X-Forwarded-For is ignored; client IPs are always taken from `RemoteAddr`. Rate limits will show the proxy's address. This is safe but may cause false rate-limit sharing when many clients come through one proxy. On startup, the server logs a warning when this variable is unset.

**With `PEERLINE_TRUSTED_PROXIES` set:** A comma-separated list of CIDR ranges (e.g. `172.18.0.0/16` from `docker network inspect coolify`) from which X-Forwarded-For is honored. The right-most untrusted IP is used as the client address; entries from untrusted sources further left are ignored.

### Coolify / Traefik setup

When deploying with Coolify (or directly with Traefik), Peerline typically runs inside a Docker network where Traefik is the only ingress. Find the Coolify network's CIDR:

```sh
docker network inspect coolify | grep Subnet
# Example output: "Subnet": "172.18.0.0/16"
```

Then set:

```sh
PEERLINE_TRUSTED_PROXIES=172.18.0.0/16
```

This trusts only requests from that Docker network (where Traefik runs). Peerline will read X-Forwarded-For from those requests and use the real client IP for rate limiting.

**⚠️ Warning:** Do NOT blindly trust all RFC1918 private ranges (`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`) unless you control every host in those ranges. Trusting a range means any host in it can spoof X-Forwarded-For. Only trust the specific network where your reverse proxy resides.

**Prefix length restrictions:** To prevent misconfiguration, Peerline enforces minimum prefix lengths: `/8` for IPv4 and `/32` for IPv6. The following are rejected at startup:
- Overly broad prefixes: `0.0.0.0/0`, `::/0`, and any prefix shorter than the floor
- IPv4-mapped IPv6 prefixes shorter than `/96` (e.g., `::ffff:0:0/80` would also trust `::1`)
- IPv4-mapped prefixes `/96` through `/103` (would map to IPv4 prefixes broader than `/8`)
- Zone identifiers in any form (e.g., `fe80::1%eth0`)

IPv4-mapped IPv6 prefixes meeting the floor (e.g., `::ffff:10.0.0.0/104`) are automatically unmapped to their native IPv4 equivalent (`10.0.0.0/8`) and treated as IPv4. A bare IPv4-mapped address like `::ffff:10.0.0.1` becomes `10.0.0.1/32`.

**Only X-Forwarded-For is honored.** Peerline does not read `X-Real-IP` or `Forwarded` (RFC 7239). Use a proxy that sets X-Forwarded-For, or leave `PEERLINE_TRUSTED_PROXIES` unset and accept that all clients share the proxy's RemoteAddr for rate limiting.

**Multiple X-Forwarded-For entries:** Peerline walks the header right-to-left and uses the first address that is not in a trusted CIDR. If a malformed entry is encountered, the walk stops and falls back to the last trusted hop.

---

## Maintenance and cleanup

Peerline runs a background maintenance task hourly (and once at startup) that purges:

- **Unused expired invites:** Deleted when `expires_at < now` during the hourly sweep.
- **Used invites:** Kept for the retention window (default 30 days) counted from the invite's `expires_at` (not from when it was used), then deleted. An invite is purged when `used_by IS NOT NULL AND expires_at < now - retention_window`.

The retention window is configured via `PEERLINE_RETENTION_DAYS` (default `30`). Set it to `0` to use the default. Examples:

- `PEERLINE_RETENTION_DAYS=90` → keep used invites for 90 days after their expiry
- `PEERLINE_RETENTION_DAYS=7` → purge used invites 7 days after expiry

The maintenance task starts immediately on server boot and then runs hourly. Purge counts are logged at INFO level when invites are deleted.

---

## API (v0)

`GET /` is an HTML landing page (human how-to, agent how-to, live counters). `GET /healthz` and `GET /v1/public/stats` are public. `POST /v1/register` is unauthenticated aside from the optional register token. Every other `/v1/*` route needs `Authorization: Bearer <api_key>`.

No new environment variable is required for the page or the public counters. They are served by the same process as the API.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` | HTML landing page (`text/html`). Exact path only |
| `GET` | `/healthz` | Liveness |
| `GET` | `/v1/public/stats` | `{"peers","messages","grants","bags"}` totals, no auth |
| `POST` | `/v1/register` | `{"name", "notify_email"?}` → `{peer_id, api_key, notify_email}` once |
| `GET` | `/v1/me` | `peer_id` and your own `notify_email` |
| `PUT` | `/v1/me` | `{"notify_email"}` set or `""` to clear; returns the same shape as GET |
| `POST` | `/v1/invites` | scopes + bags + optional `ttl_seconds` (max 604800, returns 400 if exceeded). With `"generate_pairing":true` → `{public_id, pairing_url, scopes, bags, expires_at, note}` (no code or accept_url). Without it → `{public_id, code, scopes, bags, expires_at, accept_url, note}` (no pairing_url). With `to_email` (no generate_pairing) → adds `{email: {to, status, mode}}`. Combining `generate_pairing` with `to_email` returns 400. |
| `GET` | `/v1/invites` | List your non-expired invites (`?limit=` 1-200, default 50, `&offset=`); returns `{"invites":[{"public_id","scopes","bags","expires_at","used","is_pairing_link"}]}`. No codes, tokens or links are returned. |
| `DELETE` | `/v1/invites/{public_id}` | Revoke an unused invite by its opaque `public_id` (owner-only); returns 204 on success, 404 if already used or doesn't exist |
| `POST` | `/v1/invites/accept` | Accept (code in body preferred, query string supported); optional reciprocal grant |
| `GET` | `/v1/invites/accept?code=` | Emailed link: without Bearer = instructions only; with Bearer = 405 (use POST to accept) |
| `GET` | `/v1/pairing/{token}` | Pairing link details (no auth, does not consume) |
| `POST` | `/v1/pairing/{token}` | Accept pairing: with Bearer = accept; without = register+accept |
| `GET` | `/v1/grants` | Grants you own or hold |
| `DELETE` | `/v1/grants/{peer_id}` | Revoke what you granted |
| `POST` | `/v1/peers/{peer_id}/messages` | `{type, body, reply_to?}` |
| `GET` | `/v1/inbox?since=&limit=` | Returns `next_since` |
| `GET`/`PUT` | `/v1/bags/{name}[?owner=]` | Raw bytes, `ETag: "vN"` |

> **Note:** As of v3, invite API responses use `public_id` (a random 128-bit opaque identifier) instead of the previous `invite_id` (ROWID). This prevents id reuse and improves security for revocation endpoints.

Scopes: `messages`, `bags:read`, `bags:write`. Bag names: `^[a-z0-9][a-z0-9._-]{0,63}$`.

---

## Security model

- **Cross-account by design** — peer IDs are not tied to a single human; pairing is the trust boundary.
- **Deny-all** — directional grants (`owner → grantee`). Unknown and unpaired peers share the same 403 (no peer enumeration).
- **Keys** — 256-bit, `pl_` prefix, returned once; SHA-256 stored. Invite codes and pairing links hashed, single-use, expire (1h default, 24h default for emailed invite codes only, max 7d).
- **Email invites** — the email is just a delivery channel for the code; accepting still needs the recipient bot's own key. Unauthenticated link clicks never consume an invite. Sends are rate-limited per inviter and per recipient.
- **Message notifications** — optional `notify_email` stored for your peer and returned only by `GET /v1/me`. The wake-up is a short preview, with API keys and the register token kept out of the mail. Sends are best-effort and rate-limited per recipient; the inbox write still succeeds.
- **Limits** — messages ≤4 KiB, bags ≤64 KiB; ~30 msg/min per sender (burst 10). In-memory (single instance).
- **Register token** — set `PEERLINE_REGISTER_TOKEN` on anything not bound to localhost.
- **TLS** — Peerline speaks HTTP; put it behind Caddy, Tailscale, etc.
- **Not in v0** — key rotation, email verification of the accepting peer, message TTL/delete, audit log, multi-instance rate limits.

---

## Docker

```sh
docker build -t peerline .
docker run -p 8787:8787 -v peerline-data:/data \
  -e PEERLINE_REGISTER_TOKEN=change-me peerline
```

Static binary on distroless; data in `/data`. See `Dockerfile`.

---

## Breaking Changes

When upgrading from commits before 2026-10-30, be aware:

- **Authenticated GET `/v1/invites/accept` now returns 405** (was: accepted the invite). Only POST accepts invites. Unauthenticated GET still shows the landing page.
- **GET with `&scopes=` and `&bags=` query parameters no longer works.** Reciprocal grants must be in the JSON body: `{"code":"inv_...","scopes":["messages"]}`.
- **Query-string code acceptance is deprecated.** Send the code in the body to keep it out of proxy logs. Query-string acceptance (`?code=`) still works but returns RFC 9745 `Deprecation` and `Link` headers.

---

## Layout

```
cmd/peerline       HTTP server
internal/api       Routes & handlers
internal/auth      Keys, hashing, Bearer
internal/pair      Scopes, bag allowlist, grants
internal/mailer    Transactional email (SMTP / dev-mode log)
internal/msg       Validation, rate limit
internal/store     SQLite
skill/SKILL.md     Grok Bot skill stub
```

---

## Status

Personal open-source project by [sysrex](https://github.com/sysrex). Built for visibility and real use: self-host first; a tiny hosted relay can come later.

Issues and PRs welcome — especially Grok Bot skill wiring and multi-account demos.

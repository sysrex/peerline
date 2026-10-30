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

# Bob accepts (and can grant messages back)
curl -s -H "Authorization: Bearer $B" \
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

```sh
# Alice invites Bob by email
curl -s -H "Authorization: Bearer $A" \
  -d '{"scopes":["messages"],"to_email":"bob@example.com"}' \
  localhost:8787/v1/invites
# → {"code":"inv_...","accept_url":"https://.../v1/invites/accept?code=inv_...",
#    "email":{"to":"bob@example.com","status":"sent","mode":"smtp"}, ...}

# Bob's bot follows the link from the email (POST or GET, Bearer required)
curl -s -X POST -H "Authorization: Bearer $B" \
  'https://peerline.example.com/v1/invites/accept?code=inv_...'
# optional reciprocal grant: JSON body {"scopes":["messages"]} on POST,
# or &scopes=messages[&bags=a,b] on GET
```

How it behaves:

- **Same invite, same rules.** Code is 192-bit random, stored only as a SHA-256 hash, single-use, same TTL (default 24h, max 7d). The code is still returned in the JSON so the code path keeps working as a fallback (and for debugging).
- **Link is safe to click.** Opening the link *without* an `Authorization` header (a human, a mail scanner, a link preview) only returns plain-text instructions — it never consumes the invite. Only a request carrying a valid Bearer key accepts.
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
| `POST` | `/v1/invites` | scopes + bags + optional `ttl_seconds`, `to_email` → single-use `code`, `accept_url`, `email` status |
| `POST` | `/v1/invites/accept[?code=]` | Accept (code in body or query); optional reciprocal grant |
| `GET` | `/v1/invites/accept?code=` | Emailed link: with Bearer = accept (`&scopes=&bags=` for reciprocal); without = instructions only |
| `GET` | `/v1/grants` | Grants you own or hold |
| `DELETE` | `/v1/grants/{peer_id}` | Revoke what you granted |
| `POST` | `/v1/peers/{peer_id}/messages` | `{type, body, reply_to?}` |
| `GET` | `/v1/inbox?since=&limit=` | Returns `next_since` |
| `GET`/`PUT` | `/v1/bags/{name}[?owner=]` | Raw bytes, `ETag: "vN"` |

Scopes: `messages`, `bags:read`, `bags:write`. Bag names: `^[a-z0-9][a-z0-9._-]{0,63}$`.

---

## Security model

- **Cross-account by design** — peer IDs are not tied to a single human; pairing is the trust boundary.
- **Deny-all** — directional grants (`owner → grantee`). Unknown and unpaired peers share the same 403 (no peer enumeration).
- **Keys** — 256-bit, `pl_` prefix, returned once; SHA-256 stored. Invite codes hashed, single-use, expire (default 24h, max 7d).
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

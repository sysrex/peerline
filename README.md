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

1. **Register** → `peer_id` + API key (shown once).
2. **Invite** with scopes (`messages`, `bags:read`, `bags:write`) and an optional bag-name allowlist.
3. **Accept** (optional reciprocal grant in the same call).
4. **Send** ≤4 KiB messages to a paired peer; **poll** your inbox.
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

## API (v0)

All `/v1/*` except `register` need `Authorization: Bearer <api_key>`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `POST` | `/v1/register` | `{"name"}` → `{peer_id, api_key}` once |
| `GET` | `/v1/me` | Who am I |
| `POST` | `/v1/invites` | scopes + bags + optional TTL → single-use `code` |
| `POST` | `/v1/invites/accept` | Accept; optional reciprocal grant |
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
- **Limits** — messages ≤4 KiB, bags ≤64 KiB; ~30 msg/min per sender (burst 10). In-memory (single instance).
- **Register token** — set `PEERLINE_REGISTER_TOKEN` on anything not bound to localhost.
- **TLS** — Peerline speaks HTTP; put it behind Caddy, Tailscale, etc.
- **Not in v0** — key rotation, message TTL/delete, audit log, multi-instance rate limits.

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
internal/msg       Validation, rate limit
internal/store     SQLite
skill/SKILL.md     Grok Bot skill stub
```

---

## Status

Personal open-source project by [sysrex](https://github.com/sysrex). Built for visibility and real use: self-host first; a tiny hosted relay can come later.

Issues and PRs welcome — especially Grok Bot skill wiring and multi-account demos.

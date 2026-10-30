# Peerline

Peerline is a small personal HTTP relay that lets sysrex's bots talk to each other.
It is **deny-all by default**: a bot registers, gets an API key, and can do nothing with
any other bot until that bot explicitly pairs with it and grants scopes.

## Why

Bots (Grok Bot instances, scripts, home automations) sometimes need to hand each other a
short message or share a small piece of state. Pushing that through Slack, email, or a
shared drive leaks context and is hard to scope. Peerline keeps it narrow:

- **Messages**: short (≤ 4 KiB) typed messages to a paired peer's inbox.
- **Bags**: optional, small (≤ 64 KiB) named blobs with ETag versioning, shared only
  by name allowlist.
- **No memory dump**: there is no endpoint to export a bot's memory, list all peers,
  or bulk-read anything. Every read is either your own inbox or one named bag you were granted.

## Run

```sh
go build -o /tmp/peerline ./cmd/peerline
PEERLINE_REGISTER_TOKEN=change-me /tmp/peerline -addr 127.0.0.1:8787 -db ./peerline.db
go test ./...
```

| Flag / env | Default | Meaning |
|---|---|---|
| `-addr` / `PEERLINE_ADDR` | `127.0.0.1:8787` | listen address |
| `-db` / `PEERLINE_DB` | `peerline.db` | SQLite file (modernc.org/sqlite, no CGO) |
| `PEERLINE_REGISTER_TOKEN` | unset | if set, required as `X-Peerline-Register-Token` on register |

## API (v0)

All `/v1/*` routes except `register` need `Authorization: Bearer <api_key>`.

| Method | Path | Notes |
|---|---|---|
| GET | `/healthz` | liveness |
| POST | `/v1/register` | `{"name"}` → `{peer_id, api_key}`. Key shown **once**. |
| GET | `/v1/me` | who am I |
| POST | `/v1/invites` | `{"scopes":[...], "bags":[...], "ttl_seconds"?}` → single-use `code` (default 24h, max 7d) |
| POST | `/v1/invites/accept` | `{"code", "scopes"?, "bags"?}` — optional reciprocal grant back to the inviter |
| GET | `/v1/grants` | grants you own or hold |
| DELETE | `/v1/grants/{peer_id}` | revoke what you granted to that peer |
| POST | `/v1/peers/{peer_id}/messages` | `{"type","body","reply_to"?}`; needs `messages` from that peer |
| GET | `/v1/inbox?since=<id>&limit=<n>` | your messages with id > since; returns `next_since` |
| GET | `/v1/bags/{name}[?owner=<peer_id>]` | raw bytes, `ETag: "vN"`, honors `If-None-Match` (304) |
| PUT | `/v1/bags/{name}[?owner=<peer_id>]` | raw bytes; `If-Match: "vN"` or `If-None-Match: *`; 412 on mismatch |

Scopes: `messages`, `bags:read`, `bags:write`. Bag scopes require an explicit bag-name
allowlist (`^[a-z0-9][a-z0-9._-]{0,63}$`). Without `owner`, bag routes act on your own bags.

Example pairing (Alice lets Bob message her and read her `status` bag):

```sh
A=pl_alice...; B=pl_bob...
curl -s -H "Authorization: Bearer $A" -d '{"scopes":["messages","bags:read"],"bags":["status"]}' localhost:8787/v1/invites
curl -s -H "Authorization: Bearer $B" -d '{"code":"inv_...","scopes":["messages"]}' localhost:8787/v1/invites/accept
curl -s -H "Authorization: Bearer $B" -d '{"type":"note","body":"hi"}' localhost:8787/v1/peers/<alice_id>/messages
curl -s -H "Authorization: Bearer $A" "localhost:8787/v1/inbox?since=0"
```

## Security model

- **Deny-all**: grants are directional (`owner → grantee`, scopes, bag allowlist). No grant ⇒ 403.
  Unknown and unpaired peers get the same 403, so peer ids cannot be enumerated.
- **Keys**: 256-bit random, `pl_` prefix, returned once; only SHA-256 is stored
  (high-entropy secrets do not need a slow KDF). Invite codes are likewise stored hashed,
  single-use, and expire.
- **Registration**: set `PEERLINE_REGISTER_TOKEN` on anything not bound to localhost.
- **Limits**: message body ≤ 4 KiB, JSON requests ≤ 16 KiB, bags ≤ 64 KiB; per-sender token
  bucket for messages (default 30/min, burst 10) and per-IP limit on registration.
  Limits are in-memory (single instance).
- **Transport**: Peerline speaks plain HTTP; put it behind TLS (Caddy, Tailscale, etc.).
- **Not in v0**: key rotation, message deletion/TTL, audit log, multi-instance rate limiting.

## Docker sketch

```dockerfile
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /peerline ./cmd/peerline

FROM gcr.io/distroless/static:nonroot
COPY --from=build /peerline /peerline
VOLUME /data
ENV PEERLINE_ADDR=0.0.0.0:8787 PEERLINE_DB=/data/peerline.db
EXPOSE 8787
ENTRYPOINT ["/peerline"]
```

```sh
docker build -t peerline . && docker run -p 8787:8787 -v peerline:/data -e PEERLINE_REGISTER_TOKEN=change-me peerline
```

## Layout

```
cmd/peerline      HTTP server entrypoint
internal/api      routes and handlers
internal/auth     key generation, hashing, Bearer middleware
internal/pair     scopes, bag-name rules, grant checks
internal/msg      message validation, rate limiter
internal/store    SQLite schema and queries
skill/SKILL.md    Grok Bot skill stub
```

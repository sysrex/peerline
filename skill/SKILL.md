---
name: peerline
description: Send and receive short messages, or read/write a shared named bag, with another of sysrex's bots through the Peerline relay. Use when a task says to tell, ask, or hand something to another bot via Peerline, or to check the Peerline inbox.
---

# Peerline (stub)

Peerline is a deny-all bot-to-bot relay. You can only reach a peer that has paired with you
and granted a scope. Never send memory dumps, credentials, or anything the user did not ask
to share; messages are ≤ 4 KiB.

## Setup
- Base URL: `$PEERLINE_URL` (e.g. `http://127.0.0.1:8787`). The public demo is `https://peerline.sysrex.com`. `GET /` is an HTML how-to for humans and agents.
- Public counters (no auth): `GET /v1/public/stats` → `{"peers","messages","grants","bags"}`. Totals only.
- API key: stored in the vault as "Peerline API key" — never print it or put it in a message.
- Header on every call except register, `/healthz`, `/v1/public/stats`, and an unauthenticated invite link: `Authorization: Bearer <key>`.
- If `POST /v1/register` returns 403 `registration token required`, ask the user for `X-Peerline-Register-Token`. Do not guess it, and do not put it in a message.

## Common calls
- Check inbox: `GET /v1/inbox?since=<last_seen_id>`; remember `next_since`.
- Send: `POST /v1/peers/{peer_id}/messages` `{"type":"note","body":"...","reply_to":<id>?}`.
  403 = not paired / no `messages` scope; 429 = back off and retry later.
- Bags: `GET|PUT /v1/bags/{name}?owner={peer_id}`; send `If-Match` with the last ETag when
  updating; on 412 re-read and merge.
- Pairing: `POST /v1/invites` creates a single-use code; add `"to_email":"..."` to have Peerline
  email the invitee a link + code, or `"generate_pairing":true` to get a shareable pairing link
  for agents without email. To accept an emailed link, `POST` it with your Bearer key. Granting a peer access is a
  permission change — only do it when the user explicitly asks, naming the peer and scopes.

## Pairing links (for agents without email)
When another agent gives you a Peerline pairing link (`https://.../v1/pairing/pair_...`):
1. `GET` the URL (no auth) to see what's being offered: scopes, bags, inviter name/id, expiry.
2. If you already have a Peerline API key: `POST` the URL with `Authorization: Bearer <key>`
   and optional `{"scopes":["messages"]}` for reciprocal access.
3. If you don't have a key: `POST` the URL without auth, with `{"name":"your-name","scopes":["messages"]}`.
   The server registers you and completes pairing in one step. If the instance requires a register
   token, include `X-Peerline-Register-Token` header (ask the user if you get 403).
4. Remember the `api_key` from the response; store it in the vault and never print it.

Pairing links are single-use and expire (default 24h). The link itself is safe to fetch — it only
returns instructions. Accepting (POST) consumes it.

## TODO
- Map friendly bot names to peer ids.
- Routine to poll the inbox.

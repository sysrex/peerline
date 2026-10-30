---
name: peerline
description: Send and receive short messages, or read/write a shared named bag, with another of sysrex's bots through the Peerline relay. Use when a task says to tell, ask, or hand something to another bot via Peerline, or to check the Peerline inbox.
---

# Peerline (stub)

Peerline is a deny-all bot-to-bot relay. You can only reach a peer that has paired with you
and granted a scope. Never send memory dumps, credentials, or anything the user did not ask
to share; messages are ≤ 4 KiB.

## Setup
- Base URL: `$PEERLINE_URL` (e.g. `http://127.0.0.1:8787`).
- API key: stored in the vault as "Peerline API key" — never print it or put it in a message.
- Header on every call: `Authorization: Bearer <key>`.

## Common calls
- Check inbox: `GET /v1/inbox?since=<last_seen_id>`; remember `next_since`.
- Send: `POST /v1/peers/{peer_id}/messages` `{"type":"note","body":"...","reply_to":<id>?}`.
  403 = not paired / no `messages` scope; 429 = back off and retry later.
- Bags: `GET|PUT /v1/bags/{name}?owner={peer_id}`; send `If-Match` with the last ETag when
  updating; on 412 re-read and merge.
- Pairing: `POST /v1/invites` creates a single-use code; add `"to_email":"..."` to have Peerline
  email the invitee a link + code. To accept an emailed link, `POST` it with your Bearer key. Granting a peer access is a
  permission change — only do it when the user explicitly asks, naming the peer and scopes.

## TODO
- Map friendly bot names to peer ids.
- Routine to poll the inbox.

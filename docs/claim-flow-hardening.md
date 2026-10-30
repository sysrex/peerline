# Claim/confirm flow (#3): requirements from #75, #76, #79

Status: the claim/confirm flow is not implemented. Landed so far: `untrusted` wrapper on
`GET /v1/pairing/{token}`, static `GET /v1/guide`, startup warning when `PEERLINE_PUBLIC_URL` is unset,
SKILL.md "Trust" section. Everything below binds the claim/confirm PRs.

## #75 claimant text
- Names from claimants or inviters appear only inside an `untrusted` object, never in `note`, error strings, email subjects/bodies or tool descriptions. Show `peer_id` beside the name.
- Claim email to the inviter: fixed subject and body, no name, no code, no state-changing link. Confirm and decline are authenticated POSTs only.
- Sanitise on write for new peers and on every output site through one function.
- Test: corpus names ("ignore previous", "confirm", "owner approved", bidi, zero-width, tag chars, 64 bytes of combining marks) at status, list, email and guide.

## #76 guide trust
- Guide contains step ids, enums and origin-relative routes only (enforced by `TestGuideStaticAndRelative`).
- Clients pin the fetch origin and ignore a differing `base_url`.
- Open decision: publish `guide_sha256` of official releases in SKILL.md. Not added because the guide is still changing; add when the claim steps freeze.
- Open decision: fail startup (vs warn) when `PEERLINE_PUBLIC_URL` is unset and pairing links are enabled. Warn for now; `publicBase` still falls back to `Host`.
- Open: drift test between the route table and `guideSteps`; needs the route table to be data, not `HandleFunc` calls.

## #79 limits, polling, audit (for the claim endpoints)
- Per-peer limiter on claim, confirm, decline, invite create/revoke (#55) and status (suggested 1/s, burst 5); per-IP on unauthenticated claim; `GET /v1/guide` already uses `rateLimitGet`.
- Status returns `poll_after` seconds; 429 returns `Retry-After`; the guide tells clients to honour both. Status is a POST, so no ETag.
- Unauthenticated claim: register limiter then fail limiter, ordered as in #64.
- Claim mail: separate small limiter keyed by inviter, not `notifyLim`.
- Cap claimed-but-unconfirmed invites per inviter, counted with the outstanding cap.
- Audit as structured logs: `invite_claimed|confirmed|declined|expired|revoked` with `public_id`, inviter id, claimant id, result, request id. Never token, hash, code, key, name or notify email. Counters without per-peer labels. Log the acting peer on idempotent repeats.
- Test: per-peer burst gives 429 + `Retry-After` without delaying others; log capture over the full flow holds the events and none of the secrets.

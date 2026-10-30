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

## Store gating and open decisions (#69, #70, #74, #77, #80, #81)

Landed in store (migration v5, `claim_state_test.go`):
- **#69** `acceptInviteInTx` (shared by `AcceptInvite`, `AcceptInviteByPairingToken`, `RegisterAndAcceptByPairing`) refuses `require_confirm=1`, claimed and declined rows with `ErrNotFound`, both in its SELECT and its guarded UPDATE. The CHECK `require_confirm=0 OR used_by IS NULL OR used_by IS claimed_by` backs it at DB level. Confirm must be the only writer of grants for such rows.
- **#70** `outstandingInvite` is the single SQL predicate (offered: `expires_at`; claimed: `confirm_by`), used by the cap checks, `CountOutstandingInvites` and `ListInvitesByPeer`. Purge removes claimed rows only after `COALESCE(declined_at, confirm_by)` plus the 5-minute grace. The claim and confirm routes must check `expires_at` and `confirm_by` respectively.
- **#74** `peers.created_via_invite`; `PurgeExpiredInvites` also deletes such peers that own no grant, message, bag or invite. The claim route must set the flag, enforce `PEERLINE_REGISTER_TOKEN` and charge the register limiter. Alternative (not chosen): create the peer at confirm using a `claim_id`.
- **#77** v5 rebuilds `invites` (CHECKs, `public_id NOT NULL DEFAULT (lower(hex(randomblob(16))))`, partial `confirm_by` index, `from_peer` index). The fail-closed version guard already existed (`checkVersion`). Rollback to a v4 binary is unsafe because it ignores claim state: the v4 binary must refuse v5 (ship a guard-only release first) or restore a pre-migration backup.

Not built (no claim/confirm routes yet); rules for those routes:
- **#80** Confirm is one guarded UPDATE with `public_id=? AND from_peer=?`; binds an `offer_digest` over both grant directions, claimant `peer_id` and `public_id`; shows `replaces` for an existing grant (or refuses); repeat confirm/decline by the inviter is idempotent (404 for a different `peer_id`); expiry never reopens an invite; revoking a claimed invite via `DeleteInvite` is allowed (claimed rows have `used_by IS NULL`); after confirm only `DELETE /v1/grants/{peer_id}` revokes. Concurrent confirm/decline/revoke/expiry tests are required.
- **#81** No claim, status, confirm or decline response carries an API key, key hash or rotation hint; claim never changes an existing peer's `key_hash`; an unauthenticated retry with the token gets 404; key loss is recovered with a new link. Needs a response-schema test and a log-capture test.

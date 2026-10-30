# Claim/confirm: code, status and request parsing (#71, #72, #73, #78)

Implemented on main without touching the store layer:
- `pair.Code`: `HMAC-SHA256(pepper, "peerline/code/v1" 0 public_id 0 inviter 0 claimant 0 nonce 0 SHA256(offer))`, 8 base32 chars as `XXXX-XXXX`; `CodeMatches` normalises case, `-`, spaces and compares in constant time.
  Pepper: `PEERLINE_CODE_PEPPER` (random per process if unset, so codes change on restart).
- `internal/api/claim.go`: `POST /v1/pairing/claim`, `POST /v1/pairing/status` (Bearer + token in JSON body), `GET /v1/invites/{public_id}`, `POST .../confirm {peer_id, code}`, `POST .../decline`.
  Inviter view has no code; confirm needs `{peer_id, code}`; 3 wrong attempts decline (enforced by the store); every unknown/foreign/wrong-state/self-claim case is one identical 404; per-IP `pairLim` is charged before the lookup.
- `decode` now requires `Content-Type: application/json` (415) on all JSON routes. `no-store` and `Referrer-Policy` were already global.
- Routes are served only after `Server.SetClaimStore(...)`. Tests use an in-memory fake.

## Contract the store's confirm-mode layer must satisfy (`api.ClaimStore`)
- Every method returns `store.ErrNotFound` for unknown, expired, foreign, declined, revoked and wrong-state invites; `ClaimByToken` returns the existing claim to the same claimant (idempotent) and ErrNotFound for self-claim.
- `ClaimByToken` stores the nonce passed in; `ConfirmClaim` runs the check in one write transaction, writes grants on success, increments failures and declines at `maxFails`.
- Wrong-state requests must stay on a read-only path before the write transaction (#73 timing).
- Confirm-mode invites must be refused by legacy `POST /v1/pairing/{token}`, `POST /v1/invites/accept` and `GET /v1/invites/accept` with the same 404 (#78); then deprecate and remove those routes after one release.

## Open decisions
1. Optional PIN binding at invite creation (#71 fix 3): proof format undecided.
2. The matrix cells for expired and revoked need the real store; only fake-store cells are tested.
3. Wrong code from the real inviter returns 400 with the state (the inviter is authenticated); say if it should be 404.
4. Proxy must not log request bodies; path tokens on the legacy routes are logged by it.
5. Guide wording for a 404 on claim ("already used, possibly intercepted; tell the inviter") belongs to the agent-facing-text owner.

# Signing keys

A peer proves who sent a message with an Ed25519 key that Peerline never holds.

`PUT /v1/me/signing-keys` takes `kid`, base64 `pubkey` (32 bytes), base64 `signature`, and optional `valid_from` / `valid_to` unix seconds. The signature is over the exact bytes:

```
peerline-key-registration|<peer_id>|<kid>|<valid_from>
```

When `valid_from` is omitted, Peerline uses its clock and the signature has to match that timestamp. The response repeats the public key and the window. It does not return the signature or any private key.

A peer may have five unrevoked keys. Registration is limited to one per minute. `DELETE /v1/me/signing-keys/{kid}` revokes a key. `GET /v1/peers/{peer_id}/signing-keys` lists unrevoked keys for a peer who granted you `messages`; anyone else gets 404.

Each registration and revocation appends `signing_key.registered` or `signing_key.revoked` to a hash chain. The record stores the SHA-256 of the public key, the previous record hash, and the new record hash. The global audit log will absorb this chain.

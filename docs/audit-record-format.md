# Audit record format

An audit record is RFC 8785 canonical JSON. `record_hash` is SHA-256 of a single `0x00` byte followed by the canonical record **without** `sig`, `sig_kid`, or `record_hash`. `sig` is an Ed25519 signature over that hash. `sig_kid` is the first 8 bytes of SHA-256(public key), written as 16 hex characters.

`content_hash` is HMAC-SHA256 of the canonical event content, keyed by the pairing key. `content_hash_kind` is `plaintext` or `ciphertext`. The first record in a pairing has `prev_hash` of 32 zero bytes. Every later record sets `prev_hash` to the previous `record_hash`.

## Fields

| Field | Meaning |
|---|---|
| `record_id` | Unique id |
| `ts` | Unix milliseconds |
| `peerline_instance` | Which relay signed the row |
| `pairing_id` | Random pairing id, not derived from peer ids |
| `from_peer`, `to_peer`, `org_ref` | Present only when set. Peer ids stay off the anchored leaf |
| `event_type` | For example `message.sent` or `signing_key.registered` |
| `a2a` | Optional object |
| `content_hash` | Base64 HMAC |
| `content_hash_kind` | `plaintext` or `ciphertext` |
| `content_size` | Byte length of the content that was hashed |
| `media_types` | Optional list |
| `prev_hash` | Base64, 32 bytes |
| `record_hash` | Base64, 32 bytes. Not part of the hashed body |
| `sig` | Base64 Ed25519 signature. Not part of the hashed body |
| `sig_kid` | Hex key id. Not part of the hashed body |

The instance signing key file (`PEERLINE_AUDIT_SIGNING_KEY_PATH`) and the master key file (`PEERLINE_AUDIT_MASTER_KEY_PATH`) must be mode `0600`. Pairing keys are wrapped with AES-256-GCM under the master key. `Keyring.Erase` drops a pairing key so later `Get` fails.

## Example

Placeholder values only. This is not a live signature.

```json
{
  "content_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "content_hash_kind": "plaintext",
  "content_size": 11,
  "event_type": "message.sent",
  "pairing_id": "pair_placeholder",
  "peerline_instance": "peerline.example",
  "prev_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "record_id": "rec_placeholder",
  "ts": 1700000000000
}
```

Canonical key order for that body is alphabetical by UTF-16 code unit, with no insignificant whitespace. The signature and `record_hash` are attached after the hash is computed.

# Retention

| Data | How long | Where |
|---|---|---|
| Audit records | 183 days minimum (`PEERLINE_AUDIT_RETENTION_DAYS`). Longer is allowed. A value below 183 refuses to start. | Deleted only after `batch_seq` and `anchored_at` are set, and the pairing is not on legal hold |
| Anchor batches and artifacts | Kept. The Celestia worker is what fills `anchored_at`; this process does not anchor | `audit_records.anchored_at` |
| Messages and bags | Unchanged unless a later message-retention setting is turned on. Default is to keep them | `messages`, `bags` |
| Invites | Existing purge: 5 minutes after expiry for unused invites, 30 days for used ones | `invites` |
| Pairing keys | Until erasure. Erasure deletes the key and clears peer ids and `extra_json`. `record_hash` stays | `pairing_keys` |

`pairings.hold_until` blocks both the retention job and erasure. Erasure inside the 183-day floor requires an explicit override and a recorded basis. `DeletePeer` and the invite purge do not remove audit rows.

# Storage ports

The SQLite store is the only backend today. Later subsystems (audit log, anchor outbox, A2A tasks, webhook delivery) must be testable without that file and swappable when a second backend exists. These rules keep that swap mechanical.

## Rules

- Interfaces are defined next to the code that calls them, not next to the SQL.
- SQL stays in `internal/store`. SQLite `?` placeholders do not leak into other packages, so a Postgres implementation can sit beside the SQLite one.
- `store.DBTX` is the shared transaction handle (`*sql.DB` and `*sql.Tx`). An audit append and the domain write that caused it take the same value. `audit.Tx` has the same methods so the audit package does not import `store`.
- New code takes one clock. Store methods that need a timestamp take `func() int64` (Unix seconds), the same clock the store already uses. Do not call `time.Now` inside a port implementation.
- In-memory fakes live in `internal/<port>/mem`. Each port has a conformance test that the fake passes now and that a SQLite implementation must pass later.
- `api.New` keeps its `*store.Store` argument. New code depends on the interfaces; existing handlers are unchanged.

## Ports

| Port | Package | Role |
|---|---|---|
| `LogStore` | `internal/audit` | Append a record in the caller's transaction, read a pairing's sequence range, mark batched or anchored, delete by retention |
| `Outbox` | `internal/anchor` | Enqueue, claim with a lease, mark submitted, confirmed, failed, or dead |
| `Outbox` | `internal/webhook` | Same shape as the anchor outbox, for user webhook delivery |
| `TaskStore` | `internal/a2a` | Create, get, list, and update a task. Updates name the previous state and are rejected when it does not match |
| `Allowance` | `internal/msg` | `Allow`, `Ready`, and `Refund`. The in-memory `*msg.Limiter` implements it |

No new third-party dependencies.

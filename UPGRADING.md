# Upgrading Peerline

This document describes how to safely upgrade Peerline across versions, with a focus on database schema migrations and backups.

## Table of Contents

- [General Upgrade Process](#general-upgrade-process)
- [Breaking Changes](#breaking-changes)
- [Schema Migrations and Backups](#schema-migrations-and-backups)
- [Backup Files](#backup-files)
- [Deployment and Schema Upgrades](#deployment-and-schema-upgrades)
- [Rollback Procedure](#rollback-procedure)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

## General Upgrade Process

1. **Stop the Peerline service** (recommended for single-instance deployments)
2. **Back up your database file** manually as a precaution (in addition to automatic pre-migration backups)
3. **Replace the binary** with the new version
4. **Fix directory permissions if needed** (see [Docker /data directories](#docker-data-directories) below)
5. **Start the service** – schema migrations run automatically on the first Open()

For zero-downtime deployments, see [Deployment and Schema Upgrades](#deployment-and-schema-upgrades).

## Breaking Changes

### Environment variable validation now rejects invalid numeric values (#355)

**Affected versions:** All versions upgrading to include the #355 fix

**Impact:** If `PEERLINE_EMAIL_PER_HOUR`, `PEERLINE_NOTIFY_PER_HOUR`, `PEERLINE_MAX_OUTSTANDING_INVITES`, `PEERLINE_KEY_INDEX_REBUILD_HOURS`, `PEERLINE_KEY_INDEX_WARN`, or `PEERLINE_RETENTION_DAYS` is set to a non-numeric value (e.g., `1O` with capital O) or a negative value, startup now fails with a clear error message naming the variable and the invalid value.

**What changed:**
- Before: These variables silently fell back to their defaults when parsing failed. For example, `PEERLINE_EMAIL_PER_HOUR=1O` would be ignored and the default (20) would be used. `PEERLINE_MAX_OUTSTANDING_INVITES` accepted negative values and treated them as "use default 10".
- After: Startup fails immediately with an error like `PEERLINE_EMAIL_PER_HOUR must be numeric, got: 1O` or `PEERLINE_MAX_OUTSTANDING_INVITES must be non-negative, got: -1`.
- **Zero is still valid** and means "use the default" as documented (e.g., `PEERLINE_RETENTION_DAYS=0` → 30 days).

**New upper bounds:**
- `PEERLINE_KEY_INDEX_REBUILD_HOURS` must be ≤ 8760 (hours in a year) to prevent overflow in `time.Duration` conversion
- `PEERLINE_RETENTION_DAYS` must be ≤ 36500 (100 years) to prevent overflow in seconds conversion

**Action required:** If you have set any of these variables to invalid values (typos or negative numbers), correct them before upgrading. Note that `PEERLINE_MAX_OUTSTANDING_INVITES` no longer accepts negative values; use `0` for the default instead. Unset, empty, or `0` variables continue to use their defaults as before.

### Fragment (#) in file: URI DSNs is now refused (#327, #349)

**Affected versions:** All versions upgrading to include the #327/#349 fix

**Impact:** `file:` URIs containing a fragment (`#`) now fail fast at startup with a clear error. Use `%23` to encode a literal `#` in the filename.

**What changed:**
- Before: Fragments in `file:` URIs could cause ambiguity where SQLite and the validation code disagree about the file path and parameters
- After: Any `file:` URI with `#` is refused with error: `"file: URI contains a fragment (#), which is not supported; use %23 to encode a literal # in the filename"`

**Examples:**
```bash
# Refused:
file:/data/test.db#section
file:/data/x.db#?mode=memory

# Use %23 for literal hash in filename:
file:/data/x%23y.db  # Opens x#y.db
```

**Note:** Plain (non-`file:`) paths with `#` are passed to SQLite as literal filenames and remain unchanged.

**Why this change:** Fragments in `file:` URIs create ambiguity in URI parsing that can lead to mismatches between validation and SQLite's actual behavior. Refusing them outright prevents these edge cases.

### IPv4 6to4 relay anycast prefix rejected in PEERLINE_TRUSTED_PROXIES (#331)

**Affected versions:** All versions upgrading to include the #331 fix

**Impact:** If `PEERLINE_TRUSTED_PROXIES` contains or overlaps `192.88.99.0/24`, startup now fails with `overlaps 6to4 relay anycast prefix 192.88.99.0/24`. Remove the entry (or, if a wider entry contains it, split it; see How to fix); this is the deprecated 6to4 relay anycast range and is not a reverse-proxy range.

**What changed:**
- IPv4 6to4 relay anycast prefix (`192.88.99.0/24`) is now explicitly rejected at startup (RFC 7526).
- There is no override; any entry that overlaps this range will prevent the server from starting.

**How to fix:**
Remove the overlapping entry from `PEERLINE_TRUSTED_PROXIES`. If a wider entry contains the range (e.g., `192.0.0.0/8` or `192.88.0.0/16`), split it into ranges that exclude `192.88.99.0/24`. This range covers arbitrary 6to4 relay clients and is not a legitimate reverse-proxy network.

### IPv6 transition/translation prefixes rejected in PEERLINE_TRUSTED_PROXIES (#320)

**Affected versions:** All versions upgrading to include the #320 fix

**Impact:** If `PEERLINE_TRUSTED_PROXIES` contains or overlaps `2001::/32`, `2002::/16`, `64:ff9b::/96` or `64:ff9b:1::/48`, startup now fails with `overlaps <range name>`. Remove the entry; these are never reverse-proxy ranges.

**What changed:**
- Teredo (`2001::/32`), NAT64 (`64:ff9b::/96` and `64:ff9b:1::/48`), and 6to4 (`2002::/16`) prefixes are now explicitly rejected at startup.
- There is no override; any entry that overlaps these ranges will prevent the server from starting.

**How to fix:**
Remove the overlapping entry from `PEERLINE_TRUSTED_PROXIES`. These ranges cover arbitrary internet clients and are not legitimate reverse-proxy networks.

### Confirm API requires offer_digest (Security Fix for #80)

**Affected versions:** All versions upgrading to include the #80 fix

**Impact:** The `POST /v1/invites/{public_id}/confirm` endpoint now requires an `offer_digest` parameter in the request body.

**What changed:**
- Old request: `{"peer_id": "...", "code": "..."}`
- New request: `{"peer_id": "...", "code": "...", "offer_digest": "..."}`

**Error if not updated:**
```json
{
  "error": "offer_digest required: GET /v1/invites/{public_id} and echo offer_digest"
}
```

**How to update your client:**

1. Call `GET /v1/invites/{public_id}` to get the current state
2. Extract the `offer_digest` from the response
3. Include it in your confirm request

Example:
```bash
# Step 1: Get the invite view
VIEW=$(curl -H "Authorization: Bearer $KEY" \
  https://peerline.example.com/v1/invites/$PUBLIC_ID)

# Step 2: Extract offer_digest
DIGEST=$(echo "$VIEW" | jq -r '.offer_digest')

# Step 3: Confirm with digest
curl -X POST -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  https://peerline.example.com/v1/invites/$PUBLIC_ID/confirm \
  -d "{\"peer_id\":\"$CLAIMANT\",\"code\":\"$CODE\",\"offer_digest\":\"$DIGEST\"}"
```

**Why this change:** The `offer_digest` binds the confirm operation to exactly what the inviter reviewed, including:
- Scopes and bags in both directions
- The claimant's peer_id
- Any existing grants being replaced

This prevents time-of-check-time-of-use vulnerabilities and silent grant overwrites in confirm-mode invites (`require_confirm: true`).

**Note:** A stale `offer_digest` (if the offer changed between GET and confirm) returns HTTP 409 with the fresh digest, and does not count toward the 3-strike auto-decline limit. Only code or peer_id mismatches count toward auto-decline.

**Repeat decline now succeeds (idempotent):** As of PR #241, calling `POST /v1/invites/{public_id}/decline` on an already-declined invite returns HTTP 200 success instead of HTTP 404. This makes decline idempotent, consistent with the behavior of repeated confirm operations on active invites. Clients that relied on 404 for already-declined invites should update their logic.

**Important:** This overwrite prevention applies only to confirm-mode invites. Legacy pairing paths (`POST /v1/pairing/{token}` with invite codes or pairing links) still silently overwrite existing grants between the two peers. See [issue #312](https://github.com/sysrex/peerline/issues/312) for details. For controlled re-pairing with review, use confirm-mode invites.

### Inviter Name Truncation May Show Visible Virama or Half-Form (#332, #346)

**Affected versions:** All versions upgrading to include the #332 fix

**Impact:** Inviter names longer than 64 runes are truncated. When the 64-rune cut lands inside a boundary-free run of consonant+virama clusters, truncation backs off by at most 4 clusters, and a consonant cut off from its following virama or mark at the cap counts as one of the 4. If the run inside the cut is longer than that (more than 4 complete clusters, or more than 3 when the cut also splits a cluster), at least one cluster stays and the output ends in a visible virama or half-form consonant instead of collapsing to "A Peerline peer". Examples: 54 a + स्त्र्य्म्न + bbb gives 54 a + स् (5 clusters inside the cut, 4 dropped). 40× क् gives 28× क् (32 clusters inside the cut, 4 dropped). The output is always a prefix of the full sanitized name and idempotent.

**What changed:**
- Before: Long virama runs without word boundaries collapsed to the fallback "A Peerline peer"
- After: Truncation back-off is bounded, so names may end in a trailing virama or half-form in conjunct-forming scripts (Devanagari, Bengali, Malayalam, etc.)
- The sanitized name is a display-only field (`untrusted.inviter_name`) and is never used for identity or authentication
- See #346 for security review; accepted as documented behavior

**Example:** A Devanagari name with 40 `क्` clusters (80 runes) now truncates to 28 clusters (56 runes, ending in virama) instead of returning the fallback.

### Legacy Pairing Refuses Re-pair with Different Grants (Security Fix for #312)

**Affected versions:** All versions upgrading to include the #312 fix

**Impact:** Legacy accept paths (`POST /v1/invites/accept` with invite codes and `POST /v1/pairing/{token}` with or without Bearer auth) now refuse to overwrite existing grants when scopes or bags differ. A re-pair attempt with different grants returns HTTP 409 and leaves both the grants and the invite unchanged.

**What changed:**
- Before: Accepting an invite when already paired silently replaced existing grants with no review
- After: Accept fails with 409 if grants would change; succeeds (idempotent 200) if grants are identical

**Error response:**
```json
{
  "error": "already paired with different grants; revoke the grant or use a confirm-mode invite"
}
```

**How to update your workflow:**

If you need to change grant scopes between two already-paired peers:

**Option 1: Revoke first, then accept (immediate)**
```bash
# Revoke the existing grant
curl -X DELETE -H "Authorization: Bearer $KEY" \
  https://peerline.example.com/v1/grants/$PEER_ID

# Now accept the new invite
curl -X POST -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  https://peerline.example.com/v1/invites/accept \
  -d "{\"code\":\"$CODE\"}"
```

**Option 2: Use confirm-mode invites (with review step)**
```bash
# Create invite with require_confirm: true
curl -X POST -H "Authorization: Bearer $INVITER_KEY" \
  -H "Content-Type: application/json" \
  https://peerline.example.com/v1/invites \
  -d '{"scopes":["new_scope"],"generate_pairing":true,"require_confirm":true}'

# The accepter claims it, you review the offer_digest, then confirm
```

Confirm-mode invites show you what grants are being replaced and require explicit confirmation (see the Confirm API section above).

**Why this change:** The silent overwrite allowed a stale invite to restore previously-revoked access without the inviter's knowledge. A narrower old invite could also silently downgrade a grant. This fix ensures both peers must explicitly revoke or confirm before changing grant scopes.

**Note:** This affects only re-pairing between two already-paired peers. First-time pairing is unchanged.

## Schema Migrations and Backups

Peerline automatically migrates your database schema to the latest version when the service starts. Before applying any migration, Peerline creates a **pre-migration backup** using SQLite's `VACUUM INTO` command.

### Automatic Backup Behavior

- **When**: A backup is created before migrating from an older schema version to a newer one.
- **Format**: `<database>.pre-v<to>-from-v<from>.<timestamp>` (e.g., `peerline.db.pre-v3-from-v2.20260130-120000.123456`)
- **Location**: Same directory as the database by default (override with `PEERLINE_BACKUP_DIR`)
- **Permissions**: 0600 (owner read/write only) to protect sensitive data
- **Retention**: The 3 most recent backups are kept by default (override with `PEERLINE_BACKUP_KEEP`)

### What's in a Backup?

Each backup is a complete, consistent snapshot of your database taken via `VACUUM INTO`:

- **All tables**: `peers`, `invites`, `grants`, `messages`, `bags`
- **All indexes** and constraints
- **Schema version** (`PRAGMA user_version`) matching the pre-migration state
- **Journal mode**: `delete` (backups are not in WAL mode, regardless of source database mode)

Backups are **verified** after creation:
- SQLite `PRAGMA quick_check` to detect corruption
- Schema version confirmation
- Table existence and queryability checks

### Backup Security

- Created with **0600 permissions** (owner-only access) via `O_CREATE|O_EXCL|O_NOFOLLOW` before SQLite writes to them
- **Contain sensitive data**: Backups contain API key hashes (unsalted SHA-256), invite/pairing-token hashes, notify email addresses, **full message bodies, and bag contents**. No passwords are stored anywhere in Peerline.
- **Backups retain deleted data**: Backups preserve data that retention purging or peer deletion has since removed from the live database. This data persists until the backup rotates out (up to `PEERLINE_BACKUP_KEEP` files, no age limit). Operators should:
  - Delete old backups after confirming successful upgrades
  - Include backup files in your backup and encryption policy
  - Securely wipe (`shred` or equivalent) backups before disposal
- Should be stored on encrypted volumes in production
- Backup directory requirements:
  - Must be a real directory (not a symlink), owned by the user running Peerline
  - For `PEERLINE_BACKUP_DIR`: must have mode 0700 (no group or world access)
  - For default database directory: must not be group or world writable (mode 0022 bits clear)
- Excluded from Git via `.gitignore` (`*.db.pre-v*`)

## Backup Files

### Naming Convention

Backup filenames encode the migration context:

```
<database>.pre-v<to>-from-v<from>.<timestamp>[.<suffix>]
```

Example: `peerline.db.pre-v6-from-v5.20260130-120000.123456` or `peerline.db.pre-v6-from-v5.20260130-120000.000000.a1b2c3d4` (with random suffix on collision)

- `pre-v6`: Backup taken before migrating **to** version 6
- `from-v5`: Database was at version 5 when backup was created
- Timestamp: UTC in `YYYYMMDD-HHMMSS.microseconds` format (microseconds are real only with system clock; injected test clocks show `.000000`)
- Optional suffix: 8 hex digits (lowercase) added automatically on filename collision, or legacy decimal PID for compatibility with older backups. Collisions are rare in production (microsecond-resolution timestamps) but can occur in rapid restart loops or when files are pre-planted in the backup directory.

### Backup Reuse (Restart-Loop Guard)

If Peerline crashes during migration and restarts, it will **reuse the existing backup** instead of creating a new one, provided:
- The backup file exists with the correct naming pattern
- Its modification time is newer than both the database file and its `-wal` file
- It passes verification: `PRAGMA quick_check`, correct `user_version` matches the source version, and the `peers` table is queryable

This prevents filling disk with duplicate backups during crash loops.

### Retention Policy

By default, Peerline keeps **at most 3 backup files in total** across all schema versions. Older backups are automatically deleted when new ones are created, keeping the newest 3 (by modification time).

To adjust retention:
- Set `PEERLINE_BACKUP_KEEP=5` to keep at most 5 backup files in total
- Minimum value is 1; invalid values log a warning and use the default (3)
- The just-created or reused backup counts toward this limit but is never deleted
- Only regular files matching the exact pattern (`<db>.pre-vN-from-vM.<timestamp>` with optional `.<hexhexhexhexhexhexhexhex>` or `.<decimal_pid>` suffix) are managed by retention; to keep a backup permanently, copy it elsewhere or rename it (e.g., add `.KEEP` or use uppercase hex)

### Storage Location

Backups are written to the database's directory by default. To store backups separately:

```bash
export PEERLINE_BACKUP_DIR=/var/backups/peerline
```

The directory will be created if it doesn't exist (with **0700 permissions** for security).  
Peerline will **refuse to start** if the backup directory is a symlink, is owned by another user, or allows any group or world access (mode other than 0700). This applies to the default location (the database directory) too.

### Disk Space Requirements

Peerline checks for sufficient disk space before creating a backup and will abort the migration if space is insufficient. The preflight check requires at least 100% of the database's logical size (page_count × page_size). A margin of ~10% is recommended to account for VACUUM expansion, but the check enforces only the 100% minimum.

On Unix systems, this check uses `statfs(2)`. On unsupported platforms, the check is skipped and VACUUM INTO will fail if space runs out.

## Docker /data Directories

Docker volumes typically create directories with mode **0755** (world-readable). This is compatible with Peerline's backup system when using the default backup location (the database directory itself), because the backup directory permission check only refuses **writable** bits (0022), not readable bits.

**What happens on upgrade with a 0755 /data directory:**
- ✅ Startup succeeds. The 0755 directory passes the default-directory check (only writable bits 0022 are refused), backups are written at 0600, and migration proceeds normally.
- **Automatic permission tightening**: On Unix, Peerline now tightens permissions on existing database files (database, -wal, -shm) at open if they are wider than 0600, removing group and other access. A warning is logged for each file that is tightened.
  - **Symlinked databases**: If the database path is a symlink, Peerline resolves it and tightens the target file (and its -wal and -shm files, which SQLite creates next to the target, not the link). This ensures databases accessed through symlinks are properly secured.
  - **Dangling symlinks**: A dangling symlink (link exists but target doesn't yet) is accepted if both the link's parent directory and the target's parent directory have safe permissions (not group- or world-writable, mode 0o022 bits clear). Symlinks to directories with mode 0755 are accepted; those pointing to 0777 or 1777 (sticky) directories are refused. This check runs at startup before SQLite creates the file, ensuring the database will be created in a safe location.
- **New file creation**: This release sets `umask(0077)` on Unix at startup (process-wide), so new files Peerline creates (database, WAL, SHM, backups) are created at 0600 or 0700. This prevents other local users from reading the database even in a 0755 directory. On Windows, file permissions are handled via ACLs instead of umask.
- **One-time manual step for backups**: After upgrading, run `chmod 600 peerline.db.pre-v*` to tighten permissions on existing backup files from earlier releases (the automatic tightening only applies to the main database files, not backups).

**If startup still fails** with a directory permission error:
1. Check the actual directory mode: `ls -ld /data`
2. If it's group-writable (0775) or world-writable (0777), fix it: `chmod 755 /data`
3. If even 0755 is refused (you're using an explicit `PEERLINE_BACKUP_DIR` pointing to a 0755 directory), either:
   - Fix the backup directory: `chmod 700 "$PEERLINE_BACKUP_DIR"`
   - Or leave the database directory at 0755 and unset `PEERLINE_BACKUP_DIR` to use the default location

**Recommended for production Docker deployments:**
```dockerfile
# In your Dockerfile or docker-compose volume setup:
# The container runs as uid 65532 (nonroot user), so the directory must be owned by that user
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data
```

Or in an entrypoint script:
```bash
chown 65532:65532 /data
chmod 700 /data
```

This ensures the backup directory has strict permissions and correct ownership. The `chown` is required because the image's nonroot user (uid 65532) cannot write to a root-owned directory even if it's 0700.

## Deployment and Schema Upgrades

### Important: SQLite Single-Instance Constraint

**Peerline requires a single-instance SQLite database.** Do not run multiple Peerline instances writing to the same database file, even in WAL mode. SQLite's locking is designed for single-host access; network filesystem locks are unreliable and can cause corruption.

**Single-instance deployment only.** Peerline does not support active/standby with filesystem replication or read replicas; SQLite requires a single writer instance.

### Standard Deployment Procedure

For single-instance deployments (the typical case):

1. **Stop the Peerline service**
2. **Back up your database manually** as a precaution (in addition to automatic pre-migration backups)
3. **Replace the binary** with the new version
4. **Start the service** – schema migrations run automatically on the first Open()

Peerline will create a pre-migration backup before applying any schema changes, so you can roll back if needed (see [Rollback Procedure](#rollback-procedure)).

### First Deployment with Schema Guard (This Release)

**Important: This release includes both the fail-closed schema version guard AND schema v4 (email verification).**

Binaries from before this release (before the schema guard was introduced) will **silently open** databases with any schema version, including future versions they don't understand. This means:

1. **Deploy this release's binary first** (adds version guard and migrates to v6)
2. **Verify the startup log line** confirms the migration: `database opened ... schema_version=6 max_supported=6 backup=<filename or none>`
3. **Only after confirming this binary is deployed and running everywhere**, deploy future releases with schema changes

This ensures no old binary without the guard can open a migrated database. **Binaries from this release onward refuse to open newer schemas** and will exit with code 2 and error message: `database schema version X is newer than this binary supports (max Y); upgrade the peerline binary or restore from backup`

**Pre-guard binaries run on v4+ databases silently**: The only rollback path after deploying this release is restore-from-backup, never "run the old binary".

## Rollback Procedure

If a migration fails or the new version has issues, you can roll back to a previous schema version using the pre-migration backup.

### Steps

1. **Stop all Peerline instances** accessing the database
2. **Locate the backup file** in the database directory or `PEERLINE_BACKUP_DIR`:
   ```bash
   ls -lh peerline.db.pre-v*
   ```
3. **Replace the database** with the backup:
   ```bash
   # Back up the current (failed) database and its WAL/SHM files
   mv peerline.db peerline.db.failed
   mv peerline.db-wal peerline.db-wal.failed 2>/dev/null || true
   mv peerline.db-shm peerline.db-shm.failed 2>/dev/null || true
   
   # Restore the pre-migration backup
   cp peerline.db.pre-v6-from-v5.20260130-120000.123456 peerline.db
   
   # Ensure correct permissions (newer Peerline versions create backups at 0600)
   chmod 600 peerline.db*
   ```
4. **Downgrade the Peerline binary** to the version that supports the backup's schema version
5. **Start Peerline** with the older binary – it will open the restored database without attempting migration

### Verification

After rollback:
- Check the schema version: `sqlite3 peerline.db "PRAGMA user_version"`
- Verify data integrity: `sqlite3 peerline.db "PRAGMA integrity_check"`
- Test application functionality

## Environment Variables

### Backup Control

- `PEERLINE_SKIP_MIGRATION_BACKUP=1`  
  Skip automatic pre-migration backups (not recommended for production)

- `PEERLINE_BACKUP_DIR=/path/to/backups`  
  Store backups in a custom directory instead of the database directory (created with 0700 if missing)

- `PEERLINE_BACKUP_KEEP=3`  
  Number of backups to retain across all schema versions (minimum: 1, default: 3)

### Trusted Proxies

- `PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD=1` (or `true`)  
  Lowers the IPv6 floor from `/32` to `/29` (allowing public ranges like Cloudflare's `2a06:98c0::/29`) and permits ULA ranges within `fc00::/7` to skip the floor entirely. Accepted values: `1`, `true` (opt-in), `0`, `false`, or empty (default, opt-in off). Any other value causes startup failure. **Security warning:** Trusting a public `/29` lets anyone inside it spoof `X-Forwarded-For`.  
  **Note:** IPv6 transition/translation prefixes are always rejected regardless of this setting: Teredo `2001::/32`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, and 6to4 `2002::/16`.

### Database Location

- `PEERLINE_DB=/path/to/peerline.db`  
  Database file path (default: `peerline.db` in current directory)

## SMTP TLS

- STARTTLS is required on every port except 465 (implicit TLS), except that `localhost`, `127.0.0.1` and `::1` allow plaintext by default. Override with `PEERLINE_SMTP_REQUIRE_TLS=1` or `=0`.
- `PEERLINE_SMTP_ALLOW_PLAINTEXT` is not read by any version; use `PEERLINE_SMTP_REQUIRE_TLS=false` instead.
- At startup Peerline probes the relay (3 s). A TLS misconfiguration exits 1; an unreachable relay only warns.

## Troubleshooting

### "Database schema version X is newer than this binary supports"

**Cause**: You're trying to run an older Peerline binary against a database that was migrated by a newer version.

**Solution**:
- Upgrade the binary to match the schema version, OR
- Restore from a pre-migration backup (see [Rollback Procedure](#rollback-procedure))

### "Insufficient disk space in backup directory"

**Cause**: Not enough free space to create the pre-migration backup.

**Solution**:
- Free up disk space (need at least 100% of database size, 110% recommended)
- Move the database to a volume with more space
- Set `PEERLINE_BACKUP_DIR` to a volume with sufficient space

### "Backup verification failed"

**Cause**: The backup file created by VACUUM INTO failed integrity checks.

**Solution**:
- Check disk health (`smartctl`, `fsck`)
- Verify source database integrity: `sqlite3 peerline.db "PRAGMA integrity_check"`
- If source database is corrupt, repair it before upgrading (see SQLite `.recover` command)

### Backup file already exists (crash loop)

**Cause**: Peerline crashed during a previous migration attempt and is retrying, but the timestamp-based backup filename collides.

**Behavior**: Peerline automatically adds a random 8-character hex suffix and retries up to 10 times. If all attempts fail, the migration is aborted.

**Solution**:
- Inspect the existing backup to determine if the previous migration partially completed
- Manually remove stale backups if you're certain they're from an incomplete migration
- Check logs for the root cause of the crash

### Migration hangs or times out

**Cause**: Another process holds an exclusive lock on the database.

**Solution**:
- Ensure all other Peerline instances are stopped
- Check for stale SQLite connections: `lsof | grep peerline.db`
- If using WAL mode (default), check for `-wal` and `-shm` files

---

For further assistance, see the [Peerline documentation](https://github.com/sysrex/peerline) or file an issue.

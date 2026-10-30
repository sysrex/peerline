# Upgrading Peerline

This document describes how to safely upgrade Peerline across versions, with a focus on database schema migrations and backups.

## Table of Contents

- [General Upgrade Process](#general-upgrade-process)
- [Schema Migrations and Backups](#schema-migrations-and-backups)
- [Backup Files](#backup-files)
- [Rolling Deployments](#rolling-deployments)
- [Rollback Procedure](#rollback-procedure)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

## General Upgrade Process

1. **Stop the Peerline service** (recommended for single-instance deployments)
2. **Back up your database file** manually as a precaution (in addition to automatic pre-migration backups)
3. **Replace the binary** with the new version
4. **Start the service** – schema migrations run automatically on the first Open()

For zero-downtime deployments, see [Rolling Deployments](#rolling-deployments).

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
- **WAL journal mode** (same as the source database)

Backups are **verified** after creation:
- SQLite `PRAGMA quick_check` to detect corruption
- Schema version confirmation
- Table existence and queryability checks

### Backup Security

- Created with **0600 permissions** (owner-only access) to prevent world-readable windows
- **Contain sensitive data**: Backups contain API key hashes (unsalted SHA-256), invite/pairing-token hashes, notify email addresses, full message bodies, and bag contents. No passwords are stored anywhere in Peerline.
- Should be stored on encrypted volumes in production
- Backup directory must not be group- or world-writable (checked on startup)
- Excluded from Git via `.gitignore` (`*.db.pre-v*`)

## Backup Files

### Naming Convention

Backup filenames encode the migration context:

```
<database>.pre-v<to>-from-v<from>.<timestamp>
```

Example: `peerline.db.pre-v3-from-v2.20260130-120000.123456`

- `pre-v3`: Backup taken before migrating **to** version 3
- `from-v2`: Database was at version 2 when backup was created
- Timestamp: UTC in `YYYYMMDD-HHMMSS.microseconds` format

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

### Storage Location

Backups are written to the database's directory by default. To store backups separately:

```bash
export PEERLINE_BACKUP_DIR=/var/backups/peerline
```

The directory will be created if it doesn't exist (with **0700 permissions** for security).  
Peerline will **refuse to start** if the backup directory has group- or world-writable permissions.

### Disk Space Requirements

Peerline checks for sufficient disk space before creating a backup and will abort the migration if space is insufficient (requires ~110% of database size to account for VACUUM expansion).

On Unix systems, this check uses `statfs(2)`. On unsupported platforms, the check is skipped and VACUUM INTO will fail if space runs out.

## Deployment and Schema Upgrades

### Important: SQLite Single-Instance Constraint

**Peerline requires a single-instance SQLite database.** Do not run multiple Peerline instances writing to the same database file, even in WAL mode. SQLite's locking is designed for single-host access; network filesystem locks are unreliable and can cause corruption.

For high availability, use:
- Active/standby with filesystem replication, or
- Load-balanced read replicas with a single writer

### Standard Deployment Procedure

For single-instance deployments (the typical case):

1. **Stop the Peerline service**
2. **Back up your database manually** as a precaution (in addition to automatic pre-migration backups)
3. **Replace the binary** with the new version
4. **Start the service** – schema migrations run automatically on the first Open()

Peerline will create a pre-migration backup before applying any schema changes, so you can roll back if needed (see [Rollback Procedure](#rollback-procedure)).

### First Deployment with Schema Guard (This Release)

**Special case for the first deployment that adds the fail-closed schema version guard:**

Binaries from before this release (before the schema guard was introduced) will **silently open** databases with any schema version, including future versions they don't understand. This means:

1. **Deploy this release's binary first** (adds version guard, no schema changes yet)
2. **Restart the service** with this binary
3. **Only after this binary is running, deploy future schema versions** that introduce schema changes

This ensures no old binary without the guard can open a migrated database. **Binaries from this release onward refuse to open newer schemas** and will exit with code 2 and error message: `database schema version X is newer than this binary supports (max Y); upgrade the peerline binary or restore from backup`

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
   cp peerline.db.pre-v3-from-v2.20260130-120000.123456 peerline.db
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

### Database Location

- `PEERLINE_DB=/path/to/peerline.db`  
  Database file path (default: `peerline.db` in current directory)

## Troubleshooting

### "Database schema version X is newer than this binary supports"

**Cause**: You're trying to run an older Peerline binary against a database that was migrated by a newer version.

**Solution**:
- Upgrade the binary to match the schema version, OR
- Restore from a pre-migration backup (see [Rollback Procedure](#rollback-procedure))

### "Insufficient disk space in backup directory"

**Cause**: Not enough free space to create the pre-migration backup.

**Solution**:
- Free up disk space (need ~110% of database size)
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

**Behavior**: Peerline automatically adds a PID suffix and retries once. If that also fails, the migration is aborted.

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

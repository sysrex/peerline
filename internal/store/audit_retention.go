package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const auditRetentionFloorDays = 183

// ErrRetentionFloor means erasure was asked for inside the six-month floor
// without an operator override.
var ErrRetentionFloor = errors.New("audit retention floor")

// ErrLegalHold means the pairing is under hold.
var ErrLegalHold = errors.New("pairing is under legal hold")

// auditRetainBatch and auditRetainMaxBatches match the invite purge caps.
var (
	auditRetainBatch      = 500
	auditRetainMaxBatches = 100
	auditRetainYield      = 25 * time.Millisecond
)

// AuditRetentionDays parses PEERLINE_AUDIT_RETENTION_DAYS. Empty means 183.
// Any value below 183 is refused.
func AuditRetentionDays(raw string) (int, error) {
	if raw == "" {
		return auditRetentionFloorDays, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < auditRetentionFloorDays {
		return 0, fmt.Errorf("PEERLINE_AUDIT_RETENTION_DAYS must be >= %d", auditRetentionFloorDays)
	}
	return n, nil
}

// PurgeAuditRecords deletes records older than retentionDays when they are
// batched, anchored, and not under a legal hold. It stops after the batch cap
// and reports more when a backlog remains.
func (s *Store) PurgeAuditRecords(ctx context.Context, retentionDays int) (deleted int, more bool, err error) {
	if retentionDays < auditRetentionFloorDays {
		return 0, false, ErrRetentionFloor
	}
	cutoff := s.clk.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).UnixMilli()
	now := s.clk.Now().UnixMilli()
	for batches := 0; ; batches++ {
		if err := ctx.Err(); err != nil {
			return deleted, false, err
		}
		if batches == auditRetainMaxBatches {
			return deleted, true, nil
		}
		res, err := s.db.ExecContext(ctx, `
DELETE FROM audit_records WHERE rowid IN (
  SELECT r.rowid FROM audit_records r
  JOIN pairings p ON p.id = r.pairing_id
  WHERE r.ts_ms < ?1 AND r.batch_seq IS NOT NULL AND r.anchored_at IS NOT NULL
    AND (p.hold_until IS NULL OR p.hold_until < ?2)
  LIMIT ?3)`, cutoff, now, auditRetainBatch)
		if err != nil {
			return deleted, false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return deleted, false, err
		}
		deleted += int(n)
		if int(n) < auditRetainBatch {
			return deleted, false, nil
		}
		select {
		case <-ctx.Done():
			return deleted, false, ctx.Err()
		case <-time.After(auditRetainYield):
		}
	}
}

// SetLegalHold blocks retention and erasure until untilMs.
func (s *Store) SetLegalHold(ctx context.Context, pairingID string, untilMs int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE pairings SET hold_until=? WHERE id=?`, untilMs, pairingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErasePairing removes the pairing key and the content columns. Roots
// (record_hash, prev_hash, sig) stay. Inside the retention floor this requires
// override; the reason is stored on the erasure record and nowhere else.
func (s *Store) ErasePairing(ctx context.Context, pairingID, reason string, override bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hold sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT hold_until FROM pairings WHERE id=?`, pairingID).Scan(&hold); err != nil {
		return err
	}
	if hold.Valid && hold.Int64 > s.clk.Now().UnixMilli() {
		return ErrLegalHold
	}
	var newest int64
	_ = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(ts_ms),0) FROM audit_records WHERE pairing_id=?`, pairingID).Scan(&newest)
	floor := s.clk.Now().Add(-time.Duration(auditRetentionFloorDays) * 24 * time.Hour).UnixMilli()
	if newest > floor && !override {
		return ErrRetentionFloor
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE audit_records SET extra_json=NULL, a2a_json=NULL, from_peer=NULL, to_peer=NULL, org_ref=NULL
WHERE pairing_id=?`, pairingID); err != nil {
		return err
	}
	leaf, err := tokenLeaf("erasure", "")
	if err != nil {
		return err
	}
	extra := ""
	if override {
		extra = extraJSON(map[string]string{"basis": reason})
	}
	if _, err := s.appendAudit(ctx, tx, AuditRecord{
		EventType: "erasure", PairingID: pairingID, Leaf: leaf, ExtraJSON: extra,
		TsMs: s.clk.Now().UnixMilli(),
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pairing_keys WHERE pairing_id=?`, pairingID); err != nil {
		return err
	}
	return tx.Commit()
}

// ContentErased reports whether the pairing key is gone while a record root remains.
func (s *Store) ContentErased(ctx context.Context, pairingID string) (bool, error) {
	var keys, roots int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pairing_keys WHERE pairing_id=?`, pairingID).Scan(&keys); err != nil {
		return false, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_records WHERE pairing_id=? AND record_hash IS NOT NULL`, pairingID).Scan(&roots); err != nil {
		return false, err
	}
	return keys == 0 && roots > 0, nil
}

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"

	"github.com/sysrex/peerline/internal/audit"
)

// AuditRecord is one durable event. Hashes and sig are a provisional chain:
// the canonical bytes and the Ed25519 signature arrive with the audit core.
// sig_kid "unsigned" means this row has not been signed yet.
type AuditRecord struct {
	RecordID        string
	EventType       string
	FromPeer        string
	ToPeer          string
	TsMs            int64
	ContentHash     []byte
	ContentHashKind string
	ContentSize     int
	ExtraJSON       string
	// Leaf is hashed into ContentHash when an instance signing key is configured.
	// It is not stored. Keep peer ids, bag names, and scope lists out of it.
	Leaf []byte
}

// AppendAudit writes rec in tx when audit is enabled. A nil tx starts one.
// When audit is disabled the call is a no-op and the schema is left untouched.
// The returned sequence is the per-pairing pair_seq.
func (s *Store) AppendAudit(ctx context.Context, tx DBTX, rec AuditRecord) (int64, error) {
	if !s.auditEnabled {
		return 0, nil
	}
	if rec.RecordID == "" {
		id, err := generatePublicID()
		if err != nil {
			return 0, err
		}
		rec.RecordID = id
	}
	if rec.TsMs == 0 {
		rec.TsMs = s.clk.Now().UnixMilli()
	}
	if tx != nil {
		return s.appendAudit(ctx, tx, rec)
	}
	var last error
	for range 5 {
		seq, err := s.appendAuditOwned(ctx, rec)
		if err == nil || !isUniqueConstraint(err) {
			return seq, err
		}
		last = err
		id, err := generatePublicID()
		if err != nil {
			return 0, err
		}
		rec.RecordID = id
	}
	if last == nil {
		last = errors.New("audit append conflict")
	}
	return 0, last
}

func (s *Store) appendAuditOwned(ctx context.Context, rec AuditRecord) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	seq, err := s.appendAudit(ctx, tx, rec)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *Store) appendAudit(ctx context.Context, tx DBTX, rec AuditRecord) (int64, error) {
	pairingID, err := ensurePairing(ctx, tx, rec.FromPeer, rec.ToPeer, rec.TsMs)
	if err != nil {
		return 0, err
	}
	var pairSeq int64
	var prev []byte
	err = tx.QueryRowContext(ctx, `SELECT pair_seq, head_hash FROM audit_chain_heads WHERE pairing_id=?`, pairingID).Scan(&pairSeq, &prev)
	if errors.Is(err, sql.ErrNoRows) {
		pairSeq = 0
		prev = make([]byte, 32)
		err = nil
	}
	if err != nil {
		return 0, err
	}
	pairSeq++
	sum := auditRecordHash(prev, rec)
	sig := make([]byte, 64)
	kid := "unsigned"
	if s.auditSigner != nil {
		var key []byte
		if err := tx.QueryRowContext(ctx, `SELECT wrapped_key FROM pairing_keys WHERE pairing_id=?`, pairingID).Scan(&key); err != nil {
			return 0, err
		}
		if len(rec.Leaf) > 0 {
			rec.ContentHash = audit.ContentHash(key, rec.Leaf)
			rec.ContentHashKind = audit.ContentPlaintext
			rec.ContentSize = len(rec.Leaf)
		}
		instance := s.auditInstance
		if instance == "" {
			instance = "peerline"
		}
		signed := audit.Record{
			RecordID: rec.RecordID, TS: rec.TsMs, Instance: instance,
			PairingID: pairingID, FromPeer: rec.FromPeer, ToPeer: rec.ToPeer,
			EventType: rec.EventType, ContentHash: rec.ContentHash,
			ContentHashKind: rec.ContentHashKind, ContentSize: rec.ContentSize,
			PrevHash: prev,
		}
		if err := audit.Sign(&signed, s.auditSigner); err != nil {
			return 0, err
		}
		sum, sig, kid = signed.RecordHash, signed.Sig, signed.SigKID
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_records (
  record_id, pairing_id, pair_seq, ts_ms, event_type, from_peer, to_peer,
  content_hash, content_hash_kind, content_size, extra_json, prev_hash, record_hash, sig, sig_kid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.RecordID, pairingID, pairSeq, rec.TsMs, rec.EventType, rec.FromPeer, rec.ToPeer,
		rec.ContentHash, rec.ContentHashKind, rec.ContentSize, rec.ExtraJSON, prev, sum, sig, kid); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_chain_heads (pairing_id, pair_seq, head_hash) VALUES (?, ?, ?)
ON CONFLICT(pairing_id) DO UPDATE SET pair_seq=excluded.pair_seq, head_hash=excluded.head_hash`,
		pairingID, pairSeq, sum); err != nil {
		return 0, err
	}
	return pairSeq, nil
}

func ensurePairing(ctx context.Context, tx DBTX, from, to string, tsMs int64) (string, error) {
	lo, hi := orderedPeers(from, to)
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM pairings WHERE peer_lo=? AND peer_hi=?`, lo, hi).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	id, err = generatePublicID()
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO pairings (id, peer_lo, peer_hi, created_at) VALUES (?, ?, ?, ?)`, id, lo, hi, tsMs); err != nil {
		return "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	// key_version 0: random bytes, not yet wrapped. The keyring wraps this later.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO pairing_keys (pairing_id, wrapped_key, key_version, created_at) VALUES (?, ?, 0, ?)`, id, key, tsMs); err != nil {
		return "", err
	}
	return id, nil
}

func orderedPeers(a, b string) (string, string) {
	if a == "" {
		a = b
	}
	if b == "" {
		b = a
	}
	if a > b {
		return b, a
	}
	return a, b
}

func auditRecordHash(prev []byte, rec AuditRecord) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte{0})
	h.Write([]byte(rec.EventType))
	h.Write([]byte{0})
	h.Write([]byte(rec.RecordID))
	h.Write([]byte{0})
	h.Write([]byte(rec.FromPeer))
	h.Write([]byte{0})
	h.Write([]byte(rec.ToPeer))
	h.Write([]byte{0})
	h.Write(rec.ContentHash)
	return h.Sum(nil)
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

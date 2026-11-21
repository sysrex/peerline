package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
)

const (
	maxActiveSigningKeys = 5
	signingKeyRegistered = "signing_key.registered"
	signingKeyRevoked    = "signing_key.revoked"
)

// ErrSigningKeyExists means this kid or public key is already active.
var ErrSigningKeyExists = errors.New("signing key exists")

// ErrTooManySigningKeys means the peer already has five active keys.
var ErrTooManySigningKeys = errors.New("too many signing keys")

// SigningKey is a peer's public Ed25519 key. Peerline never stores a private key.
type SigningKey struct {
	KID       string
	PubKey    []byte
	ValidFrom int64
	ValidTo   int64
	RevokedAt int64
}

// SigningKeyAudit is one hash-chained registration or revocation.
type SigningKeyAudit struct {
	Seq        int64
	EventType  string
	PeerID     string
	KID        string
	PubkeyHash []byte
	PrevHash   []byte
	RecordHash []byte
	CreatedAt  int64
}

// RegisterSigningKey stores a public key and appends a chained audit record.
func (s *Store) RegisterSigningKey(ctx context.Context, peerID, kid string, pub []byte, validFrom, validTo int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM peer_signing_keys
WHERE peer_id=? AND revoked_at=0 AND (valid_to=0 OR valid_to>?)`, peerID, validFrom).Scan(&n); err != nil {
		return err
	}
	if n >= maxActiveSigningKeys {
		return ErrTooManySigningKeys
	}
	var dup int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM peer_signing_keys
WHERE peer_id=? AND revoked_at=0 AND (kid=? OR pubkey=?)`, peerID, kid, pub).Scan(&dup); err != nil {
		return err
	}
	if dup > 0 {
		return ErrSigningKeyExists
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO peer_signing_keys (peer_id, kid, pubkey, valid_from, valid_to)
VALUES (?, ?, ?, ?, ?)`, peerID, kid, pub, validFrom, validTo); err != nil {
		return err
	}
	if err := appendSigningKeyAudit(ctx, tx, signingKeyRegistered, peerID, kid, pub, validFrom); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeSigningKey marks a key revoked and appends a chained audit record.
func (s *Store) RevokeSigningKey(ctx context.Context, peerID, kid string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pub []byte
	err = tx.QueryRowContext(ctx, `
SELECT pubkey FROM peer_signing_keys WHERE peer_id=? AND kid=? AND revoked_at=0`, peerID, kid).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE peer_signing_keys SET revoked_at=? WHERE peer_id=? AND kid=? AND revoked_at=0`, now, peerID, kid); err != nil {
		return err
	}
	if err := appendSigningKeyAudit(ctx, tx, signingKeyRevoked, peerID, kid, pub, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ListSigningKeys returns keys that have not been revoked.
func (s *Store) ListSigningKeys(ctx context.Context, peerID string) ([]SigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT kid, pubkey, valid_from, valid_to, revoked_at FROM peer_signing_keys
WHERE peer_id=? AND revoked_at=0 ORDER BY kid`, peerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.KID, &k.PubKey, &k.ValidFrom, &k.ValidTo, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SigningKeyUsable reports whether kid can verify a signature at now.
func (s *Store) SigningKeyUsable(ctx context.Context, peerID, kid string, now int64) (bool, error) {
	var validFrom, validTo, revoked int64
	err := s.db.QueryRowContext(ctx, `
SELECT valid_from, valid_to, revoked_at FROM peer_signing_keys
WHERE peer_id=? AND kid=?`, peerID, kid).Scan(&validFrom, &validTo, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if revoked != 0 || now < validFrom || (validTo != 0 && now >= validTo) {
		return false, nil
	}
	return true, nil
}

// SigningKeyAuditLog returns the chain in append order.
func (s *Store) SigningKeyAuditLog(ctx context.Context) ([]SigningKeyAudit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT seq, event_type, peer_id, kid, pubkey_hash, prev_hash, record_hash, created_at
FROM signing_key_audit ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKeyAudit
	for rows.Next() {
		var a SigningKeyAudit
		if err := rows.Scan(&a.Seq, &a.EventType, &a.PeerID, &a.KID, &a.PubkeyHash, &a.PrevHash, &a.RecordHash, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func appendSigningKeyAudit(ctx context.Context, tx *sql.Tx, event, peerID, kid string, pub []byte, ts int64) error {
	pubHash := sha256.Sum256(pub)
	prev := make([]byte, 32)
	err := tx.QueryRowContext(ctx, `SELECT record_hash FROM signing_key_audit ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		prev = make([]byte, 32)
		err = nil
	}
	if err != nil {
		return err
	}
	sum := signingKeyRecordHash(prev, event, peerID, kid, pubHash[:], ts)
	_, err = tx.ExecContext(ctx, `
INSERT INTO signing_key_audit (event_type, peer_id, kid, pubkey_hash, prev_hash, record_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, event, peerID, kid, pubHash[:], prev, sum, ts)
	return err
}

func signingKeyRecordHash(prev []byte, event, peerID, kid string, pubHash []byte, ts int64) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte(event))
	h.Write([]byte{0})
	h.Write([]byte(peerID))
	h.Write([]byte{0})
	h.Write([]byte(kid))
	h.Write([]byte{0})
	h.Write(pubHash)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	h.Write(b[:])
	return h.Sum(nil)
}

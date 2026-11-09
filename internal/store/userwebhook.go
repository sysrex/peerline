package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
)

// PeerWebhook is one peer's push endpoint. Secret and OldSecret are whsec_ values.
type PeerWebhook struct {
	URL              string
	Secret           string
	OldSecret        string
	OldSecretExpires int64
	Enabled          bool
	Dead             bool
	Events           string
}

// PutPeerWebhook stores a new endpoint and returns a new secret. The endpoint
// stays disabled until MarkPeerWebhookEnabled.
func (s *Store) PutPeerWebhook(ctx context.Context, peerID, rawURL string) (secret string, err error) {
	secret, err = newWebhookSecret()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO peer_webhook (peer_id, url, secret, enabled, dead, events)
VALUES (?, ?, ?, 0, 0, 'message.received')
ON CONFLICT(peer_id) DO UPDATE SET url=excluded.url, secret=excluded.secret, enabled=0, dead=0`,
		peerID, rawURL, secret)
	return secret, err
}

// MarkPeerWebhookEnabled turns delivery on after the challenge succeeds.
func (s *Store) MarkPeerWebhookEnabled(ctx context.Context, peerID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE peer_webhook SET enabled=1, dead=0 WHERE peer_id=?`, peerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetPeerWebhook returns the endpoint without revealing the secret to callers
// that only need status. includeSecret is for delivery and rotation.
func (s *Store) GetPeerWebhook(ctx context.Context, peerID string, includeSecret bool) (PeerWebhook, error) {
	var w PeerWebhook
	var enabled, dead int
	err := s.db.QueryRowContext(ctx, `SELECT url, secret, old_secret, old_secret_expires_at, enabled, dead, events FROM peer_webhook WHERE peer_id=?`, peerID).
		Scan(&w.URL, &w.Secret, &w.OldSecret, &w.OldSecretExpires, &enabled, &dead, &w.Events)
	if errors.Is(err, sql.ErrNoRows) {
		return PeerWebhook{}, ErrNotFound
	}
	if err != nil {
		return PeerWebhook{}, err
	}
	w.Enabled, w.Dead = enabled == 1, dead == 1
	if !includeSecret {
		w.Secret, w.OldSecret = "", ""
	}
	return w, nil
}

// DeletePeerWebhook removes the endpoint.
func (s *Store) DeletePeerWebhook(ctx context.Context, peerID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peer_webhook WHERE peer_id=?`, peerID)
	return err
}

// RotatePeerWebhookSecret replaces the secret and keeps the old one until expiresAt.
func (s *Store) RotatePeerWebhookSecret(ctx context.Context, peerID string, expiresAt int64) (secret string, err error) {
	secret, err = newWebhookSecret()
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE peer_webhook
SET old_secret=secret, old_secret_expires_at=?, secret=?
WHERE peer_id=?`, expiresAt, secret, peerID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}

// WebhookDelivery is the status of one push. Payload stays in the row for retries
// and is not returned by the status API.
type WebhookDelivery struct {
	ID        string
	MessageID int64
	Status    string
	Attempts  int
	CreatedAt int64
}

// SaveWebhookDelivery inserts one row per message. A later attempt keeps the
// original id and increments attempts.
func (s *Store) SaveWebhookDelivery(ctx context.Context, id, peerID string, messageID int64, payload, status string, now int64) (attempts int, err error) {
	_, err = s.db.ExecContext(ctx, `
INSERT INTO webhook_delivery (id, peer_id, message_id, status, attempts, created_at, payload)
VALUES (?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(peer_id, message_id) DO UPDATE SET
  status=excluded.status,
  attempts=webhook_delivery.attempts+1`, id, peerID, messageID, status, now, payload)
	if err != nil {
		return 0, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT attempts FROM webhook_delivery WHERE peer_id=? AND message_id=?`, peerID, messageID).Scan(&attempts)
	return attempts, err
}

// ListWebhookDeliveries returns the newest status rows, without payloads.
func (s *Store) ListWebhookDeliveries(ctx context.Context, peerID string, limit int) ([]WebhookDelivery, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, message_id, status, attempts, created_at FROM webhook_delivery
WHERE peer_id=? ORDER BY created_at DESC, id DESC LIMIT ?`, peerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.MessageID, &d.Status, &d.Attempts, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkPeerWebhookDead disables delivery after a 410 or a dead-letter.
func (s *Store) MarkPeerWebhookDead(ctx context.Context, peerID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE peer_webhook SET dead=1, enabled=0 WHERE peer_id=?`, peerID)
	return err
}

// WebhookDeliveryCount returns how many delivery rows a peer has for a message.
func (s *Store) WebhookDeliveryCount(ctx context.Context, peerID string, messageID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webhook_delivery WHERE peer_id=? AND message_id=?`, peerID, messageID).Scan(&n)
	return n, err
}

func newWebhookSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b), nil
}

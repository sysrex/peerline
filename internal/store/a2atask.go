package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"
)

const (
	A2AMaxEnvelope = 4096
	A2AMaxArtifact = 64 << 10
	a2aTTLDefault  = 30 * 24 * time.Hour
)

var (
	a2aPurgeBatch      = 500
	a2aPurgeMaxBatches = 100
	a2aPurgeYield      = 25 * time.Millisecond
)

// ErrA2ATerminal means the task is finished and cannot take another message.
var ErrA2ATerminal = errors.New("task is terminal")

// ErrA2ANotCancelable means cancel was asked of a task that cannot be canceled.
var ErrA2ANotCancelable = errors.New("task not cancelable")

// ErrA2ATooLarge means an envelope or artifact exceeds its cap.
var ErrA2ATooLarge = errors.New("a2a payload too large")

// A2ATask is one durable task. History and artifacts are JSON text.
type A2ATask struct {
	ID         string
	ContextID  string
	ClientPeer string
	ExecPeer   string
	State      string
	History    string
	Artifacts  string
	ExpiresAt  int64
}

// A2ATransition reports whether from -> to is legal.
func A2ATransition(from, to string) error {
	if a2aTerminal(from) {
		if to == "canceled" {
			return ErrA2ANotCancelable
		}
		return ErrA2ATerminal
	}
	switch to {
	case "working", "input_required", "auth_required", "completed", "failed", "canceled", "rejected":
		if from == "submitted" || from == "working" || from == "input_required" || from == "auth_required" {
			if from == "auth_required" && (to == "input_required" || to == "rejected" || to == "completed") {
				return ErrA2ATerminal
			}
			return nil
		}
	}
	return ErrA2ATerminal
}

func a2aTerminal(state string) bool {
	switch state {
	case "completed", "failed", "canceled", "rejected":
		return true
	default:
		return false
	}
}

// CreateA2ATask inserts a submitted task. envelope is the canonical message
// body and must be at most 4096 bytes. artifacts, when set, must be at most 64 KiB.
func (s *Store) CreateA2ATask(ctx context.Context, id, contextID, client, exec, envelope, artifacts string, ttl time.Duration) error {
	if len(envelope) > A2AMaxEnvelope || len(artifacts) > A2AMaxArtifact {
		return ErrA2ATooLarge
	}
	if ttl <= 0 {
		ttl = a2aTTLDefault
	}
	now := s.clk.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if artifacts == "" {
		artifacts = "[]"
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO a2a_tasks (id, context_id, client_peer, exec_peer, state, created_at, updated_at, expires_at, history_json, artifacts_json)
VALUES (?, ?, ?, ?, 'submitted', ?, ?, ?, ?, ?)`,
		id, contextID, client, exec, now.Unix(), now.Unix(), now.Add(ttl).Unix(), envelope, artifacts)
	if err != nil {
		return err
	}
	leaf, err := tokenLeaf("task.created", "submitted")
	if err != nil {
		return err
	}
	if err := s.noteAudit(ctx, tx, "task.created", client, exec, leaf, ""); err != nil {
		return err
	}
	return tx.Commit()
}

// GetA2ATask returns the task to its client or executor. Anyone else gets ErrNotFound.
func (s *Store) GetA2ATask(ctx context.Context, id, peer string) (A2ATask, error) {
	var t A2ATask
	err := s.db.QueryRowContext(ctx, `
SELECT id, context_id, client_peer, exec_peer, state, history_json, artifacts_json, expires_at
FROM a2a_tasks WHERE id=? AND (client_peer=? OR exec_peer=?)`, id, peer, peer).
		Scan(&t.ID, &t.ContextID, &t.ClientPeer, &t.ExecPeer, &t.State, &t.History, &t.Artifacts, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return A2ATask{}, ErrNotFound
	}
	return t, err
}

// AnswerA2ATask moves the task. Only the executor may call it.
func (s *Store) AnswerA2ATask(ctx context.Context, id, exec, to, message, artifacts string) error {
	if len(message) > A2AMaxEnvelope || len(artifacts) > A2AMaxArtifact {
		return ErrA2ATooLarge
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var from, client string
	err = tx.QueryRowContext(ctx, `SELECT state, client_peer FROM a2a_tasks WHERE id=? AND exec_peer=?`, id, exec).Scan(&from, &client)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := A2ATransition(from, to); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
UPDATE a2a_tasks SET state=?, updated_at=?, history_json=CASE WHEN ?!='' THEN ? ELSE history_json END,
  artifacts_json=CASE WHEN ?!='' THEN ? ELSE artifacts_json END
WHERE id=?`, to, s.clk.Now().Unix(), message, message, artifacts, artifacts, id)
	if err != nil {
		return err
	}
	leaf, err := tokenLeaf("task.status", to)
	if err != nil {
		return err
	}
	if err := s.noteAudit(ctx, tx, "task.status", client, exec, leaf, ""); err != nil {
		return err
	}
	if artifacts != "" {
		art, err := tokenLeaf("artifact.update", "")
		if err != nil {
			return err
		}
		if err := s.noteAudit(ctx, tx, "artifact.update", client, exec, art, ""); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EnableAuditForTest turns the audit writer on so an API test can see records.
func EnableAuditForTest(s *Store, key ed25519.PrivateKey) {
	s.auditEnabled = true
	s.auditSigner = key
}

// AuditEventCount is the number of audit rows of one event type.
func AuditEventCount(s *Store, event string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE event_type=?`, event).Scan(&n)
	return n, err
}

// NoteA2ACall records one JSON-RPC call. The leaf is hashes, not peer ids.
func (s *Store) NoteA2ACall(ctx context.Context, peer string, leaf []byte) error {
	return s.noteAudit(ctx, nil, "a2a.rpc", peer, "", leaf, "")
}

// ListA2ATasks returns tasks where peer is the client or the executor.
func (s *Store) ListA2ATasks(ctx context.Context, peer string, limit int) ([]A2ATask, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, context_id, client_peer, exec_peer, state, history_json, artifacts_json, expires_at
FROM a2a_tasks WHERE client_peer=? OR exec_peer=? ORDER BY updated_at DESC LIMIT ?`, peer, peer, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []A2ATask
	for rows.Next() {
		var t A2ATask
		if err := rows.Scan(&t.ID, &t.ContextID, &t.ClientPeer, &t.ExecPeer, &t.State, &t.History, &t.Artifacts, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PurgeA2ATasks deletes expired tasks in batches.
func (s *Store) PurgeA2ATasks(ctx context.Context) (int, bool, error) {
	now := s.clk.Now().Unix()
	deleted := 0
	for batches := 0; ; batches++ {
		if err := ctx.Err(); err != nil {
			return deleted, false, err
		}
		if batches == a2aPurgeMaxBatches {
			return deleted, true, nil
		}
		res, err := s.db.ExecContext(ctx, `DELETE FROM a2a_tasks WHERE rowid IN (SELECT rowid FROM a2a_tasks WHERE expires_at < ? LIMIT ?)`, now, a2aPurgeBatch)
		if err != nil {
			return deleted, false, err
		}
		n, _ := res.RowsAffected()
		deleted += int(n)
		if int(n) < a2aPurgeBatch {
			return deleted, false, nil
		}
		select {
		case <-ctx.Done():
			return deleted, false, ctx.Err()
		case <-time.After(a2aPurgeYield):
		}
	}
}

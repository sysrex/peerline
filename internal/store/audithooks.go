package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/sysrex/peerline/internal/audit"
)

// noteAudit appends one signed record in tx. A nil tx starts its own transaction.
// Audit disabled returns immediately, before any hashing, so the request path
// does not pay for a record. Audit enabled without a signing key fails closed.
func (s *Store) noteAudit(ctx context.Context, tx DBTX, event, from, to string, leaf []byte, extra string) error {
	if !s.auditEnabled {
		return nil
	}
	if s.auditFail != nil {
		if err := s.auditFail(); err != nil {
			return err
		}
	}
	if len(s.auditSigner) == 0 {
		return errors.New("audit signing key is not configured")
	}
	_, err := s.AppendAudit(ctx, tx, AuditRecord{
		EventType: event,
		FromPeer:  from,
		ToPeer:    to,
		Leaf:      leaf,
		ExtraJSON: extra,
	})
	return err
}

func messageLeaf(m *Message) ([]byte, error) {
	body := map[string]any{"type": m.Type, "body": m.Body}
	if m.ReplyTo != nil {
		body["reply_to"] = *m.ReplyTo
	}
	return audit.Canonical(body)
}

func bagLeaf(version int64, content []byte) ([]byte, error) {
	sum := sha256.Sum256(content)
	return audit.Canonical(map[string]any{
		"version":        version,
		"content_sha256": hex.EncodeToString(sum[:]),
	})
}

func tokenLeaf(event, prefix string) ([]byte, error) {
	return audit.Canonical(map[string]any{"event": event, "prefix": prefix})
}
func (s *Store) noteGrant(ctx context.Context, tx DBTX, g *Grant) error {
	if g == nil {
		return nil
	}
	leaf, err := tokenLeaf("grant.created", "")
	if err != nil {
		return err
	}
	return s.noteAudit(ctx, tx, "grant.created", g.Owner, g.Grantee, leaf, extraJSON(g.Scopes))
}

func extraJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// Package audit is the append-only record log used by later compliance work.
// The SQLite implementation is not in this package; SQL stays in internal/store.
package audit

import (
	"context"
	"errors"

	"github.com/sysrex/peerline/internal/store"
)

// ErrNotFound is returned when a pairing has no record in the requested range.
var ErrNotFound = errors.New("audit record not found")

// Record is one hash-chained event. Payload is the canonical content bytes.
// Seq is assigned by the store and is unique per PairingID.
type Record struct {
	PairingID string
	Seq       int64
	Kind      string
	Payload   []byte
	CreatedAt int64
	BatchID   string
	AnchorRef string
}

// LogStore appends records inside the caller's transaction and reads them back.
// now, when a memory fake needs it, is supplied by the constructor, not by the methods.
type LogStore interface {
	// Append writes rec in tx and returns the assigned sequence.
	Append(ctx context.Context, tx store.DBTX, rec Record) (seq int64, err error)
	// ReadRange returns records with fromSeq <= seq <= toSeq, in order.
	// toSeq < 0 means through the latest record.
	ReadRange(ctx context.Context, pairingID string, fromSeq, toSeq int64) ([]Record, error)
	// MarkBatched stamps records with seq <= throughSeq that are not yet batched.
	MarkBatched(ctx context.Context, tx store.DBTX, pairingID string, throughSeq int64, batchID string) error
	// MarkAnchored stamps every record in batchID with the anchor reference.
	MarkAnchored(ctx context.Context, tx store.DBTX, batchID, anchorRef string) error
	// DeleteBefore removes records with CreatedAt < beforeUnix and returns how many.
	DeleteBefore(ctx context.Context, tx store.DBTX, beforeUnix int64) (int, error)
}

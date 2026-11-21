// Package audit is the append-only record log used by later compliance work.
// The SQLite implementation is not in this package; SQL stays in internal/store.
package audit

import (
	"context"
	"database/sql"
	"errors"
)

// ErrNotFound is returned when a pairing has no record in the requested range.
var ErrNotFound = errors.New("audit record not found")

// Tx is the transaction a LogStore writes through. It matches store.DBTX
// (*sql.DB and *sql.Tx) without importing that package.
type Tx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LogRecord is one stored event. Payload is opaque bytes.
// Seq is assigned by the store and is unique per PairingID.
// The signed, canonical record is Record, defined alongside the chain.
type LogRecord struct {
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
	Append(ctx context.Context, tx Tx, rec LogRecord) (seq int64, err error)
	// ReadRange returns records with fromSeq <= seq <= toSeq, in order.
	// toSeq < 0 means through the latest record.
	ReadRange(ctx context.Context, pairingID string, fromSeq, toSeq int64) ([]LogRecord, error)
	// MarkBatched stamps records with seq <= throughSeq that are not yet batched.
	MarkBatched(ctx context.Context, tx Tx, pairingID string, throughSeq int64, batchID string) error
	// MarkAnchored stamps every record in batchID with the anchor reference.
	MarkAnchored(ctx context.Context, tx Tx, batchID, anchorRef string) error
	// DeleteBefore removes records with CreatedAt < beforeUnix and returns how many.
	DeleteBefore(ctx context.Context, tx Tx, beforeUnix int64) (int, error)
}

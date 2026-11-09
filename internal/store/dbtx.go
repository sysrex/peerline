package store

import (
	"context"
	"database/sql"
)

// DBTX is the subset of *sql.DB and *sql.Tx that domain writes share with
// an audit append. SQL text stays in this package; callers pass the handle.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Compile-time proof that the database handle and a transaction both qualify.
var (
	_ DBTX = (*sql.DB)(nil)
	_ DBTX = (*sql.Tx)(nil)
)

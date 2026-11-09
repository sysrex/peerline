// Package a2a is the port for the agent-to-agent task store.
// The SQLite tables and the JSON-RPC gateway come in later issues.
package a2a

import (
	"context"
	"errors"

	"github.com/sysrex/peerline/internal/store"
)

// ErrNotFound means the task id does not exist.
var ErrNotFound = errors.New("task not found")

// ErrConflict means the task was not in the expected state.
var ErrConflict = errors.New("task state conflict")

// State is the task lifecycle. Transitions are checked by TaskStore.Update.
type State string

const (
	StateSubmitted State = "submitted"
	StateWorking   State = "working"
	StateCompleted State = "completed"
	StateCanceled  State = "canceled"
	StateFailed    State = "failed"
)

// Task is one unit of agent work.
type Task struct {
	ID        string
	ContextID string
	PeerID    string
	State     State
	History   []byte
}

// TaskStore creates and updates tasks. Update names the state the caller
// observed; a mismatch returns ErrConflict and does not write.
type TaskStore interface {
	Create(ctx context.Context, tx store.DBTX, task Task) error
	Get(ctx context.Context, id string) (Task, error)
	List(ctx context.Context, peerID string, limit int) ([]Task, error)
	Update(ctx context.Context, tx store.DBTX, id string, from, to State, history []byte) error
}

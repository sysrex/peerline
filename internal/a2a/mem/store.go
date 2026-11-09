// Package mem is an in-memory a2a.TaskStore.
package mem

import (
	"context"
	"slices"

	"github.com/sysrex/peerline/internal/a2a"
	"github.com/sysrex/peerline/internal/store"
)

// Store is a process-local task map.
type Store struct {
	tasks map[string]a2a.Task
}

// New returns an empty store.
func New() *Store { return &Store{tasks: map[string]a2a.Task{}} }

func (s *Store) Create(_ context.Context, _ store.DBTX, task a2a.Task) error {
	if _, ok := s.tasks[task.ID]; ok {
		return a2a.ErrConflict
	}
	if task.State == "" {
		task.State = a2a.StateSubmitted
	}
	task.History = append([]byte(nil), task.History...)
	s.tasks[task.ID] = task
	return nil
}

func (s *Store) Get(_ context.Context, id string) (a2a.Task, error) {
	task, ok := s.tasks[id]
	if !ok {
		return a2a.Task{}, a2a.ErrNotFound
	}
	task.History = append([]byte(nil), task.History...)
	return task, nil
}

func (s *Store) List(_ context.Context, peerID string, limit int) ([]a2a.Task, error) {
	var out []a2a.Task
	for _, task := range s.tasks {
		if task.PeerID == peerID {
			out = append(out, task)
		}
	}
	slices.SortFunc(out, func(a, b a2a.Task) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) Update(_ context.Context, _ store.DBTX, id string, from, to a2a.State, history []byte) error {
	task, ok := s.tasks[id]
	if !ok {
		return a2a.ErrNotFound
	}
	if task.State != from {
		return a2a.ErrConflict
	}
	task.State = to
	if history != nil {
		task.History = append([]byte(nil), history...)
	}
	s.tasks[id] = task
	return nil
}

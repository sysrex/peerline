// Package conform is the shared TaskStore test suite.
package conform

import (
	"context"
	"errors"
	"testing"

	"github.com/sysrex/peerline/internal/a2a"
)

// TaskStore runs the cases every a2a.TaskStore must pass.
func TaskStore(t *testing.T, open func() a2a.TaskStore) {
	t.Helper()
	ctx := context.Background()
	s := open()
	task := a2a.Task{ID: "t1", ContextID: "c1", PeerID: "peer", State: a2a.StateSubmitted, History: []byte("hi")}
	if err := s.Create(ctx, nil, task); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(ctx, nil, task); !errors.Is(err, a2a.ErrConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	got, err := s.Get(ctx, "t1")
	if err != nil || got.State != a2a.StateSubmitted {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.Get(ctx, "missing"); !errors.Is(err, a2a.ErrNotFound) {
		t.Fatalf("missing get: %v", err)
	}
	if err := s.Update(ctx, nil, "t1", a2a.StateWorking, a2a.StateCompleted, nil); !errors.Is(err, a2a.ErrConflict) {
		t.Fatalf("wrong from-state: %v", err)
	}
	if err := s.Update(ctx, nil, "t1", a2a.StateSubmitted, a2a.StateWorking, []byte("work")); err != nil {
		t.Fatalf("update: %v", err)
	}
	list, err := s.List(ctx, "peer", 10)
	if err != nil || len(list) != 1 || list[0].State != a2a.StateWorking || string(list[0].History) != "work" {
		t.Fatalf("list: %+v %v", list, err)
	}
}

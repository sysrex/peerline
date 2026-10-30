package api

import (
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/store"
)

// newTestServer creates a Server whose rate limiters use a custom clock (testing only).
func newTestServer(st *store.Store, cfg Config, clock func() time.Time) *Server {
	cfg.Now = clock
	srv, err := New(st, cfg)
	if err != nil {
		panic(err)
	}
	return srv
}

func mustNew(t testing.TB, st *store.Store, cfg Config) *Server {
	t.Helper()
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

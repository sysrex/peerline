package api

import (
	"time"

	"github.com/sysrex/peerline/internal/store"
)

// newTestServer creates a Server whose rate limiters use a custom clock (testing only).
func newTestServer(st *store.Store, cfg Config, clock func() time.Time) *Server {
	cfg.Now = clock
	return New(st, cfg)
}

package api

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/store"
)

// newTestServer creates a Server whose rate limiters use a custom clock (testing only).
func newTestServer(st *store.Store, cfg Config, clock func() time.Time) *Server {
	cfg.Now = clock
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		panic(err)
	}
	applyTestLimitDefaults(&cfg)
	srv, err := New(st, cfg)
	if err != nil {
		panic(err)
	}
	return srv
}

// applyTestLimitDefaults sets high write and auth-failure limits unless a test configures them.
func applyTestLimitDefaults(cfg *Config) {
	if cfg.WritePerMinute == 0 {
		cfg.WritePerMinute = 1000
		cfg.WriteBurst = 100
	}
	if cfg.AuthFailPerMinute == 0 {
		cfg.AuthFailPerMinute = 1000
		cfg.AuthFailBurst = 100
	}
}

func prepareTestConfig(t testing.TB, st *store.Store, cfg *Config) {
	t.Helper()
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	applyTestLimitDefaults(cfg)
}

func mustNew(t testing.TB, st *store.Store, cfg Config) *Server {
	t.Helper()
	prepareTestConfig(t, st, &cfg)
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

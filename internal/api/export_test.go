package api

import (
	"context"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/msg"
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

// withLimiterOverride applies a limiter override to a Server, preserving the server's clock.
// The callback receives the LimiterManager and a constructor that builds limiters using the
// server's clock, so callers cannot forget to pass WithClock.
// Use this in tests that need custom rate limits without duplicating LimiterManager setup.
func withLimiterOverride(t *testing.T, s *Server, f func(lm *LimiterManager, newLimiter func(perMinute, burst int) *msg.Limiter)) {
	t.Helper()
	newLimiter := func(perMinute, burst int) *msg.Limiter {
		return msg.NewLimiter(perMinute, burst, msg.WithClock(s.now))
	}
	f(s.lim, newLimiter)
}

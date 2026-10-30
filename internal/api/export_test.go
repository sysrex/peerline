package api

import (
	"context"
	"time"

	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

// newTestLimiterManager creates a LimiterManager with a custom clock for testing.
func newTestLimiterManager(cfg Config, clock func() time.Time) *LimiterManager {
	ctx, cancel := context.WithCancel(context.Background())
	opts := []msg.LimiterOption{msg.WithClock(clock)}

	lm := &LimiterManager{
		msgLim:        msg.NewLimiter(cfg.MsgPerMinute, cfg.MsgBurst, opts...),
		regLim:        msg.NewLimiter(10, 5, opts...),
		pairLim:       msg.NewLimiter(10, 5, opts...),
		failLim:       msg.NewLimiter(cfg.AuthFailPerMinute, cfg.AuthFailBurst, opts...),
		getLim:        msg.NewLimiter(getPerMinute, getBurst, opts...),
		authLim:       msg.NewLimiter(authGetPerMinute, authGetBurst, opts...),
		writeLim:      msg.NewLimiter(cfg.WritePerMinute, cfg.WriteBurst, opts...),
		mailLim:       msg.NewLimiterPerHour(cfg.EmailPerHour, cfg.EmailBurst, opts...),
		rcptLim:       msg.NewLimiterPerHour(cfg.EmailRcptPerHour, cfg.EmailRcptPerHour, opts...),
		notifyLim:     msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst, opts...),
		notifyAddrLim: msg.NewLimiterPerHour(cfg.NotifyPerHour, cfg.NotifyBurst, opts...),
		ctx:           ctx,
		cancel:        cancel,
	}

	lm.wg.Add(1)
	go lm.pruneLoop()

	return lm
}

// newTestServer creates a Server with a custom clock for rate limiters (testing only).
func newTestServer(st *store.Store, cfg Config, clock func() time.Time) *Server {
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		panic(err)
	}
	if cfg.WritePerMinute == 0 {
		cfg.WritePerMinute = 1000
		cfg.WriteBurst = 100
	}
	if cfg.AuthFailPerMinute == 0 {
		cfg.AuthFailPerMinute = 1000
		cfg.AuthFailBurst = 100
	}
	srv, err := New(st, cfg)
	if err != nil {
		panic(err)
	}
	srv.lim.Stop()
	srv.lim = newTestLimiterManager(srv.cfg, clock)
	return srv
}

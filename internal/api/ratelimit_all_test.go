package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/sysrex/peerline/internal/clock"
	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
)

func TestLimiterManagerAllCoversEveryLimiter(t *testing.T) {
	lm := NewLimiterManager(Config{Clock: clock.Real{}, MsgPerMinute: 1, MsgBurst: 1, AuthFailPerMinute: 1, AuthFailBurst: 1,
		WritePerMinute: 1, WriteBurst: 1, EmailPerHour: 1, EmailBurst: 1, EmailRcptPerHour: 1, NotifyPerHour: 1, NotifyBurst: 1})
	defer lm.Stop()
	listed := map[unsafe.Pointer]bool{}
	for _, l := range lm.all() {
		listed[unsafe.Pointer(l)] = true
	}
	v := reflect.ValueOf(lm).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Type() == reflect.TypeOf((*msg.Limiter)(nil)) && !listed[f.UnsafePointer()] {
			t.Errorf("limiter %s missing from all()", v.Type().Field(i).Name)
		}
	}
}

func TestVersionLimiterPruned(t *testing.T) {
	clk := clocktest.New(time.Unix(1e9, 0))
	lm := NewLimiterManager(Config{Clock: clk, MsgPerMinute: 1, MsgBurst: 1, AuthFailPerMinute: 1, AuthFailBurst: 1,
		WritePerMinute: 1, WriteBurst: 1, EmailPerHour: 1, EmailBurst: 1, EmailRcptPerHour: 1, NotifyPerHour: 1, NotifyBurst: 1})
	defer lm.Stop()
	lm.versionLim.Allow("1.2.3.4")
	clk.Advance(time.Hour)
	if n := lm.versionLim.Prune(); n != 1 {
		t.Fatalf("sanity: expected 1 idle bucket, got %d", n)
	}
	lm.versionLim.Allow("1.2.3.4")
	clk.Advance(time.Hour)
	lm.prune()
	if n := lm.versionLim.Prune(); n != 0 {
		t.Errorf("prune() left %d stale /version buckets", n)
	}
}

func TestBlankTrustedProxyEntriesWarn(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv, err := New(st, Config{TrustedProxies: []string{" ", " "}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	if !strings.Contains(buf.String(), "no trusted proxies configured") {
		t.Errorf("expected warning for blank entries, got %q", buf.String())
	}
}

func TestMessageBudgetIndependentOfWriteBucket(t *testing.T) {
	srv := newServer(t, Config{MsgPerMinute: 60, MsgBurst: 20, WritePerMinute: 1, WriteBurst: 3})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	pairUp(t, a, b, []string{"messages"}, nil, nil)
	for i := 0; i < 10; i++ {
		resp, body := b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, 201)
	}
}

// TestMessageSendLimiters locks the two buckets a POST /v1/peers/{id}/messages
// actually charges: the shared authenticated-request limiter first (120/min,
// burst 40, Retry-After 10), then the message limiter after the grant check
// (Retry-After 2). The write bucket is not one of them. A 403 does not spend
// a message token.
func TestMessageSendLimiters(t *testing.T) {
	t.Run("write bucket exhausted", func(t *testing.T) {
		// pairUp spends bob's two write tokens (accept, then the single-use replay).
		srv := newServer(t, Config{MsgPerMinute: 60, MsgBurst: 5, WritePerMinute: 1, WriteBurst: 2})
		alice, bob := register(t, srv, "alice"), register(t, srv, "bob")
		pairUp(t, alice, bob, []string{"messages"}, nil, nil)

		resp, body := bob.do("PUT", "/v1/me", map[string]any{"notify_email": ""}, nil)
		want(t, resp, body, http.StatusTooManyRequests)
		if got := resp.Header.Get("Retry-After"); got != "2" {
			t.Fatalf("exhausted write bucket Retry-After = %q, want 2", got)
		}

		resp, body = bob.do("POST", "/v1/peers/"+alice.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, http.StatusCreated)
	})

	t.Run("forbidden send does not spend message budget", func(t *testing.T) {
		srv := newServer(t, Config{MsgPerMinute: 1, MsgBurst: 3})
		alice, bob := register(t, srv, "alice"), register(t, srv, "bob")
		for i := 0; i < 12; i++ {
			resp, body := bob.do("POST", "/v1/peers/"+alice.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
			want(t, resp, body, http.StatusForbidden)
		}
		pairUp(t, alice, bob, []string{"messages"}, nil, nil)
		for i := 0; i < 3; i++ {
			resp, body := bob.do("POST", "/v1/peers/"+alice.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
			want(t, resp, body, http.StatusCreated)
		}
		resp, body := bob.do("POST", "/v1/peers/"+alice.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, http.StatusTooManyRequests)
		if got := resp.Header.Get("Retry-After"); got != "2" {
			t.Fatalf("message limiter Retry-After = %q, want 2", got)
		}
		resp, body = bob.do("GET", "/v1/inbox", nil, nil)
		want(t, resp, body, http.StatusOK)
	})

	t.Run("authenticated request bucket binds first", func(t *testing.T) {
		st, err := store.Open(t.TempDir() + "/t.db")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		// Freeze the limiter clock at the real instant the invite is created.
		// A 1970 timestamp would already be expired against the store clock.
		frozen := time.Now()
		s := newTestServer(st, Config{}, func() time.Time { return frozen })
		defer s.Stop()
		srv := httptest.NewServer(s.Handler())
		defer srv.Close()

		alice, bob := register(t, srv, "alice"), register(t, srv, "bob")
		pairUp(t, alice, bob, []string{"messages"}, nil, nil)
		const authBurst = 40
		for i := 0; i < authBurst; i++ {
			resp, body := bob.do("GET", "/v1/inbox", nil, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("inbox %d: %d %s", i+1, resp.StatusCode, body)
			}
		}
		resp, body := bob.do("POST", "/v1/peers/"+alice.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
		want(t, resp, body, http.StatusTooManyRequests)
		if got := resp.Header.Get("Retry-After"); got != "10" {
			t.Fatalf("auth limiter Retry-After = %q, want 10", got)
		}
		resp, body = alice.do("GET", "/v1/inbox", nil, nil)
		want(t, resp, body, http.StatusOK)
	})
}

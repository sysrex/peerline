package api

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/sysrex/peerline/internal/msg"
)

func TestLimiterManagerAllCoversEveryLimiter(t *testing.T) {
	lm := NewLimiterManager(Config{Now: time.Now, MsgPerMinute: 1, MsgBurst: 1, AuthFailPerMinute: 1, AuthFailBurst: 1,
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
	now := time.Unix(1e9, 0)
	lm := NewLimiterManager(Config{Now: func() time.Time { return now }, MsgPerMinute: 1, MsgBurst: 1, AuthFailPerMinute: 1, AuthFailBurst: 1,
		WritePerMinute: 1, WriteBurst: 1, EmailPerHour: 1, EmailBurst: 1, EmailRcptPerHour: 1, NotifyPerHour: 1, NotifyBurst: 1})
	defer lm.Stop()
	lm.versionLim.Allow("1.2.3.4")
	now = now.Add(time.Hour)
	if n := lm.versionLim.Prune(); n != 1 {
		t.Fatalf("sanity: expected 1 idle bucket, got %d", n)
	}
	lm.versionLim.Allow("1.2.3.4")
	now = now.Add(time.Hour)
	lm.prune()
	if n := lm.versionLim.Prune(); n != 0 {
		t.Errorf("prune() left %d stale /version buckets", n)
	}
}

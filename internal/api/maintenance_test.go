package api

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

// fakePurger implements StorePurger for testing.
type fakePurger struct {
	mu               sync.Mutex
	calls            []int64 // retention seconds from each call
	purgeReturnCount int
	purgeReturnErr   error
	called           chan struct{} // signals when PurgeExpiredInvites is called
}

func (f *fakePurger) PurgeExpiredInvites(ctx context.Context, retentionSeconds int64) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, retentionSeconds)
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
	return f.purgeReturnCount, f.purgeReturnErr
}

func (f *fakePurger) ReconcileKeyIndex(ctx context.Context, forceRebuild bool) (bool, error) {
	// No-op for these tests
	return false, nil
}

func (f *fakePurger) getCalls() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]int64, len(f.calls))
	copy(copied, f.calls)
	return copied
}

// TestMaintenanceManager_PassesRetentionAndRunsAtStart verifies that the
// maintenance manager passes the configured retention to the purger and
// runs the purge at startup.
func TestMaintenanceManager_PassesRetentionAndRunsAtStart(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	fake := &fakePurger{
		purgeReturnCount: 42,
		called:           make(chan struct{}, 1),
	}
	retention := int64(7 * 24 * 60 * 60) // 7 days

	m := NewMaintenanceManager(ctx, fake, log, retention, 6)
	defer m.Stop()

	// Wait for the startup purge to complete
	select {
	case <-fake.called:
		// Purge was called
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for startup purge")
	}

	calls := fake.getCalls()
	if len(calls) < 1 {
		t.Fatal("expected at least 1 purge call at startup")
	}

	// Verify the retention value was passed correctly
	if calls[0] != retention {
		t.Errorf("expected retention %d, got %d", retention, calls[0])
	}
}

// TestMaintenanceManager_RunsHourly verifies that the maintenance manager
// continues to run purges on the hourly ticker.
func TestMaintenanceManager_RunsHourly(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	fake := &fakePurger{
		purgeReturnCount: 10,
		called:           make(chan struct{}, 10),
	}
	retention := int64(30 * 24 * 60 * 60) // 30 days

	m := NewMaintenanceManager(ctx, fake, log, retention, 6, WithTickInterval(50*time.Millisecond))
	defer m.Stop()

	// Wait for at least 2 calls (startup + at least one tick)
	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-fake.called:
			// Got a call
		case <-timeout:
			t.Fatalf("timeout waiting for call %d", i+1)
		}
	}

	calls := fake.getCalls()
	if len(calls) < 2 {
		t.Fatalf("expected at least 2 purge calls, got %d", len(calls))
	}

	// Verify retention was passed correctly in all calls
	for i, ret := range calls {
		if ret != retention {
			t.Errorf("call %d: expected retention %d, got %d", i, retention, ret)
		}
	}
}

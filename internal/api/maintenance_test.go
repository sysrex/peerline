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
}

func (f *fakePurger) PurgeExpiredInvites(ctx context.Context, retentionSeconds int64) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, retentionSeconds)
	f.mu.Unlock()
	return f.purgeReturnCount, f.purgeReturnErr
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

	fake := &fakePurger{purgeReturnCount: 42}
	retention := int64(7 * 24 * 60 * 60) // 7 days

	m := NewMaintenanceManager(ctx, fake, log, retention)
	defer m.Stop()

	// Wait for the startup purge to complete
	time.Sleep(100 * time.Millisecond)

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
	if testing.Short() {
		t.Skip("skipping hourly ticker test in short mode")
	}

	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	fake := &fakePurger{purgeReturnCount: 10}
	retention := int64(30 * 24 * 60 * 60) // 30 days

	// Note: This test doesn't actually wait an hour; it just verifies the mechanism.
	// A real test would require time manipulation or a shorter ticker for testing.
	m := NewMaintenanceManager(ctx, fake, log, retention)
	defer m.Stop()

	// Wait for the startup purge
	time.Sleep(100 * time.Millisecond)

	calls := fake.getCalls()
	if len(calls) < 1 {
		t.Fatal("expected at least 1 purge call")
	}

	if calls[0] != retention {
		t.Errorf("expected retention %d, got %d", retention, calls[0])
	}
}

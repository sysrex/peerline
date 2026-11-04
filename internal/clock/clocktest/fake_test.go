package clocktest_test

import (
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestFake(t *testing.T) {
	start := time.Unix(1234567890, 0)
	clk := clocktest.New(start)

	if got := clk.Now(); got != start {
		t.Errorf("Now() = %v, want %v", got, start)
	}

	clk.Advance(5 * time.Second)
	want := start.Add(5 * time.Second)
	if got := clk.Now(); got != want {
		t.Errorf("After Advance(5s): Now() = %v, want %v", got, want)
	}

	newTime := time.Unix(2000000000, 0)
	clk.Set(newTime)
	if got := clk.Now(); got != newTime {
		t.Errorf("After Set: Now() = %v, want %v", got, newTime)
	}
}

func TestFakeRaceSafe(t *testing.T) {
	clk := clocktest.New(time.Unix(1000000000, 0))
	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = clk.Now()
			}
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				clk.Advance(time.Millisecond)
			}
		}()
	}

	wg.Wait()

	// Clock should have advanced by exactly 5 * 100 = 500 milliseconds
	expected := time.Unix(1000000000, 0).Add(500 * time.Millisecond)
	if got := clk.Now(); got != expected {
		t.Errorf("After concurrent operations: Now() = %v, want %v", got, expected)
	}
}

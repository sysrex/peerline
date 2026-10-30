package api

import (
	"time"
)

// testSetClock sets the clock for all limiters in a LimiterManager (test hook).
func (lm *LimiterManager) testSetClock(clock func() time.Time) {
	for _, lim := range lm.all() {
		lim.TestSetClock(clock)
	}
}

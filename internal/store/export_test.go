package store

import "time"

// SetTestClock sets the store's clocks for testing. Must be called after Open.
// nowFunc is the int64 Unix seconds clock for DB operations.
// nowTimeFunc is the time.Time clock for Store.Now() (API/rate limiters).
func (s *Store) SetTestClock(nowFunc func() int64, nowTimeFunc func() time.Time) {
	s.now = nowFunc
	s.nowTime = nowTimeFunc
}

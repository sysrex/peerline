package store

import "time"

// OpenWithTestClock is a test helper that creates a store with custom clocks.
// nowFunc is the int64 Unix seconds clock for DB operations.
// nowTimeFunc is the time.Time clock for Store.Now() (API/rate limiters).
// This is exported so other package tests (e.g., api tests) can use it,
// but the actual clock field (OpenOptions.now) remains unexported so
// production code cannot set it.
func OpenWithTestClock(path string, nowFunc func() int64, nowTimeFunc func() time.Time) (*Store, error) {
	opts := OpenOptions{
		SkipMigrationBackup:  true,
		BackupRetentionCount: 3,
		now:                  nowFunc,
	}
	st, err := OpenWithOptions(path, opts)
	if err != nil {
		return nil, err
	}
	st.nowTime = nowTimeFunc
	return st, nil
}

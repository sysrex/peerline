// Package storetest provides test helpers for internal/store.
// This package must not be imported by cmd/ or any production code.
package storetest

import (
	"time"

	"github.com/sysrex/peerline/internal/store"
)

// OpenWithClock creates a store with a custom time source for testing.
// clock must not be nil.
func OpenWithClock(path string, clock func() time.Time) (*store.Store, error) {
	if clock == nil {
		panic("storetest.OpenWithClock: clock must not be nil")
	}
	opts := store.OpenOptions{
		SkipMigrationBackup:  true,
		BackupRetentionCount: 3,
	}
	st, err := store.OpenWithOptions(path, opts)
	if err != nil {
		return nil, err
	}
	st.SetClock(clock)
	return st, nil
}

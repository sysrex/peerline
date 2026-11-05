//go:build !unix

package store

import "log/slog"

// tightenDatabaseFilePermissions is a no-op on non-Unix systems.
func tightenDatabaseFilePermissions(dbDSN string, logger *slog.Logger) {
	// No-op on Windows and other non-Unix systems
}

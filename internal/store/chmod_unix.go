//go:build unix

package store

import (
	"log/slog"
	"os"
	"path/filepath"
)

// tightenDatabaseFilePermissions tightens permissions on the database file and
// associated -wal and -shm files if they are wider than 0600. This fixes existing
// databases created before the umask was set or manually created with wrong permissions.
//
// Only tightens permissions on regular files (not symlinks or other special files).
func tightenDatabaseFilePermissions(dbPath string, logger *slog.Logger) {
	paths := []string{
		dbPath,
		dbPath + "-wal",
		dbPath + "-shm",
	}

	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // File doesn't exist yet (e.g. -wal, -shm)
			}
			continue // Skip on error
		}

		// Only process regular files (not symlinks or other special files)
		if !info.Mode().IsRegular() {
			continue
		}

		oldMode := info.Mode().Perm()
		// Check if file is wider than 0600 (has group or other bits set)
		if oldMode&0o077 == 0 {
			continue // Already tight
		}

		// Tighten to remove group and other permissions
		newMode := oldMode &^ 0o077
		if err := os.Chmod(path, newMode); err != nil {
			continue // Skip on error
		}

		logger.Warn("tightened database file permissions", "path", filepath.Base(path), "old_mode", oldMode, "new_mode", newMode)
	}
}

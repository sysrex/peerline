//go:build unix

package store

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
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
		// Open with O_NOFOLLOW to avoid following symlinks and O_NONBLOCK to avoid blocking on FIFOs
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			if os.IsNotExist(err) {
				continue // File doesn't exist yet (e.g. -wal, -shm)
			}
			logger.Warn("failed to open database file for chmod", "path", filepath.Base(path), "error", pathless(err))
			continue
		}

		// Fstat the open fd to check file type and current mode
		info, err := f.Stat()
		if err != nil {
			f.Close()
			logger.Warn("failed to stat database file for chmod", "path", filepath.Base(path), "error", pathless(err))
			continue
		}

		// Only process regular files
		if !info.Mode().IsRegular() {
			f.Close()
			continue
		}

		oldMode := info.Mode().Perm()
		// Check if file is wider than 0600 (has group or other bits set)
		if oldMode&0o077 == 0 {
			f.Close()
			continue // Already tight
		}

		// Tighten to remove group and other permissions
		newMode := oldMode &^ 0o077
		if err := f.Chmod(newMode); err != nil {
			f.Close()
			logger.Warn("failed to tighten database file permissions", "path", filepath.Base(path), "error", pathless(err))
			continue
		}
		f.Close()

		logger.Warn("tightened database file permissions", "path", filepath.Base(path), "old_mode", oldMode, "new_mode", newMode)
	}
}

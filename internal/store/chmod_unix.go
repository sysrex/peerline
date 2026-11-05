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
// Resolves symlinks and tightens the target file race-safely (open with O_NOFOLLOW,
// fchmod the fd). This ensures databases created through symlinks get tightened.
func tightenDatabaseFilePermissions(dbDSN string, logger *slog.Logger) {
	// Parse the DSN to get the actual file path
	dbPath, isMemory, err := dbFilePath(dbDSN)
	if err != nil {
		logger.Warn("failed to parse database DSN for chmod", "error", err)
		return
	}

	// Memory databases don't need permission tightening
	if isMemory {
		return
	}

	// For symlinks, resolve to the target (EvalSymlinks returns the original path if not a symlink)
	// WAL and SHM files are created by SQLite next to the resolved database file, not next to the symlink
	resolvedPath, err := filepath.EvalSymlinks(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			// DB doesn't exist yet, nothing to tighten
			return
		}
		logger.Warn("failed to resolve database symlink for chmod", "path", filepath.Base(dbPath), "error", pathless(err))
		return
	}

	paths := []string{
		resolvedPath,
		resolvedPath + "-wal",
		resolvedPath + "-shm",
	}

	for _, path := range paths {
		// Open with O_NOFOLLOW (race-safe: refuse if path became a symlink after EvalSymlinks)
		// and O_NONBLOCK to avoid blocking on FIFOs.
		// Note: O_NOFOLLOW only protects the final component. A directory-swap race
		// (parent directory replaced with a symlink) is accepted as an edge case.
		f, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				continue // File doesn't exist yet (e.g. -wal, -shm)
			}
			logger.Warn("failed to open database file for chmod", "path", filepath.Base(path), "error", pathless(openErr))
			continue
		}

		// Fstat the open fd to check file type and current mode
		info, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			logger.Warn("failed to stat database file for chmod", "path", filepath.Base(path), "error", pathless(statErr))
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
		if chmodErr := f.Chmod(newMode); chmodErr != nil {
			f.Close()
			logger.Warn("failed to tighten database file permissions", "path", filepath.Base(path), "error", pathless(chmodErr))
			continue
		}
		f.Close()

		logger.Warn("tightened database file permissions", "path", filepath.Base(path), "old_mode", oldMode, "new_mode", newMode)
	}
}

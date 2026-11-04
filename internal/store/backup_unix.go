//go:build unix

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openBackupFileExclusive creates a new file with O_CREATE|O_EXCL|O_NOFOLLOW at mode 0600.
// Returns an error if the file exists or the path is a symlink.
func openBackupFileExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
}

// verifyBackupFileMode checks that the backup file has mode 0600 on Unix.
// On Unix systems, this verification is required for security.
func verifyBackupFileMode(finfo os.FileInfo, path string) error {
	if perm := finfo.Mode().Perm(); perm != 0600 {
		return fmt.Errorf("backup file %q has mode %04o, expected 0600", filepath.Base(path), perm)
	}
	return nil
}

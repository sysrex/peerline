//go:build unix

package store

import (
	"os"
	"syscall"
)

// openBackupFileExclusive creates a new file with O_CREATE|O_EXCL|O_NOFOLLOW at mode 0600.
// Returns an error if the file exists or the path is a symlink.
func openBackupFileExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
}

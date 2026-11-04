//go:build !unix

package store

import "os"

// openBackupFileExclusive creates a new file with O_CREATE|O_EXCL at mode 0600.
// On non-Unix platforms, O_NOFOLLOW is not available.
func openBackupFileExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

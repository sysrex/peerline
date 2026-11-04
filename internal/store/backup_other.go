//go:build !unix

package store

import "os"

// openBackupFileExclusive creates a new file with O_CREATE|O_EXCL at mode 0600.
// On non-Unix platforms, O_NOFOLLOW is not available.
func openBackupFileExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

// verifyBackupFileMode is a no-op on non-Unix platforms.
// On Windows, Go reports 0666 or 0444 even when the file is created with mode 0600,
// so mode verification would incorrectly fail.
func verifyBackupFileMode(finfo os.FileInfo, path string) error {
	return nil
}

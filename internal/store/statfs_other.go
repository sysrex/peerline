//go:build !linux && !darwin

package store

// availableDiskSpace returns (0, false, nil) on unsupported platforms.
// The caller will skip the disk space check.
func availableDiskSpace(path string) (uint64, bool, error) {
	return 0, false, nil
}

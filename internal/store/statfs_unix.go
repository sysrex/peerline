//go:build linux || darwin

package store

import "golang.org/x/sys/unix"

// availableDiskSpace returns the available disk space in bytes for the given path.
// Returns (avail, true, nil) on success.
// Returns (0, true, nil) when disk is full (avail == 0 is a real failure).
// Returns (0, false, err) when statfs fails.
func availableDiskSpace(path string) (uint64, bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, false, err
	}
	// Available blocks * block size = available bytes
	// Bavail is uint64 on Linux/Darwin, but may need type conversion on BSD
	avail := uint64(stat.Bavail) * uint64(stat.Bsize)
	return avail, true, nil
}

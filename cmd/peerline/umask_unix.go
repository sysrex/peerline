//go:build unix

package main

import "syscall"

// setRestrictiveUmask sets umask to 0077, ensuring all files created by
// this process (database, WAL, SHM, backups) are created with mode 0600 or 0700.
// This prevents other local users from reading the database in a 0755 data directory.
//
// This is process-wide and affects all file creation in this process.
func setRestrictiveUmask() {
	syscall.Umask(0o077)
}

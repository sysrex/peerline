//go:build !unix

package main

// setRestrictiveUmask is a no-op on non-Unix platforms.
// On Windows, file permissions are handled differently via ACLs.
func setRestrictiveUmask() {
	// No-op: Windows uses ACLs instead of Unix permission bits
}

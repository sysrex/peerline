//go:build !unix

package store

import "io/fs"

func ownedByCurrentUser(fs.FileInfo) bool { return true }

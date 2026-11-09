//go:build unix

package store

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

type uidInfo struct {
	uid uint32
	sys any
}

func (uidInfo) Name() string       { return "backup" }
func (uidInfo) Size() int64        { return 1 }
func (uidInfo) Mode() fs.FileMode  { return 0o600 }
func (uidInfo) ModTime() time.Time { return time.Time{} }
func (uidInfo) IsDir() bool        { return false }
func (u uidInfo) Sys() any {
	if u.sys != nil {
		return u.sys
	}
	return &syscall.Stat_t{Uid: u.uid}
}

func TestOwnedByCurrentUser(t *testing.T) {
	me := uint32(os.Geteuid())
	if !ownedByCurrentUser(uidInfo{uid: me}) {
		t.Fatal("file owned by the current euid was rejected")
	}
	other := me + 1
	if ownedByCurrentUser(uidInfo{uid: other}) {
		t.Fatalf("file owned by uid %d was accepted", other)
	}
	// A stat result we cannot read is not treated as a foreign owner.
	if !ownedByCurrentUser(uidInfo{sys: "not a stat"}) {
		t.Fatal("non-Stat_t info should not be rejected")
	}
}

package mem

import (
	"testing"

	"github.com/sysrex/peerline/internal/audit"
	"github.com/sysrex/peerline/internal/audit/conform"
)

func TestConformance(t *testing.T) {
	var now int64 = 100
	conform.LogStore(t, func() audit.LogStore {
		return New(func() int64 { return now })
	})
}

package mem

import (
	"testing"

	"github.com/sysrex/peerline/internal/a2a"
	"github.com/sysrex/peerline/internal/a2a/conform"
)

func TestConformance(t *testing.T) {
	conform.TaskStore(t, func() a2a.TaskStore { return New() })
}

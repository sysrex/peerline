package mem

import (
	"testing"

	"github.com/sysrex/peerline/internal/anchor"
	"github.com/sysrex/peerline/internal/anchor/conform"
)

func TestConformance(t *testing.T) {
	conform.Outbox(t, func() anchor.Outbox { return New() })
}

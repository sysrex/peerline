package mem

import (
	"testing"

	"github.com/sysrex/peerline/internal/webhook"
	"github.com/sysrex/peerline/internal/webhook/conform"
)

func TestConformance(t *testing.T) {
	conform.Outbox(t, func() webhook.Outbox { return New() })
}

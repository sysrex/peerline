package webhook

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestDeliveryLogOmitsBodyAndSecret(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	body := `{"secret":"whsec_SHOULD_NOT_APPEAR","text":"payload-body"}`
	LogFailure(log, "msg_1", 500)
	out := buf.String()
	if strings.Contains(out, body) || strings.Contains(out, "whsec_") || strings.Contains(out, "payload-body") {
		t.Fatalf("delivery log leaked content: %s", out)
	}
	if !strings.Contains(out, "msg_1") || !strings.Contains(out, "500") {
		t.Fatalf("log missing id or status: %s", out)
	}
}

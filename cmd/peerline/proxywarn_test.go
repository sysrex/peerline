package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestWarnTrustedProxies(t *testing.T) {
	tests := []struct {
		name       string
		rawValue   string
		wantWarn   bool
		wantSubstr string
	}{
		{
			name:       "unset (empty string)",
			rawValue:   "",
			wantWarn:   true,
			wantSubstr: "PEERLINE_TRUSTED_PROXIES unset",
		},
		{
			name:     "set with single IP",
			rawValue: "192.0.2.1",
			wantWarn: false,
		},
		{
			name:     "set with CIDR",
			rawValue: "192.0.2.0/24",
			wantWarn: false,
		},
		{
			name:     "set with multiple values",
			rawValue: "192.0.2.1,192.0.2.2",
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

			warnTrustedProxies(log, tt.rawValue)

			output := buf.String()

			if tt.wantWarn {
				if !strings.Contains(output, tt.wantSubstr) {
					t.Errorf("expected warning with %q, got: %s", tt.wantSubstr, output)
				}
			} else {
				if output != "" {
					t.Errorf("expected no warning, got: %s", output)
				}
			}
		})
	}
}

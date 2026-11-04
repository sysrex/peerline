package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
)

func TestParseNonNegativeInt(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"5", 5, false},
		{"-1", 0, true},
		{"1OO", 0, true}, // capital O instead of zero
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := parseNonNegativeInt(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseNonNegativeInt(%q) = %d, nil; want error", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseNonNegativeInt(%q) = %d, %v; want %d, nil", tt.input, got, err, tt.want)
			} else if got != tt.want {
				t.Errorf("parseNonNegativeInt(%q) = %d; want %d", tt.input, got, tt.want)
			}
		}
	}
}

func TestParseNonNegativeInt64(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"5", 5, false},
		{"-1", 0, true},
		{"1OO", 0, true}, // capital O instead of zero
		{"abc", 0, true},
	}

	for _, tt := range tests {
		got, err := parseNonNegativeInt64(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseNonNegativeInt64(%q) = %d, nil; want error", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseNonNegativeInt64(%q) = %d, %v; want %d, nil", tt.input, got, err, tt.want)
			} else if got != tt.want {
				t.Errorf("parseNonNegativeInt64(%q) = %d; want %d", tt.input, got, tt.want)
			}
		}
	}
}

func TestParseBagLimits(t *testing.T) {
	tests := []struct {
		name        string
		bagsStr     string
		bytesStr    string
		wantBags    int
		wantBytes   int64
		wantErr     bool
		errContains string
	}{
		{"both valid", "100", "1048576", 100, 1048576, false, ""},
		{"both empty", "", "", 0, 0, false, ""},
		{"bags invalid", "abc", "100", 0, 0, true, "MAX_BAGS_PER_PEER"},
		{"bytes invalid", "100", "xyz", 0, 0, true, "MAX_BAG_BYTES_PER_PEER"},
		{"bags negative", "-5", "100", 0, 0, true, "MAX_BAGS_PER_PEER"},
		{"bytes negative", "100", "-1", 0, 0, true, "MAX_BAG_BYTES_PER_PEER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBags, gotBytes, err := parseBagLimits(tt.bagsStr, tt.bytesStr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBagLimits(%q, %q) = (%d, %d, nil); want error containing %q",
						tt.bagsStr, tt.bytesStr, gotBags, gotBytes, tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseBagLimits(%q, %q) error = %v; want error containing %q",
						tt.bagsStr, tt.bytesStr, err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("parseBagLimits(%q, %q) = (%d, %d, %v); want (%d, %d, nil)",
						tt.bagsStr, tt.bytesStr, gotBags, gotBytes, err, tt.wantBags, tt.wantBytes)
				} else if gotBags != tt.wantBags || gotBytes != tt.wantBytes {
					t.Errorf("parseBagLimits(%q, %q) = (%d, %d); want (%d, %d)",
						tt.bagsStr, tt.bytesStr, gotBags, gotBytes, tt.wantBags, tt.wantBytes)
				}
			}
		})
	}
}

func TestParseVersionDetail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"minimal lowercase", "minimal", "minimal", false},
		{"full lowercase", "full", "full", false},
		{"off lowercase", "off", "off", false},
		{"minimal uppercase", "MINIMAL", "minimal", false},
		{"full mixed case", "Full", "full", false},
		{"off uppercase", "OFF", "off", false},
		{"with whitespace", "  minimal  ", "minimal", false},
		{"invalid value", "invalid", "", true},
		{"empty string", "", "", true},
		{"partial match", "min", "", true},
		{"typo", "ful", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVersionDetail(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseVersionDetail(%q) = %q, nil; want error", tt.input, got)
				}
			} else {
				if err != nil {
					t.Errorf("parseVersionDetail(%q) = %q, %v; want %q, nil", tt.input, got, err, tt.want)
				} else if got != tt.want {
					t.Errorf("parseVersionDetail(%q) = %q; want %q", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestParseBoolStrict(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{"empty string", "", false, false},
		{"0", "0", false, false},
		{"false lowercase", "false", false, false},
		{"false uppercase", "FALSE", false, false},
		{"false mixed case", "False", false, false},
		{"1", "1", true, false},
		{"true lowercase", "true", true, false},
		{"true uppercase", "TRUE", true, false},
		{"true mixed case", "True", true, false},
		{"with whitespace 0", "  0  ", false, false},
		{"with whitespace 1", "  1  ", true, false},
		{"with whitespace true", "  true  ", true, false},
		{"invalid yes", "yes", false, true},
		{"invalid no", "no", false, true},
		{"invalid on", "on", false, true},
		{"invalid off", "off", false, true},
		{"invalid 2", "2", false, true},
		{"invalid t", "t", false, true},
		{"invalid f", "f", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBoolStrict(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBoolStrict(%q) = %v, nil; want error", tt.input, got)
				}
			} else {
				if err != nil {
					t.Errorf("parseBoolStrict(%q) = %v, %v; want %v, nil", tt.input, got, err, tt.want)
				} else if got != tt.want {
					t.Errorf("parseBoolStrict(%q) = %v; want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestDescribeTLSMode(t *testing.T) {
	tests := []struct {
		name string
		smtp *mailer.SMTP
		want string
	}{
		{
			name: "implicit TLS (port 465)",
			smtp: &mailer.SMTP{
				Host:        "mail.example.com",
				Port:        465,
				ImplicitTLS: true,
			},
			want: "implicit TLS (port 465)",
		},
		{
			name: "STARTTLS optional (plaintext allowed)",
			smtp: &mailer.SMTP{
				Host:           "localhost",
				Port:           587,
				AllowPlaintext: true,
			},
			want: "STARTTLS optional (plaintext allowed)",
		},
		{
			name: "STARTTLS required",
			smtp: &mailer.SMTP{
				Host:           "mail.example.com",
				Port:           587,
				AllowPlaintext: false,
			},
			want: "STARTTLS required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeTLSMode(tt.smtp); got != tt.want {
				t.Errorf("describeTLSMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSMTPProbeAction(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantFatal bool
		wantLevel slog.Level
		wantMsg   string
	}{
		{
			name:      "nil error = no action",
			err:       nil,
			wantFatal: false,
			wantLevel: slog.LevelInfo,
			wantMsg:   "",
		},
		{
			name:      "ErrRelayUnreachable = warn, not fatal",
			err:       mailer.ErrRelayUnreachable,
			wantFatal: false,
			wantLevel: slog.LevelWarn,
			wantMsg:   "smtp relay unreachable at startup (will retry on send)",
		},
		{
			name:      "wrapped ErrRelayUnreachable = warn, not fatal",
			err:       fmt.Errorf("context: %w", mailer.ErrRelayUnreachable),
			wantFatal: false,
			wantLevel: slog.LevelWarn,
			wantMsg:   "smtp relay unreachable at startup (will retry on send)",
		},
		{
			name:      "TLS error = fatal",
			err:       errors.New("x509: certificate signed by unknown authority"),
			wantFatal: true,
			wantLevel: slog.LevelError,
			wantMsg:   "smtp probe failed: configuration error",
		},
		{
			name:      "other error = fatal",
			err:       errors.New("something else"),
			wantFatal: true,
			wantLevel: slog.LevelError,
			wantMsg:   "smtp probe failed: configuration error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFatal, gotLevel, gotMsg := smtpProbeAction(tt.err)
			if gotFatal != tt.wantFatal {
				t.Errorf("fatal = %v, want %v", gotFatal, tt.wantFatal)
			}
			if gotLevel != tt.wantLevel {
				t.Errorf("level = %v, want %v", gotLevel, tt.wantLevel)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("msg = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

func TestTrustedProxyConfig(t *testing.T) {
	tests := []struct {
		name           string
		proxiesEnv     string
		allowBroadEnv  string
		wantProxies    []string
		wantAllowBroad bool
		wantErr        bool
	}{
		{
			name:           "both set with opt-in enabled",
			proxiesEnv:     "10.0.0.0/8,192.168.0.0/16",
			allowBroadEnv:  "1",
			wantProxies:    []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantAllowBroad: true,
		},
		{
			name:           "proxies set, opt-in disabled",
			proxiesEnv:     "10.0.0.0/8",
			allowBroadEnv:  "0",
			wantProxies:    []string{"10.0.0.0/8"},
			wantAllowBroad: false,
		},
		{
			name:           "proxies unset, opt-in enabled",
			proxiesEnv:     "",
			allowBroadEnv:  "true",
			wantProxies:    nil,
			wantAllowBroad: true,
		},
		{
			name:           "both unset",
			proxiesEnv:     "",
			allowBroadEnv:  "",
			wantProxies:    nil,
			wantAllowBroad: false,
		},
		{
			name:          "invalid opt-in value",
			proxiesEnv:    "10.0.0.0/8",
			allowBroadEnv: "yes",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				switch key {
				case "PEERLINE_TRUSTED_PROXIES":
					return tt.proxiesEnv
				case "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD":
					return tt.allowBroadEnv
				default:
					return ""
				}
			}

			proxies, allowBroad, err := trustedProxyConfig(getenv)
			if tt.wantErr {
				if err == nil {
					t.Errorf("trustedProxyConfig() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("trustedProxyConfig() error = %v, want nil", err)
			}
			if allowBroad != tt.wantAllowBroad {
				t.Errorf("allowBroad = %v, want %v", allowBroad, tt.wantAllowBroad)
			}
			if !equalStringSlices(proxies, tt.wantProxies) {
				t.Errorf("proxies = %v, want %v", proxies, tt.wantProxies)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWarnTrustedProxyStartup(t *testing.T) {
	tests := []struct {
		name           string
		allowBroad     bool
		trustedProxies []string
		proxiesEnv     string
		wantWarnCount  int
		wantMessage    string
		wantLevel      slog.Level
	}{
		{
			name:           "opt-in enabled without proxies env",
			allowBroad:     true,
			trustedProxies: nil,
			proxiesEnv:     "",
			wantWarnCount:  1,
			wantMessage:    "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled but PEERLINE_TRUSTED_PROXIES is unset; the opt-in has no effect",
			wantLevel:      slog.LevelWarn,
		},
		{
			name:           "opt-in enabled with proxies",
			allowBroad:     true,
			trustedProxies: []string{"10.0.0.0/8"},
			proxiesEnv:     "10.0.0.0/8",
			wantWarnCount:  0,
		},
		{
			name:           "opt-in disabled without proxies",
			allowBroad:     false,
			trustedProxies: nil,
			proxiesEnv:     "",
			wantWarnCount:  0,
		},
		{
			name:           "opt-in disabled with proxies",
			allowBroad:     false,
			trustedProxies: []string{"10.0.0.0/8"},
			proxiesEnv:     "10.0.0.0/8",
			wantWarnCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			warnTrustedProxyStartup(log, tt.allowBroad, tt.trustedProxies, tt.proxiesEnv)
			output := buf.String()

			// Count warnings
			warnCount := strings.Count(output, "level=WARN")
			if warnCount != tt.wantWarnCount {
				t.Errorf("got %d warnings, want %d; output: %q", warnCount, tt.wantWarnCount, output)
			}

			// Check specific message and level if warning expected
			if tt.wantWarnCount > 0 {
				if !strings.Contains(output, tt.wantMessage) {
					t.Errorf("output missing expected message %q; got: %q", tt.wantMessage, output)
				}
				if !strings.Contains(output, "level=WARN") {
					t.Errorf("output missing level=WARN; got: %q", output)
				}
			}
		})
	}
}

func TestAllowBroadIPv6ConfigWiring(t *testing.T) {
	tests := []struct {
		name           string
		proxiesEnv     string
		allowBroadEnv  string
		wantAllowBroad bool
		testProxy      string
		wantAccepted   bool
	}{
		{"enabled with 1", "2a06:98c0::/29", "1", true, "2a06:98c0::/29", true},
		{"enabled with true", "2a06:98c0::/29", "true", true, "2a06:98c0::/29", true},
		{"disabled with 0", "2a06:98c0::/29", "0", false, "2a06:98c0::/29", false},
		{"disabled with false", "2a06:98c0::/29", "false", false, "2a06:98c0::/29", false},
		{"disabled when unset", "2a06:98c0::/29", "", false, "2a06:98c0::/29", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				switch key {
				case "PEERLINE_TRUSTED_PROXIES":
					return tt.proxiesEnv
				case "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD":
					return tt.allowBroadEnv
				default:
					return ""
				}
			}

			proxies, allowBroad, err := trustedProxyConfig(getenv)
			if err != nil {
				t.Fatalf("trustedProxyConfig failed: %v", err)
			}

			if allowBroad != tt.wantAllowBroad {
				t.Errorf("allowBroad = %v, want %v", allowBroad, tt.wantAllowBroad)
			}

			// Verify the config wires through to api.Config and affects parsing
			st, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}

			var logBuf bytes.Buffer
			cfg := api.Config{
				TrustedProxies: proxies,
				AllowBroadIPv6: allowBroad,
				Logger:         slog.New(slog.NewTextHandler(&logBuf, nil)),
			}
			srv, err := api.New(st, cfg)
			accepted := (err == nil)
			if accepted != tt.wantAccepted {
				if accepted {
					t.Errorf("api.New succeeded with allowBroad=%v, want failure (shows %s was accepted, but shouldn't be)", allowBroad, tt.testProxy)
				} else {
					t.Errorf("api.New failed with allowBroad=%v: %v (shows %s was rejected, but should be accepted)", allowBroad, err, tt.testProxy)
				}
			}
			if srv != nil {
				defer srv.Stop()
			}
		})
	}
}

func TestDescribeSMTPMode(t *testing.T) {
	tests := []struct {
		name      string
		smtp      *mailer.SMTP
		wantLevel slog.Level
		wantMsg   string
	}{
		{
			name: "loopback with plaintext = INFO",
			smtp: &mailer.SMTP{
				Host:           "localhost",
				Port:           587,
				AllowPlaintext: true,
				Timeout:        10 * time.Second,
			},
			wantLevel: slog.LevelInfo,
			wantMsg:   "SMTP configured",
		},
		{
			name: "non-loopback with STARTTLS required = INFO",
			smtp: &mailer.SMTP{
				Host:           "mail.example.com",
				Port:           587,
				AllowPlaintext: false,
				Timeout:        10 * time.Second,
			},
			wantLevel: slog.LevelInfo,
			wantMsg:   "SMTP configured",
		},
		{
			name: "non-loopback with plaintext allowed = WARN",
			smtp: &mailer.SMTP{
				Host:           "192.168.1.1",
				Port:           587,
				AllowPlaintext: true,
				Timeout:        10 * time.Second,
			},
			wantLevel: slog.LevelWarn,
			wantMsg:   "SMTP configured with plaintext allowed to non-loopback relay; invite codes and message previews are not protected in transit",
		},
		{
			name: "port 465 implicit TLS = INFO",
			smtp: &mailer.SMTP{
				Host:        "mail.example.com",
				Port:        465,
				ImplicitTLS: true,
				Timeout:     10 * time.Second,
			},
			wantLevel: slog.LevelInfo,
			wantMsg:   "SMTP configured",
		},
		{
			name: "port 465 with AllowPlaintext on non-loopback = INFO (no spurious warn)",
			smtp: &mailer.SMTP{
				Host:           "mail.example.com",
				Port:           465,
				ImplicitTLS:    true,
				AllowPlaintext: true,
				Timeout:        10 * time.Second,
			},
			wantLevel: slog.LevelInfo,
			wantMsg:   "SMTP configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevel, gotMsg := describeSMTPMode(tt.smtp)
			if gotLevel != tt.wantLevel {
				t.Errorf("describeSMTPMode() level = %v, want %v", gotLevel, tt.wantLevel)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("describeSMTPMode() msg = %q, want %q", gotMsg, tt.wantMsg)
			}
		})
	}
}

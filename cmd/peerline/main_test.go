package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/clock"
	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
)

// testMailerStub is a no-op mailer for testing config wiring.
type testMailerStub struct{}

func (testMailerStub) Send(ctx context.Context, m mailer.Message) error { return nil }
func (testMailerStub) Mode() string                                     { return "test" }

func TestParseNonNegativeInt(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		varName     string
		max         int
		want        int
		wantErr     bool
		errContains []string // must all be present in error message
	}{
		{"empty string", "", "TEST_VAR", 0, 0, false, nil},
		{"zero", "0", "TEST_VAR", 0, 0, false, nil},
		{"valid positive", "10", "TEST_VAR", 0, 10, false, nil},
		{"valid large", "1000000", "TEST_VAR", 0, 1000000, false, nil},
		{"negative", "-5", "TEST_VAR", 0, 0, true, []string{"TEST_VAR", "-5", "non-negative"}},
		{"non-numeric", "abc", "TEST_VAR", 0, 0, true, []string{"TEST_VAR", "abc", "numeric"}},
		{"typo O for 0", "1O", "TEST_VAR", 0, 0, true, []string{"TEST_VAR", "1O", "numeric"}},
		{"within max", "100", "TEST_VAR", 200, 100, false, nil},
		{"at max", "200", "TEST_VAR", 200, 200, false, nil},
		{"exceeds max", "201", "TEST_VAR", 200, 0, true, []string{"TEST_VAR", "201", "200"}},
		{"huge overflow", "999999999999999999999", "TEST_VAR", 0, 0, true, []string{"TEST_VAR", "999999999999999999999", "out of range"}},
		{"leading space rejected", " 5", "TEST_VAR", 0, 0, true, []string{"TEST_VAR", " 5", "numeric"}},
		{"explicit plus accepted", "+5", "TEST_VAR", 0, 5, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNonNegativeInt(tt.input, tt.varName, tt.max)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseNonNegativeInt(%q, %q, %d) = %d, nil; want error", tt.input, tt.varName, tt.max, got)
				} else {
					errStr := err.Error()
					for _, substr := range tt.errContains {
						if !strings.Contains(errStr, substr) {
							t.Errorf("parseNonNegativeInt(%q, %q, %d) error = %q; want it to contain %q", tt.input, tt.varName, tt.max, errStr, substr)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("parseNonNegativeInt(%q, %q, %d) = %d, %v; want %d, nil", tt.input, tt.varName, tt.max, got, err, tt.want)
				} else if got != tt.want {
					t.Errorf("parseNonNegativeInt(%q, %q, %d) = %d; want %d", tt.input, tt.varName, tt.max, got, tt.want)
				}
			}
		})
	}
}

// TestParseStartupLimits verifies that parseStartupLimits correctly parses and validates
// PEERLINE_KEY_INDEX_WARN and PEERLINE_RETENTION_DAYS.
func TestParseStartupLimits(t *testing.T) {
	tests := []struct {
		name              string
		keyIndexWarn      string
		retentionDays     string
		wantKeyIndexWarn  int
		wantRetentionDays int
		wantErr           bool
		errContains       []string // must all be present in error message
	}{
		{
			name:              "both valid",
			keyIndexWarn:      "500000",
			retentionDays:     "90",
			wantKeyIndexWarn:  500000,
			wantRetentionDays: 90,
			wantErr:           false,
		},
		{
			name:              "both unset",
			keyIndexWarn:      "",
			retentionDays:     "",
			wantKeyIndexWarn:  0,
			wantRetentionDays: 0,
			wantErr:           false,
		},
		{
			name:              "both zero (defaults)",
			keyIndexWarn:      "0",
			retentionDays:     "0",
			wantKeyIndexWarn:  0,
			wantRetentionDays: 0,
			wantErr:           false,
		},
		{
			name:          "KEY_INDEX_WARN non-numeric",
			keyIndexWarn:  "abc",
			retentionDays: "30",
			wantErr:       true,
			errContains:   []string{"PEERLINE_KEY_INDEX_WARN", "abc", "numeric"},
		},
		{
			name:          "KEY_INDEX_WARN typo",
			keyIndexWarn:  "1OOO",
			retentionDays: "30",
			wantErr:       true,
			errContains:   []string{"PEERLINE_KEY_INDEX_WARN", "1OOO", "numeric"},
		},
		{
			name:          "KEY_INDEX_WARN negative",
			keyIndexWarn:  "-100",
			retentionDays: "30",
			wantErr:       true,
			errContains:   []string{"PEERLINE_KEY_INDEX_WARN", "-100", "non-negative"},
		},
		{
			name:          "RETENTION_DAYS non-numeric",
			keyIndexWarn:  "1000000",
			retentionDays: "xyz",
			wantErr:       true,
			errContains:   []string{"PEERLINE_RETENTION_DAYS", "xyz", "numeric"},
		},
		{
			name:          "RETENTION_DAYS typo",
			keyIndexWarn:  "1000000",
			retentionDays: "3O",
			wantErr:       true,
			errContains:   []string{"PEERLINE_RETENTION_DAYS", "3O", "numeric"},
		},
		{
			name:          "RETENTION_DAYS negative",
			keyIndexWarn:  "1000000",
			retentionDays: "-7",
			wantErr:       true,
			errContains:   []string{"PEERLINE_RETENTION_DAYS", "-7", "non-negative"},
		},
		{
			name:          "RETENTION_DAYS exceeds max",
			keyIndexWarn:  "1000000",
			retentionDays: "50000",
			wantErr:       true,
			errContains:   []string{"PEERLINE_RETENTION_DAYS", "50000", "36500"},
		},
		{
			name:              "RETENTION_DAYS at max",
			keyIndexWarn:      "1000000",
			retentionDays:     "36500",
			wantKeyIndexWarn:  1000000,
			wantRetentionDays: 36500,
			wantErr:           false,
		},
		{
			name:          "RETENTION_DAYS at max+1",
			keyIndexWarn:  "1000000",
			retentionDays: "36501",
			wantErr:       true,
			errContains:   []string{"PEERLINE_RETENTION_DAYS", "36501", "36500"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				switch key {
				case "PEERLINE_KEY_INDEX_WARN":
					return tt.keyIndexWarn
				case "PEERLINE_RETENTION_DAYS":
					return tt.retentionDays
				}
				return ""
			}

			gotKeyIndexWarn, gotRetentionDays, err := parseStartupLimits(getenv)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseStartupLimits() succeeded with (%d, %d), want error", gotKeyIndexWarn, gotRetentionDays)
				} else {
					errStr := err.Error()
					for _, substr := range tt.errContains {
						if !strings.Contains(errStr, substr) {
							t.Errorf("parseStartupLimits() error = %q; want it to contain %q", errStr, substr)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("parseStartupLimits() error = %v, want nil", err)
				} else {
					if gotKeyIndexWarn != tt.wantKeyIndexWarn {
						t.Errorf("parseStartupLimits() keyIndexWarn = %d; want %d", gotKeyIndexWarn, tt.wantKeyIndexWarn)
					}
					if gotRetentionDays != tt.wantRetentionDays {
						t.Errorf("parseStartupLimits() retentionDays = %d; want %d", gotRetentionDays, tt.wantRetentionDays)
					}
				}
			}
		})
	}
}

func TestValidateStartupEnv(t *testing.T) {
	t.Run("empty is valid", func(t *testing.T) {
		if err := validateStartupEnv(func(string) string { return "" }); err != nil {
			t.Fatalf("validateStartupEnv(empty) = %v", err)
		}
	})
	t.Run("bad retention names the variable", func(t *testing.T) {
		err := validateStartupEnv(func(key string) string {
			if key == "PEERLINE_RETENTION_DAYS" {
				return "3O"
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "PEERLINE_RETENTION_DAYS") || !strings.Contains(err.Error(), "3O") {
			t.Fatalf("validateStartupEnv() = %v, want error naming PEERLINE_RETENTION_DAYS and 3O", err)
		}
	})
	t.Run("bad email limit names the variable", func(t *testing.T) {
		err := validateStartupEnv(func(key string) string {
			if key == "PEERLINE_EMAIL_PER_HOUR" {
				return "-1"
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "PEERLINE_EMAIL_PER_HOUR") || !strings.Contains(err.Error(), "-1") {
			t.Fatalf("validateStartupEnv() = %v, want error naming PEERLINE_EMAIL_PER_HOUR and -1", err)
		}
	})
	t.Run("rebuild hours above cap", func(t *testing.T) {
		err := validateStartupEnv(func(key string) string {
			if key == "PEERLINE_KEY_INDEX_REBUILD_HOURS" {
				return "8761"
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "PEERLINE_KEY_INDEX_REBUILD_HOURS") || !strings.Contains(err.Error(), "8761") {
			t.Fatalf("validateStartupEnv() = %v, want error for 8761", err)
		}
	})
}

func TestRetentionSecondsFromDays(t *testing.T) {
	// 36500 is the documented cap and is above MaxInt32/86400 (24855).
	// The result must be the full int64 product, never a wrapped int.
	const days = 36500
	const want = int64(days) * 24 * 60 * 60
	if got := retentionSecondsFromDays(days); got != want || got <= 0 {
		t.Fatalf("retentionSecondsFromDays(%d) = %d, want %d", days, got, want)
	}
	if got := retentionSecondsFromDays(0); got != 0 {
		t.Fatalf("retentionSecondsFromDays(0) = %d, want 0", got)
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

// captureHandler is a slog.Handler that captures all log records for test inspection.
type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *captureHandler) WithGroup(string) slog.Handler {
	return h
}

// TestBuildTrustedProxySettings verifies that buildTrustedProxySettings parses
// the proxy environment variables exactly once and emits warnings correctly.
func TestBuildTrustedProxySettings(t *testing.T) {
	tests := []struct {
		name           string
		proxiesEnv     string
		allowBroadEnv  string
		wantProxies    []string
		wantAllowBroad bool
		wantWarnCount  int
		wantWarnMsg    string
		wantErr        bool
	}{
		{
			name:           "opt-in enabled without proxies warns once",
			proxiesEnv:     "",
			allowBroadEnv:  "1",
			wantProxies:    nil,
			wantAllowBroad: true,
			wantWarnCount:  1,
			wantWarnMsg:    "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled but PEERLINE_TRUSTED_PROXIES is unset; the opt-in has no effect",
		},
		{
			name:           "proxies with opt-in enabled",
			proxiesEnv:     "10.0.0.0/8,192.168.0.0/16",
			allowBroadEnv:  "1",
			wantProxies:    []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantAllowBroad: true,
			wantWarnCount:  0,
		},
		{
			name:           "proxies with opt-in true",
			proxiesEnv:     "127.0.0.0/8",
			allowBroadEnv:  "true",
			wantProxies:    []string{"127.0.0.0/8"},
			wantAllowBroad: true,
			wantWarnCount:  0,
		},
		{
			name:           "proxies with opt-in disabled",
			proxiesEnv:     "127.0.0.0/8",
			allowBroadEnv:  "0",
			wantProxies:    []string{"127.0.0.0/8"},
			wantAllowBroad: false,
			wantWarnCount:  0,
		},
		{
			name:           "proxies with opt-in false",
			proxiesEnv:     "192.168.0.0/16",
			allowBroadEnv:  "false",
			wantProxies:    []string{"192.168.0.0/16"},
			wantAllowBroad: false,
			wantWarnCount:  0,
		},
		{
			name:          "invalid opt-in value",
			proxiesEnv:    "127.0.0.0/8",
			allowBroadEnv: "yes",
			wantErr:       true,
		},
		{
			name:           "both unset no warn",
			proxiesEnv:     "",
			allowBroadEnv:  "",
			wantProxies:    nil,
			wantAllowBroad: false,
			wantWarnCount:  0,
		},
		{
			name:           "no proxies with opt-in false no warn",
			proxiesEnv:     "",
			allowBroadEnv:  "false",
			wantProxies:    nil,
			wantAllowBroad: false,
			wantWarnCount:  0,
		},
		{
			name:          "bad CIDR",
			proxiesEnv:    "not-a-cidr",
			allowBroadEnv: "0",
			wantErr:       true,
		},
		{
			name:          "broad CIDR without opt-in",
			proxiesEnv:    "2a06:98c0::/29",
			allowBroadEnv: "0",
			wantErr:       true,
		},
		{
			name:           "broad CIDR with opt-in accepted",
			proxiesEnv:     "2a06:98c0::/29",
			allowBroadEnv:  "1",
			wantProxies:    []string{"2a06:98c0::/29"},
			wantAllowBroad: true,
			wantWarnCount:  0,
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

			h := &captureHandler{}
			log := slog.New(h)
			proxies, allowBroad, err := buildTrustedProxySettings(getenv, log)
			if tt.wantErr {
				if err == nil {
					t.Errorf("buildTrustedProxySettings() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildTrustedProxySettings() error = %v, want nil", err)
			}
			if allowBroad != tt.wantAllowBroad {
				t.Errorf("allowBroad = %v, want %v", allowBroad, tt.wantAllowBroad)
			}
			if !equalStringSlices(proxies, tt.wantProxies) {
				t.Errorf("proxies = %v, want %v", proxies, tt.wantProxies)
			}

			// Check warning count
			warnCount := 0
			for _, r := range h.records {
				if r.Level == slog.LevelWarn {
					warnCount++
					if tt.wantWarnMsg != "" && r.Message != tt.wantWarnMsg {
						t.Errorf("warning message = %q, want %q", r.Message, tt.wantWarnMsg)
					}
				}
			}
			if warnCount != tt.wantWarnCount {
				t.Errorf("got %d warnings, want %d", warnCount, tt.wantWarnCount)
			}
		})
	}
}

// TestBuildAPIConfig verifies that buildAPIConfig returns the exact config
// main() passes to api.New, with no field assignments in between.
func TestBuildAPIConfig(t *testing.T) {
	// Tripwire: if api.Config's field count changes, update this test.
	// buildAPIConfig sets 20 fields; MsgPerMinute, MsgBurst, EmailBurst,
	// EmailRcptPerHour, and NotifyBurst are defaulted in api.New.
	if got, want := reflect.TypeOf(api.Config{}).NumField(), 25; got != want {
		t.Fatalf("api.Config has %d fields, expected %d; update TestBuildAPIConfig expected configs", got, want)
	}

	testClock := clocktest.New(time.Unix(1234567890, 0))
	testMailer := &testMailerStub{}
	testLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name               string
		envVars            map[string]string
		trustedProxies     []string
		allowBroadIPv6     bool
		clock              clock.Clock
		mailer             mailer.Sender
		logger             *slog.Logger
		versionDetail      string
		publicURL          string
		maxBagsPerPeer     int
		maxBagBytesPerPeer int64
		retentionSeconds   int64
		want               api.Config
		wantBuildErr       bool
		wantBuildErrSubstr []string // must all be present in buildAPIConfig error
		wantNewErr         bool
		wantNewErrContains string
	}{
		{
			name: "all fields set",
			envVars: map[string]string{
				"PEERLINE_REGISTER_TOKEN":          "test_reg_token_abc123",
				"PEERLINE_CODE_PEPPER":             "test_pepper_xyz789",
				"PEERLINE_EMAIL_PER_HOUR":          "50",
				"PEERLINE_NOTIFY_PER_HOUR":         "30",
				"PEERLINE_MAX_OUTSTANDING_INVITES": "15",
				"PEERLINE_AUTH_FAIL_PER_MINUTE":    "20",
				"PEERLINE_AUTH_FAIL_BURST":         "8",
				"PEERLINE_WRITE_PER_MINUTE":        "15",
				"PEERLINE_WRITE_BURST":             "5",
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "12",
			},
			trustedProxies:     []string{"10.0.0.0/8"},
			allowBroadIPv6:     true,
			clock:              testClock,
			mailer:             testMailer,
			logger:             testLogger,
			versionDetail:      "full",
			publicURL:          "https://test.example.com",
			maxBagsPerPeer:     200,
			maxBagBytesPerPeer: 2097152,
			retentionSeconds:   5184000,
			want: api.Config{
				RegisterToken:         "test_reg_token_abc123",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                testMailer,
				PublicURL:             "https://test.example.com",
				EmailPerHour:          50,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         30,
				NotifyBurst:           0,
				TrustedProxies:        []string{"10.0.0.0/8"},
				AllowBroadIPv6:        true,
				Clock:                 testClock,
				MaxOutstandingInvites: 15,
				RetentionSeconds:      5184000,
				AuthFailPerMinute:     20,
				AuthFailBurst:         8,
				WritePerMinute:        15,
				WriteBurst:            5,
				KeyIndexRebuildHours:  12,
				VersionDetail:         "full",
				CodePepper:            []byte("test_pepper_xyz789"),
				MaxBagsPerPeer:        200,
				MaxBagBytesPerPeer:    2097152,
			},
		},
		{
			name:           "key index rebuild default",
			envVars:        map[string]string{},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "invalid auth fail per minute",
			envVars: map[string]string{
				"PEERLINE_AUTH_FAIL_PER_MINUTE": "not_a_number",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			wantBuildErr:   true,
		},
		{
			name: "invalid write burst",
			envVars: map[string]string{
				"PEERLINE_WRITE_BURST": "abc",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			wantBuildErr:   true,
		},
		{
			name: "EMAIL_PER_HOUR non-numeric",
			envVars: map[string]string{
				"PEERLINE_EMAIL_PER_HOUR": "1O",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_EMAIL_PER_HOUR", "1O", "numeric"},
		},
		{
			name: "EMAIL_PER_HOUR zero (default)",
			envVars: map[string]string{
				"PEERLINE_EMAIL_PER_HOUR": "0",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "EMAIL_PER_HOUR negative",
			envVars: map[string]string{
				"PEERLINE_EMAIL_PER_HOUR": "-5",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_EMAIL_PER_HOUR", "-5", "non-negative"},
		},
		{
			name: "NOTIFY_PER_HOUR non-numeric",
			envVars: map[string]string{
				"PEERLINE_NOTIFY_PER_HOUR": "abc",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_NOTIFY_PER_HOUR", "abc", "numeric"},
		},
		{
			name: "NOTIFY_PER_HOUR zero (default)",
			envVars: map[string]string{
				"PEERLINE_NOTIFY_PER_HOUR": "0",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "NOTIFY_PER_HOUR negative",
			envVars: map[string]string{
				"PEERLINE_NOTIFY_PER_HOUR": "-10",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_NOTIFY_PER_HOUR", "-10", "non-negative"},
		},
		{
			name: "MAX_OUTSTANDING_INVITES non-numeric",
			envVars: map[string]string{
				"PEERLINE_MAX_OUTSTANDING_INVITES": "xyz",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_MAX_OUTSTANDING_INVITES", "xyz", "numeric"},
		},
		{
			name: "MAX_OUTSTANDING_INVITES zero (default)",
			envVars: map[string]string{
				"PEERLINE_MAX_OUTSTANDING_INVITES": "0",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "MAX_OUTSTANDING_INVITES negative",
			envVars: map[string]string{
				"PEERLINE_MAX_OUTSTANDING_INVITES": "-1",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_MAX_OUTSTANDING_INVITES", "-1", "non-negative"},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS non-numeric",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "notanumber",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_KEY_INDEX_REBUILD_HOURS", "notanumber", "numeric"},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS zero (default)",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "0",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS negative",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "-3",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_KEY_INDEX_REBUILD_HOURS", "-3", "non-negative"},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS exceeds max",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "10000",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_KEY_INDEX_REBUILD_HOURS", "10000", "8760"},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS at max",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "8760",
			},
			trustedProxies: nil,
			allowBroadIPv6: false,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        nil,
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  8760,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name: "KEY_INDEX_REBUILD_HOURS at max+1",
			envVars: map[string]string{
				"PEERLINE_KEY_INDEX_REBUILD_HOURS": "8761",
			},
			trustedProxies:     nil,
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantBuildErr:       true,
			wantBuildErrSubstr: []string{"PEERLINE_KEY_INDEX_REBUILD_HOURS", "8761", "8760"},
		},
		{
			name:               "/29 without opt-in rejected by api.New",
			envVars:            map[string]string{},
			trustedProxies:     []string{"2a06:98c0::/29"},
			allowBroadIPv6:     false,
			logger:             testLogger,
			wantNewErr:         true,
			wantNewErrContains: "must be at least /32",
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        []string{"2a06:98c0::/29"},
				AllowBroadIPv6:        false,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
		{
			name:           "/29 with opt-in accepted",
			envVars:        map[string]string{},
			trustedProxies: []string{"2a06:98c0::/29"},
			allowBroadIPv6: true,
			logger:         testLogger,
			want: api.Config{
				RegisterToken:         "",
				MsgPerMinute:          0,
				MsgBurst:              0,
				Logger:                testLogger,
				Mailer:                nil,
				PublicURL:             "",
				EmailPerHour:          0,
				EmailBurst:            0,
				EmailRcptPerHour:      0,
				NotifyPerHour:         0,
				NotifyBurst:           0,
				TrustedProxies:        []string{"2a06:98c0::/29"},
				AllowBroadIPv6:        true,
				Clock:                 nil,
				MaxOutstandingInvites: 0,
				RetentionSeconds:      0,
				AuthFailPerMinute:     0,
				AuthFailBurst:         0,
				WritePerMinute:        0,
				WriteBurst:            0,
				KeyIndexRebuildHours:  6,
				VersionDetail:         "",
				CodePepper:            []byte{},
				MaxBagsPerPeer:        0,
				MaxBagBytesPerPeer:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				if val, ok := tt.envVars[key]; ok {
					return val
				}
				return ""
			}

			// Build config exactly as main() does
			cfg, err := buildAPIConfig(getenv, tt.clock, tt.mailer, tt.versionDetail, tt.publicURL, tt.maxBagsPerPeer, tt.maxBagBytesPerPeer, tt.retentionSeconds, tt.trustedProxies, tt.allowBroadIPv6, tt.logger)
			if tt.wantBuildErr {
				if err == nil {
					t.Errorf("buildAPIConfig() succeeded, want error")
				} else if len(tt.wantBuildErrSubstr) > 0 {
					errStr := err.Error()
					for _, substr := range tt.wantBuildErrSubstr {
						if !strings.Contains(errStr, substr) {
							t.Errorf("buildAPIConfig() error = %q; want it to contain %q", errStr, substr)
						}
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("buildAPIConfig() error = %v, want nil", err)
			}

			// Compare Logger, Clock, and Mailer by identity
			if cfg.Logger != tt.want.Logger {
				t.Errorf("cfg.Logger = %p, want %p (mutation: Logger dropped or replaced)", cfg.Logger, tt.want.Logger)
			}
			if cfg.Clock != tt.want.Clock {
				t.Errorf("cfg.Clock = %p, want %p (mutation: Clock dropped or replaced)", cfg.Clock, tt.want.Clock)
			}
			if cfg.Mailer != tt.want.Mailer {
				t.Errorf("cfg.Mailer = %p, want %p (mutation: Mailer dropped or replaced)", cfg.Mailer, tt.want.Mailer)
			}

			// Nil out identity fields and compare the rest with DeepEqual
			cfg.Logger = nil
			cfg.Clock = nil
			cfg.Mailer = nil
			wantCopy := tt.want
			wantCopy.Logger = nil
			wantCopy.Clock = nil
			wantCopy.Mailer = nil

			if !reflect.DeepEqual(cfg, wantCopy) {
				t.Errorf("buildAPIConfig() returned config mismatch:\ngot:  %+v\nwant: %+v", cfg, wantCopy)
			}

			// Restore Logger, Clock, and Mailer for api.New test (they were nil'd out for DeepEqual)
			cfg.Logger = tt.want.Logger
			cfg.Clock = tt.want.Clock
			cfg.Mailer = tt.want.Mailer

			// Verify that api.New accepts or rejects the config as expected
			st, stErr := store.Open(":memory:")
			if stErr != nil {
				t.Fatal(stErr)
			}
			defer st.Close()
			if _, _, stErr := st.LoadKeyIndex(context.Background()); stErr != nil {
				t.Fatal(stErr)
			}

			srv, newErr := api.New(st, cfg)
			if tt.wantNewErr {
				if newErr == nil {
					t.Errorf("api.New succeeded, want error containing %q", tt.wantNewErrContains)
				} else if !strings.Contains(newErr.Error(), tt.wantNewErrContains) {
					t.Errorf("api.New error = %q, want error containing %q", newErr.Error(), tt.wantNewErrContains)
				}
			} else {
				if newErr != nil {
					t.Errorf("api.New failed: %v", newErr)
				}
			}
			if srv != nil {
				srv.Stop()
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

// TestBroadProxyBehavior verifies that the main glue (buildTrustedProxySettings + buildAPIConfig + api.New)
// honors X-Forwarded-For from inside a trusted /29 proxy with ALLOW_BROAD=1.
// It uses per-IP rate limiting to observe the resolved client IP: requests with different XFF values
// are rate-limited separately, proving XFF is honored.
func TestBroadProxyBehavior(t *testing.T) {
	tests := []struct {
		name         string
		allowBroad   string
		trustedProxy string
		wantNewErr   bool
	}{
		{
			name:         "broad /29 without opt-in rejected at buildTrustedProxySettings",
			allowBroad:   "0",
			trustedProxy: "2a06:98c0::/29",
			wantNewErr:   true,
		},
		{
			name:         "broad /29 with opt-in honors XFF for rate limiting",
			allowBroad:   "1",
			trustedProxy: "2a06:98c0::/29",
			wantNewErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}

			// Build config exactly as main() does, with low auth-fail rate limit for testing
			getenv := func(key string) string {
				switch key {
				case "PEERLINE_TRUSTED_PROXIES":
					return tt.trustedProxy
				case "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD":
					return tt.allowBroad
				case "PEERLINE_AUTH_FAIL_PER_MINUTE":
					return "2" // Low limit for testing
				case "PEERLINE_AUTH_FAIL_BURST":
					return "2"
				default:
					return ""
				}
			}

			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			trustedProxies, allowBroadIPv6, err := buildTrustedProxySettings(getenv, log)
			if tt.wantNewErr {
				if err == nil {
					t.Fatal("buildTrustedProxySettings succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildTrustedProxySettings error = %v", err)
			}

			cfg, err := buildAPIConfig(getenv, nil, nil, "minimal", "", 0, 0, 0, trustedProxies, allowBroadIPv6, log)
			if err != nil {
				t.Fatalf("buildAPIConfig error = %v", err)
			}

			srv, newErr := api.New(st, cfg)
			if newErr != nil {
				t.Fatalf("api.New failed: %v", newErr)
			}
			defer srv.Stop()

			// Create test HTTP server with custom transport to control RemoteAddr
			handler := srv.Handler()
			testSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Rewrite RemoteAddr to be inside the trusted /29
				r.RemoteAddr = "[2a06:98c0::1]:12345"
				handler.ServeHTTP(w, r)
			}))
			testSrv.Start()
			defer testSrv.Close()

			// Helper to send auth-fail request with XFF
			sendAuthFail := func(xffIP string) int {
				body := strings.NewReader(`{"email":"test@example.com","mode":"claim"}`)
				req, _ := http.NewRequest("POST", testSrv.URL+"/v1/invite", body)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer pl_invalid_key")
				if xffIP != "" {
					req.Header.Set("X-Forwarded-For", xffIP)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				return resp.StatusCode
			}

			// XFF IP A: exhaust rate limit (2 requests, burst 2)
			if status := sendAuthFail("203.0.113.1"); status != 401 {
				t.Errorf("XFF A request 1 status = %d, want 401", status)
			}
			if status := sendAuthFail("203.0.113.1"); status != 401 {
				t.Errorf("XFF A request 2 status = %d, want 401", status)
			}
			// XFF IP A: should be rate-limited now
			if status := sendAuthFail("203.0.113.1"); status != 429 {
				t.Errorf("XFF A request 3 (rate-limited) status = %d, want 429", status)
			}

			// XFF IP B: should NOT be rate-limited (different client IP)
			if status := sendAuthFail("203.0.113.2"); status != 401 {
				t.Errorf("XFF B request 1 status = %d, want 401 (proving XFF is honored)", status)
			}
		})
	}
}

package main

import (
	"strings"
	"testing"
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

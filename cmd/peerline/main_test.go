package main

import (
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

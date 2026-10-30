package api

import (
	"net"
	"strings"
	"testing"
)

func TestClientIPEdgeCases(t *testing.T) {
	trustedNets, _ := ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.0/24"})

	tests := []struct {
		name        string
		remoteAddr  string
		xff         []string
		trustedNets []*net.IPNet
		want        string
	}{
		{
			name:        "nil XFF header",
			remoteAddr:  "10.0.0.1:1234",
			xff:         nil,
			trustedNets: trustedNets,
			want:        "10.0.0.1",
		},
		{
			name:        "empty XFF header slice",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{},
			trustedNets: trustedNets,
			want:        "10.0.0.1",
		},
		{
			name:        "empty XFF header value",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{""},
			trustedNets: trustedNets,
			want:        "10.0.0.1",
		},
		{
			name:        "malformed entry in middle",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.99, unknown, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "10.0.0.2", // stops at unknown, returns last trusted
		},
		{
			name:        "malformed entry at right",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.99, _hidden"},
			trustedNets: trustedNets,
			want:        "10.0.0.1", // stops at _hidden, returns remoteAddr
		},
		{
			name:        "bare bracketed IPv6 without port",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"[2001:db8::1], 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "2001:db8::1",
		},
		{
			name:        "bracketed IPv6 with port",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"[2001:db8::1]:443, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "2001:db8::1",
		},
		{
			name:        "IPv6 with zone",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"fe80::1%eth0, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "fe80::1", // zone stripped
		},
		{
			name:        "IPv4-mapped IPv6 in XFF",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"::ffff:203.0.113.5, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "203.0.113.5", // unmapped
		},
		{
			name:        "all entries trusted",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"10.0.0.5, 10.0.0.6, 192.168.1.100"},
			trustedNets: trustedNets,
			want:        "10.0.0.1", // all trusted, falls back to RemoteAddr
		},
		{
			name:        "two XFF header lines",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.10, 10.0.0.2", "10.0.0.3"},
			trustedNets: trustedNets,
			want:        "203.0.113.10", // combined and walked right-to-left
		},
		{
			name:        "IPv4 with port",
			remoteAddr:  "10.0.0.1:1234",
			xff:         []string{"203.0.113.20:8080, 10.0.0.2"},
			trustedNets: trustedNets,
			want:        "203.0.113.20",
		},
		{
			name:        "cap at 50 entries - client IP beyond cap",
			remoteAddr:  "10.0.0.1:1234",
			xff:         makeXFFWithManyEntries(55, "203.0.113.1", "10.0.0.2"),
			trustedNets: trustedNets,
			want:        "10.0.0.1", // client IP at position 0 is beyond 50-entry cap, all visible entries trusted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientIP(tt.remoteAddr, tt.xff, tt.trustedNets)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// makeXFFWithManyEntries creates an XFF header with n entries:
// the first entry is clientIP, followed by n-2 trusted IPs, then proxyIP at the end.
func makeXFFWithManyEntries(n int, clientIP, proxyIP string) []string {
	if n < 2 {
		return []string{clientIP}
	}
	var entries []string
	entries = append(entries, clientIP)
	for i := 1; i < n-1; i++ {
		entries = append(entries, "10.0.0.100") // trusted filler
	}
	entries = append(entries, proxyIP)

	// Join all into one header
	result := ""
	for i, e := range entries {
		if i > 0 {
			result += ", "
		}
		result += e
	}
	return []string{result}
}

func TestParseAndNormalizeIPBrackets(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[2001:db8::1]", "2001:db8::1"},
		{"[::1]", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:80", "1.2.3.4"},
		{"[1.2.3.4]", ""}, // invalid
		{"not-an-ip", ""},
		{"[", ""},
		{"]", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseAndNormalizeIP(tt.input)
			if got != tt.want {
				t.Errorf("parseAndNormalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxiesRejectsOverlyBroad(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantError string
	}{
		{
			name:      "IPv4 /0",
			input:     []string{"0.0.0.0/0"},
			wantError: "prefix length /0 is too broad",
		},
		{
			name:      "IPv6 /0",
			input:     []string{"::/0"},
			wantError: "prefix length /0 is too broad",
		},
		{
			name:      "IPv4 /1",
			input:     []string{"0.0.0.0/1"},
			wantError: "IPv4 prefix must be at least /8",
		},
		{
			name:      "IPv4 /7",
			input:     []string{"10.0.0.0/7"},
			wantError: "IPv4 prefix must be at least /8",
		},
		{
			name:      "IPv6 /16",
			input:     []string{"2001:db8::/16"},
			wantError: "IPv6 prefix must be at least /32",
		},
		{
			name:      "IPv6 /31",
			input:     []string{"2001:db8::/31"},
			wantError: "IPv6 prefix must be at least /32",
		},
		{name: "zoned bare", input: []string{"fe80::1%eth0"}, wantError: "zone"},
		{name: "zoned CIDR", input: []string{"fe80::1%eth0/64"}, wantError: "zone"},
		{name: "mapped /96", input: []string{"::ffff:0:0/96"}, wantError: "at least /104"},
		{name: "mapped /80", input: []string{"::ffff:0:0/80"}, wantError: "at least /104"},
		{name: "mapped /95", input: []string{"::ffff:10.0.0.0/95"}, wantError: "at least /104"},
		{name: "mapped bare", input: []string{"::ffff:10.0.0.1"}},
		{name: "mapped /104", input: []string{"::ffff:10.0.0.0/104"}},
		{
			name:  "valid IPv4 /8",
			input: []string{"10.0.0.0/8"},
		},
		{
			name:  "valid IPv4 /16",
			input: []string{"192.168.0.0/16"},
		},
		{
			name:  "valid IPv6 /32",
			input: []string{"2001:db8::/32"},
		},
		{
			name:  "valid IPv6 /64",
			input: []string{"2001:db8::/64"},
		},
		{
			name:  "bare IPv4",
			input: []string{"192.168.1.1"},
		},
		{
			name:  "bare IPv6",
			input: []string{"2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTrustedProxies(tt.input)
			if tt.wantError != "" {
				if err == nil {
					t.Errorf("ParseTrustedProxies(%v) succeeded, want error containing %q", tt.input, tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("ParseTrustedProxies(%v) error = %q, want error containing %q", tt.input, err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("ParseTrustedProxies(%v) failed: %v", tt.input, err)
				}
			}
		})
	}
}

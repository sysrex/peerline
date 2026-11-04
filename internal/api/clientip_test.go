package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysrex/peerline/internal/msg"
	"github.com/sysrex/peerline/internal/store"
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
		want      string // expected network string for success cases
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
		{name: "mapped /96", input: []string{"::ffff:0:0/96"}, wantError: "covers all of IPv4"},
		{name: "mapped /80", input: []string{"::ffff:0:0/80"}, wantError: "at least /96"},
		{name: "mapped /95", input: []string{"::ffff:10.0.0.0/95"}, wantError: "at least /96"},
		{name: "mapped bare", input: []string{"::ffff:10.0.0.1"}},
		{name: "mapped /104", input: []string{"::ffff:10.0.0.0/104"}},
		{name: "0.0.0.0/8 (this network)", input: []string{"0.0.0.0/8"}, wantError: "this network"},
		{name: "::ffff:0.0.0.0/104 (mapped this network)", input: []string{"::ffff:0.0.0.0/104"}, wantError: "this network"},
		{
			name:      "zoned IPv6 address",
			input:     []string{"fe80::1%eth0"},
			wantError: "zone identifiers are not allowed",
		},
		{
			name:      "zoned IPv6 CIDR",
			input:     []string{"fe80::/64%eth0"},
			wantError: "zone identifiers are not allowed",
		},
		{
			name:      "IPv4-mapped IPv6 /80 (too broad, would trust ::1)",
			input:     []string{"::ffff:0:0/80"},
			wantError: "IPv4-mapped IPv6 prefix must be at least /96",
		},
		{
			name:      "IPv4-mapped IPv6 /96 (covers all IPv4)",
			input:     []string{"::ffff:0:0/96"},
			wantError: "covers all of IPv4",
		},
		{
			name:      "IPv4-mapped IPv6 /103 (too broad for IPv4)",
			input:     []string{"::ffff:10.0.0.0/103"},
			wantError: "must map to at least /8 in IPv4",
		},
		{
			name:  "IPv4-mapped IPv6 /104 (valid, unmaps to /8)",
			input: []string{"::ffff:10.0.0.0/104"},
			want:  "10.0.0.0/8",
		},
		{
			name:  "IPv4-mapped IPv6 /112 (valid, unmaps to /16)",
			input: []string{"::ffff:192.168.0.0/112"},
			want:  "192.168.0.0/16",
		},
		{
			name:  "bare IPv4-mapped IPv6 address",
			input: []string{"::ffff:10.0.0.1"},
			want:  "10.0.0.1/32",
		},
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
			nets, err := ParseTrustedProxies(tt.input)
			if tt.wantError != "" {
				if err == nil {
					t.Errorf("ParseTrustedProxies(%v) succeeded, want error containing %q", tt.input, tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("ParseTrustedProxies(%v) error = %q, want error containing %q", tt.input, err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("ParseTrustedProxies(%v) failed: %v", tt.input, err)
				} else if tt.want != "" {
					// Verify the resulting network
					if len(nets) != 1 {
						t.Errorf("ParseTrustedProxies(%v) returned %d networks, want 1", tt.input, len(nets))
					} else if nets[0].String() != tt.want {
						t.Errorf("ParseTrustedProxies(%v) = %q, want %q", tt.input, nets[0].String(), tt.want)
					}
				}
			}
		})
	}
}

// TestParseTrustedProxiesSymmetry verifies that IPv4-mapped and native IPv4
// prefixes trust the same client IPs.
func TestParseTrustedProxiesSymmetry(t *testing.T) {
	// Test that ::ffff:10.0.0.0/104 and 10.0.0.0/8 trust the same IPs
	mapped, err := ParseTrustedProxies([]string{"::ffff:10.0.0.0/104"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies(mapped) failed: %v", err)
	}
	native, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies(native) failed: %v", err)
	}

	// Both should result in 10.0.0.0/8
	if mapped[0].String() != "10.0.0.0/8" {
		t.Errorf("mapped network = %q, want 10.0.0.0/8", mapped[0].String())
	}
	if native[0].String() != "10.0.0.0/8" {
		t.Errorf("native network = %q, want 10.0.0.0/8", native[0].String())
	}

	// Verify Contains agrees for mapped and native forms for a table of addresses
	testAddrs := []struct {
		addr     string
		inRange  bool
		mappable bool
	}{
		{"10.0.0.5", true, true},
		{"::ffff:10.0.0.5", true, false}, // already mapped, so "mappable" = false
		{"10.1.0.1", true, true},
		{"::1", false, false},
		{"2001:db8::1", false, false},
		{"203.0.113.1", false, true},
	}

	for _, tt := range testAddrs {
		addr := net.ParseIP(tt.addr)
		mappedContains := mapped[0].Contains(addr)
		nativeContains := native[0].Contains(addr)

		if mappedContains != nativeContains {
			t.Errorf("Contains(%q): mapped=%v native=%v, want same", tt.addr, mappedContains, nativeContains)
		}
		if mappedContains != tt.inRange {
			t.Errorf("Contains(%q) = %v, want %v", tt.addr, mappedContains, tt.inRange)
		}
	}

	// Test clientIP with a mapped peer and mapped XFF hop
	ip := clientIP("[::ffff:10.0.0.5]:1234", []string{"::ffff:203.0.113.9"}, mapped)
	if ip != "203.0.113.9" {
		t.Errorf("clientIP with mapped peer and mapped XFF = %q, want 203.0.113.9", ip)
	}
}

// TestRateLimitGetWithMultipleXFFHeaders verifies that multiple X-Forwarded-For
// header lines are properly combined and used for IP-based rate limiting on
// public GET routes (#61). Uses GET /v1/pairing/{token} which goes through rateLimitGet.
func TestRateLimitGetWithMultipleXFFHeaders(t *testing.T) {
	// Set up test database
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create server with trusted proxies and custom small getLim for testing
	cfg := Config{
		TrustedProxies: []string{"127.0.0.0/8", "10.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Override the GET limiter with a tiny budget (burst 2) for testing
	srv.lim.getLim = msg.NewLimiter(2, 2) // 2 per minute, burst 2

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Create a peer via the HTTP API and get an invite with pairing token
	client := &struct {
		t   *testing.T
		key string
	}{t: t}

	// Register a peer
	regResp, err := http.Post(httpSrv.URL+"/v1/register", "application/json", strings.NewReader(`{"name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	var regBody struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regBody); err != nil {
		t.Fatal(err)
	}
	client.key = regBody.APIKey

	// Create an invite with pairing URL
	invReq, _ := http.NewRequest("POST", httpSrv.URL+"/v1/invites", strings.NewReader(`{"scopes":["messages"],"generate_pairing":true}`))
	invReq.Header.Set("Authorization", "Bearer "+client.key)
	invReq.Header.Set("Content-Type", "application/json")
	invResp, err := http.DefaultClient.Do(invReq)
	if err != nil {
		t.Fatal(err)
	}
	defer invResp.Body.Close()

	if invResp.StatusCode != 201 {
		t.Fatalf("create invite failed: status %d", invResp.StatusCode)
	}

	var invBody struct {
		PairingURL string `json:"pairing_url"`
	}
	if err := json.NewDecoder(invResp.Body).Decode(&invBody); err != nil {
		t.Fatal(err)
	}

	// Extract pairing token from URL (e.g., http://host/v1/pairing/TOKEN)
	parts := strings.Split(invBody.PairingURL, "/")
	pairingToken := parts[len(parts)-1]

	// Helper to make a GET request with custom XFF headers
	makeRequest := func(xff ...string) (int, string) {
		req, _ := http.NewRequest("GET", httpSrv.URL+"/v1/pairing/"+pairingToken, nil)
		for _, header := range xff {
			req.Header.Add("X-Forwarded-For", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}

	// Client X sends two XFF header lines: "203.0.113.10, 10.0.0.2" and "127.0.0.2"
	// Combined list: [203.0.113.10, 10.0.0.2, 127.0.0.2]
	// Walk right-to-left: 127.0.0.2 (trusted), 10.0.0.2 (trusted), 203.0.113.10 (untrusted → use this)
	xffClientX := []string{"203.0.113.10, 10.0.0.2", "127.0.0.2"}

	// Exhaust Client X's budget (burst 2)
	status1, _ := makeRequest(xffClientX...)
	if status1 != 200 {
		t.Errorf("client X request 1: got status %d, want 200", status1)
	}
	status2, _ := makeRequest(xffClientX...)
	if status2 != 200 {
		t.Errorf("client X request 2: got status %d, want 200", status2)
	}

	// Third request from Client X should be rate limited
	status3, retryAfter := makeRequest(xffClientX...)
	if status3 != 429 {
		t.Errorf("client X request 3: got status %d, want 429 (rate limited)", status3)
	}
	if retryAfter == "" {
		t.Error("client X request 3: missing Retry-After header")
	}

	// Client Y sends a single XFF: "203.0.113.11" with trusted proxy "127.0.0.3"
	// Different IP, so different bucket - should still succeed
	xffClientY := []string{"203.0.113.11", "127.0.0.3"}
	statusY, _ := makeRequest(xffClientY...)
	if statusY != 200 {
		t.Errorf("client Y request: got status %d, want 200 (different IP bucket)", statusY)
	}
}

// TestRateLimitGetRightmostKeying verifies that rate limiting uses the rightmost
// untrusted IP from X-Forwarded-For, not the leftmost (#61, #166).
// This test would pass incorrectly if the code took the leftmost entry.
func TestRateLimitGetRightmostKeying(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		TrustedProxies: []string{"127.0.0.0/8", "10.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Override GET limiter with burst 2
	srv.lim.getLim = msg.NewLimiter(2, 2)

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Create a peer and invite with pairing token
	regResp, err := http.Post(httpSrv.URL+"/v1/register", "application/json", strings.NewReader(`{"name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	var regBody struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regBody); err != nil {
		t.Fatal(err)
	}

	invReq, _ := http.NewRequest("POST", httpSrv.URL+"/v1/invites", strings.NewReader(`{"scopes":["messages"],"generate_pairing":true}`))
	invReq.Header.Set("Authorization", "Bearer "+regBody.APIKey)
	invReq.Header.Set("Content-Type", "application/json")
	invResp, err := http.DefaultClient.Do(invReq)
	if err != nil {
		t.Fatal(err)
	}
	defer invResp.Body.Close()
	var invBody struct {
		PairingURL string `json:"pairing_url"`
	}
	if err := json.NewDecoder(invResp.Body).Decode(&invBody); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(invBody.PairingURL, "/")
	token := parts[len(parts)-1]

	makeReq := func(xff ...string) int {
		req, _ := http.NewRequest("GET", httpSrv.URL+"/v1/pairing/"+token, nil)
		for _, h := range xff {
			req.Header.Add("X-Forwarded-For", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Client A: XFF [198.51.100.1, 203.0.113.10]
	// Rightmost untrusted is 203.0.113.10
	if status := makeReq("198.51.100.1, 203.0.113.10", "127.0.0.2"); status != 200 {
		t.Errorf("client A request 1: got %d, want 200", status)
	}
	if status := makeReq("198.51.100.1, 203.0.113.10", "127.0.0.2"); status != 200 {
		t.Errorf("client A request 2: got %d, want 200", status)
	}

	// Client B: XFF [198.51.100.2, 203.0.113.10]
	// Also keys to 203.0.113.10 (rightmost), should get 429
	// This test FAILS if code takes leftmost (would key to different IPs)
	if status := makeReq("198.51.100.2, 203.0.113.10", "127.0.0.3"); status != 429 {
		t.Errorf("client B: got %d, want 429 (same rightmost IP exhausted)", status)
	}

	// Test with headers split across two lines
	// Client C: same rightmost (203.0.113.10) split differently
	if status := makeReq("198.51.100.3", "203.0.113.10, 127.0.0.4"); status != 429 {
		t.Errorf("client C split headers: got %d, want 429", status)
	}

	// Positive control: Client D with a different rightmost entry should still get 200
	if status := makeReq("198.51.100.4, 203.0.113.11", "127.0.0.5"); status != 200 {
		t.Errorf("client D different rightmost: got %d, want 200", status)
	}
}

// TestUntrustedDirectPeer verifies that XFF is ignored when RemoteAddr is not trusted.
func TestUntrustedDirectPeer(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		TrustedProxies: []string{"10.0.0.0/8"}, // httptest server uses 127.0.0.1 (loopback, not in 10/8)
		MsgPerMinute:   10,
		MsgBurst:       10,
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv.lim.regLim = msg.NewLimiter(2, 2)

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Register from RemoteAddr that is not in the trusted 10.0.0.0/8 range.
	// XFF header should be ignored.
	makeReg := func(xff string) int {
		req, _ := http.NewRequest("POST", httpSrv.URL+"/v1/register", strings.NewReader(`{"name":"test"}`))
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Two registrations - keyed on RemoteAddr not XFF
	if status := makeReg("1.2.3.4"); status != 201 {
		t.Errorf("reg 1: got %d, want 201", status)
	}
	if status := makeReg("5.6.7.8"); status != 201 {
		t.Errorf("reg 2: got %d, want 201", status)
	}
	// Third should be rate limited - same RemoteAddr bucket
	if status := makeReg("9.10.11.12"); status != 429 {
		t.Errorf("reg 3: got %d, want 429", status)
	}
}

// TestIPv4MappedDirectPeer verifies that ::ffff:a.b.c.d keys the same as a.b.c.d.
func TestIPv4MappedDirectPeer(t *testing.T) {
	trustedNets, _ := ParseTrustedProxies([]string{"10.0.0.0/8"})

	// Test clientIP with IPv4-mapped RemoteAddr
	ipv4Mapped := clientIP("[::ffff:203.0.113.10]:1234", nil, trustedNets)
	ipv4Native := clientIP("203.0.113.10:1234", nil, trustedNets)

	if ipv4Mapped != "203.0.113.10" {
		t.Errorf("IPv4-mapped RemoteAddr = %q, want 203.0.113.10", ipv4Mapped)
	}
	if ipv4Native != "203.0.113.10" {
		t.Errorf("IPv4 native RemoteAddr = %q, want 203.0.113.10", ipv4Native)
	}

	// Verify they produce the same rate limit key
	keyMapped := rateLimitKey(ipv4Mapped)
	keyNative := rateLimitKey(ipv4Native)
	if keyMapped != keyNative {
		t.Errorf("rate limit keys differ: mapped=%q native=%q", keyMapped, keyNative)
	}

	// Test a trusted mapped peer with XFF: should extract the XFF hop
	ipWithXFF := clientIP("[::ffff:10.0.0.5]:1234", []string{"203.0.113.9"}, trustedNets)
	if ipWithXFF != "203.0.113.9" {
		t.Errorf("clientIP with trusted mapped peer and XFF = %q, want 203.0.113.9", ipWithXFF)
	}
}

// TestClientIPAtMultipleCallSites verifies clientIP is used correctly at
// registration (regLim), pairing (pairLim), and auth-fail (failLim) call sites.
func TestClientIPAtMultipleCallSites(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		TrustedProxies: []string{"127.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv.lim.regLim = msg.NewLimiter(2, 2)
	srv.lim.pairLim = msg.NewLimiter(2, 2)
	srv.lim.failLim = msg.NewLimiter(2, 2)

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	makeReg := func(xff ...string) int {
		req, _ := http.NewRequest("POST", httpSrv.URL+"/v1/register", strings.NewReader(`{"name":"test"}`))
		req.Header.Set("Content-Type", "application/json")
		for _, h := range xff {
			req.Header.Add("X-Forwarded-For", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Test regLim keying
	// Client with XFF [203.0.113.50, 127.0.0.2]
	xff := []string{"203.0.113.50", "127.0.0.2"}
	if status := makeReg(xff...); status != 201 {
		t.Errorf("reg 1: got %d, want 201", status)
	}
	if status := makeReg(xff...); status != 201 {
		t.Errorf("reg 2: got %d, want 201", status)
	}
	if status := makeReg(xff...); status != 429 {
		t.Errorf("reg 3: got %d, want 429 (rate limited)", status)
	}

	// Test pairLim keying: create an invite with pairing URL and POST to accept it
	regResp, err := http.Post(httpSrv.URL+"/v1/register", "application/json", strings.NewReader(`{"name":"pair-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	var regBody struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regBody); err != nil {
		t.Fatal(err)
	}
	acceptorKey := regBody.APIKey

	// Register another peer to create invites for each test
	regResp2, err := http.Post(httpSrv.URL+"/v1/register", "application/json", strings.NewReader(`{"name":"inviter"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp2.Body.Close()
	var regBody2 struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(regResp2.Body).Decode(&regBody2); err != nil {
		t.Fatal(err)
	}
	inviterKey := regBody2.APIKey

	// Helper to create a new pairing invite
	createPairingInvite := func() string {
		invReq, _ := http.NewRequest("POST", httpSrv.URL+"/v1/invites", strings.NewReader(`{"scopes":["messages"],"generate_pairing":true}`))
		invReq.Header.Set("Authorization", "Bearer "+inviterKey)
		invReq.Header.Set("Content-Type", "application/json")
		invResp, err := http.DefaultClient.Do(invReq)
		if err != nil {
			t.Fatal(err)
		}
		defer invResp.Body.Close()
		var invBody struct {
			PairingURL string `json:"pairing_url"`
		}
		if err := json.NewDecoder(invResp.Body).Decode(&invBody); err != nil {
			t.Fatal(err)
		}
		return invBody.PairingURL
	}

	// POST to pairing URL charges pairLim
	makePairReq := func(pairingURL string, xff ...string) int {
		req, _ := http.NewRequest("POST", pairingURL, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+acceptorKey)
		req.Header.Set("Content-Type", "application/json")
		for _, h := range xff {
			req.Header.Add("X-Forwarded-For", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	xffPair := []string{"203.0.113.60", "127.0.0.3"}
	url1 := createPairingInvite()
	status1 := makePairReq(url1, xffPair...)
	if status1 != 200 && status1 != 201 {
		t.Errorf("pair 1: got %d, want 200 or 201", status1)
	}
	url2 := createPairingInvite()
	status2 := makePairReq(url2, xffPair...)
	if status2 != 200 && status2 != 201 {
		t.Errorf("pair 2: got %d, want 200 or 201", status2)
	}
	url3 := createPairingInvite()
	if status := makePairReq(url3, xffPair...); status != 429 {
		t.Errorf("pair 3: got %d, want 429 (rate limited)", status)
	}

	// Test failLim keying: send bad auth to /v1/me
	makeFailReq := func(xff ...string) int {
		req, _ := http.NewRequest("GET", httpSrv.URL+"/v1/me", nil)
		req.Header.Set("Authorization", "Bearer pl_invalid")
		for _, h := range xff {
			req.Header.Add("X-Forwarded-For", h)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	xffFail := []string{"203.0.113.70", "127.0.0.4"}
	if status := makeFailReq(xffFail...); status != 401 {
		t.Errorf("fail 1: got %d, want 401", status)
	}
	if status := makeFailReq(xffFail...); status != 401 {
		t.Errorf("fail 2: got %d, want 401", status)
	}
	if status := makeFailReq(xffFail...); status != 429 {
		t.Errorf("fail 3: got %d, want 429 (rate limited)", status)
	}
}

// TestNewWithInvalidProxyConfig verifies that api.New returns an error
// for invalid trusted proxy configuration.
func TestNewWithInvalidProxyConfig(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tests := []struct {
		name           string
		trustedProxies []string
	}{
		{"zoned address", []string{"fe80::1%eth0"}},
		{"invalid CIDR", []string{"256.256.256.256/24"}},
		{"too broad IPv4", []string{"0.0.0.0/0"}},
		{"too broad IPv6", []string{"::/0"}},
		{"IPv4-mapped too broad", []string{"::ffff:0:0/96"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TrustedProxies: tt.trustedProxies,
			}
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, err := New(st, cfg)
			if err == nil {
				t.Error("New() succeeded with invalid proxy config, want error")
			}
		})
	}
}

// TestNoRequestPanicAfterValidConfig verifies that clientIP call sites never panic
// after any valid configuration is accepted. This is the request-level version of
// the parse-level guard (TestNewWithInvalidProxyConfig).
func TestNoRequestPanicAfterValidConfig(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		wantStatus     int
	}{
		// Empty config: no trusted proxies, should work
		{name: "empty config", trustedProxies: []string{}, remoteAddr: "127.0.0.1", xff: "203.0.113.1", wantStatus: 200},
		// Simple IPv4
		{name: "IPv4 /8, untrusted peer", trustedProxies: []string{"10.0.0.0/8"}, remoteAddr: "127.0.0.1", xff: "203.0.113.2", wantStatus: 200},
		{name: "IPv4 /8, trusted peer with XFF", trustedProxies: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.1", xff: "203.0.113.3", wantStatus: 200},
		// IPv6
		{name: "IPv6 /32", trustedProxies: []string{"2001:db8::/32"}, remoteAddr: "2001:db8::1", xff: "2001:db8::99", wantStatus: 200},
		// IPv4-mapped IPv6 (this was the #164 nil *net.IPNet path)
		{name: "IPv4-mapped /104, trusted peer", trustedProxies: []string{"::ffff:10.0.0.0/104"}, remoteAddr: "::ffff:10.0.0.5", xff: "203.0.113.4", wantStatus: 200},
		{name: "IPv4-mapped /104, untrusted peer", trustedProxies: []string{"::ffff:10.0.0.0/104"}, remoteAddr: "127.0.0.1", xff: "203.0.113.5", wantStatus: 200},
		// Bare IPs
		{name: "bare IPs", trustedProxies: []string{"10.0.0.1", "192.168.1.1"}, remoteAddr: "10.0.0.1", xff: "203.0.113.6", wantStatus: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TrustedProxies: tt.trustedProxies,
				MsgPerMinute:   10,
				MsgBurst:       10,
			}
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}
			srv, err := New(st, cfg)
			if err != nil {
				t.Fatalf("New() with %v failed: %v", tt.trustedProxies, err)
			}

			httpSrv := httptest.NewServer(srv.Handler())
			defer httpSrv.Close()

			// Register a peer and create a pairing invite
			regResp, err := http.Post(httpSrv.URL+"/v1/register", "application/json", strings.NewReader(`{"name":"test"}`))
			if err != nil {
				t.Fatal(err)
			}
			var regBody struct {
				APIKey string `json:"api_key"`
			}
			json.NewDecoder(regResp.Body).Decode(&regBody)
			regResp.Body.Close()

			invReq, _ := http.NewRequest("POST", httpSrv.URL+"/v1/invites", strings.NewReader(`{"scopes":["messages"],"generate_pairing":true}`))
			invReq.Header.Set("Authorization", "Bearer "+regBody.APIKey)
			invReq.Header.Set("Content-Type", "application/json")
			invResp, err := http.DefaultClient.Do(invReq)
			if err != nil {
				t.Fatal(err)
			}
			var invBody struct {
				PairingURL string `json:"pairing_url"`
			}
			json.NewDecoder(invResp.Body).Decode(&invBody)
			invResp.Body.Close()

			// Extract pairing token
			parts := strings.Split(invBody.PairingURL, "/")
			pairingToken := parts[len(parts)-1]

			// Make a request through clientIP call site (GET /v1/pairing/{token})
			// This exercises the actual clientIP code path, including the #164 nil-IPNet case
			req, _ := http.NewRequest("GET", httpSrv.URL+"/v1/pairing/"+pairingToken, nil)
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			// Note: httptest always uses 127.0.0.1 as RemoteAddr, so we can't actually
			// test the exact RemoteAddr, but we can verify no panic and correct status.

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed (connection error): %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("got status %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

// TestTrustedProxiesStartupLogging verifies that trusted proxy networks are
// logged at startup (#62).
func TestTrustedProxiesStartupLogging(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	tests := []struct {
		name           string
		trustedProxies []string
		wantLog        string
	}{
		{
			name:           "with proxies",
			trustedProxies: []string{"10.0.0.0/8", "192.168.1.0/24"},
			wantLog:        "10.0.0.0/8, 192.168.1.0/24",
		},
		{
			name:           "empty list",
			trustedProxies: []string{},
			wantLog:        "no trusted proxies configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuf.Reset()
			cfg := Config{
				TrustedProxies: tt.trustedProxies,
				Logger:         logger,
			}
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}
			srv, err := New(st, cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer srv.Stop()

			logOutput := logBuf.String()
			if !strings.Contains(logOutput, tt.wantLog) {
				t.Errorf("log output %q does not contain %q", logOutput, tt.wantLog)
			}
		})
	}
}

func TestNewWarnsWhenTrustedProxiesParseToNothing(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, Config{TrustedProxies: []string{" ", ""}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.lim.Stop)
	logOutput := logs.String()
	if !strings.Contains(logOutput, "no trusted proxies configured") {
		t.Fatalf("a set-but-empty trusted proxy list must warn, got logs: %q", logOutput)
	}
	// Ensure there's only one warning (not duplicated)
	count := strings.Count(logOutput, "no trusted proxies configured")
	if count != 1 {
		t.Fatalf("expected exactly 1 warning, got %d in logs: %q", count, logOutput)
	}
}

func TestIPv6FloorWithOptIn(t *testing.T) {
	tests := []struct {
		name       string
		input      []string
		allowBroad bool
		wantError  string
		wantNet    string
	}{
		// Default floor /32
		{name: "IPv6 /32 allowed (default)", input: []string{"2001:db8::/32"}, allowBroad: false},
		{name: "IPv6 /31 rejected (default)", input: []string{"2001:db8::/31"}, allowBroad: false, wantError: "must be at least /32"},
		{name: "IPv6 /29 rejected (default)", input: []string{"2a06:98c0::/29"}, allowBroad: false, wantError: "must be at least /32"},
		{name: "ULA fc00::/7 rejected (default)", input: []string{"fc00::/7"}, allowBroad: false, wantError: "must be at least /32"},
		{name: "ULA fd00::/8 rejected (default)", input: []string{"fd00::/8"}, allowBroad: false, wantError: "must be at least /32"},

		// Opt-in floor /29
		{name: "IPv6 /29 allowed (opt-in)", input: []string{"2a06:98c0::/29"}, allowBroad: true, wantNet: "2a06:98c0::/29"},
		{name: "IPv6 /32 allowed (opt-in)", input: []string{"2001:db8::/32"}, allowBroad: true},
		{name: "IPv6 /28 rejected (opt-in)", input: []string{"2a06:98c0::/28"}, allowBroad: true, wantError: "must be at least /29"},
		{name: "ULA fc00::/7 allowed (opt-in)", input: []string{"fc00::/7"}, allowBroad: true, wantNet: "fc00::/7"},
		{name: "ULA fd00::/8 allowed (opt-in)", input: []string{"fd00::/8"}, allowBroad: true, wantNet: "fd00::/8"},

		// Still rejected even with opt-in
		{name: "::/0 rejected (opt-in)", input: []string{"::/0"}, allowBroad: true, wantError: "too broad"},
		{name: "2000::/3 rejected (opt-in)", input: []string{"2000::/3"}, allowBroad: true, wantError: "too broad"},
		{name: "2002::/16 rejected (opt-in)", input: []string{"2002::/16"}, allowBroad: true, wantError: "not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseTrustedProxiesWithOpts(tt.input, tt.allowBroad)
			if tt.wantError != "" {
				if err == nil {
					t.Errorf("ParseTrustedProxiesWithOpts(%v, %v) succeeded, want error containing %q", tt.input, tt.allowBroad, tt.wantError)
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error = %q, want error containing %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("ParseTrustedProxiesWithOpts(%v, %v) failed: %v", tt.input, tt.allowBroad, err)
				} else if tt.wantNet != "" {
					if len(nets) != 1 {
						t.Errorf("got %d networks, want 1", len(nets))
					} else if nets[0].String() != tt.wantNet {
						t.Errorf("got network %q, want %q", nets[0].String(), tt.wantNet)
					}
				}
			}
		})
	}
}

func TestAllowBroadIPv6Warning(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, Config{
		TrustedProxies: []string{"2a06:98c0::/29"},
		AllowBroadIPv6: true,
		Logger:         slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.lim.Stop)

	logOutput := logs.String()
	if !strings.Contains(logOutput, "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled") {
		t.Errorf("expected warning about ALLOW_BROAD, got logs: %q", logOutput)
	}
	if !strings.Contains(logOutput, "spoof X-Forwarded-For") {
		t.Errorf("expected security warning about spoofing, got logs: %q", logOutput)
	}
}

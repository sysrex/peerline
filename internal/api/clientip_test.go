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
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
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
		{name: "0.0.0.0/16 (inside this network)", input: []string{"0.0.0.0/16"}, wantError: "this network"},
		{name: "0.1.0.0/16 (inside this network)", input: []string{"0.1.0.0/16"}, wantError: "this network"},
		{name: "bare 0.0.0.0 (this network)", input: []string{"0.0.0.0"}, wantError: "this network"},
		{name: "::ffff:0.0.0.0/104 (mapped this network)", input: []string{"::ffff:0.0.0.0/104"}, wantError: "this network"},
		{name: "bare ::ffff:0.0.0.0 (mapped this network)", input: []string{"::ffff:0.0.0.0"}, wantError: "this network"},
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

	// Verify Contains agrees for mapped and native forms of each address against the same net
	testAddrs := []struct {
		addr    string
		inRange bool
	}{
		{"10.0.0.5", true},
		{"::ffff:10.0.0.5", true},
		{"10.1.0.1", true},
		{"::1", false},
		{"2001:db8::1", false},
		{"203.0.113.1", false},
	}

	for _, tt := range testAddrs {
		addr := net.ParseIP(tt.addr)
		nativeContains := native[0].Contains(addr)
		mappedContains := mapped[0].Contains(addr)

		if nativeContains != tt.inRange {
			t.Errorf("native[0].Contains(%q) = %v, want %v", tt.addr, nativeContains, tt.inRange)
		}
		if mappedContains != tt.inRange {
			t.Errorf("mapped[0].Contains(%q) = %v, want %v", tt.addr, mappedContains, tt.inRange)
		}
		if nativeContains != mappedContains {
			t.Errorf("Contains(%q): native=%v mapped=%v, want same", tt.addr, nativeContains, mappedContains)
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
	json.NewDecoder(regResp.Body).Decode(&regBody)

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
	json.NewDecoder(invResp.Body).Decode(&invBody)
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
	if status := makeReq("198.51.100.5, 203.0.113.11", "127.0.0.5"); status != 200 {
		t.Errorf("client D different rightmost: got %d, want 200", status)
	}
}

// TestUntrustedDirectPeer verifies that XFF is ignored when RemoteAddr is not trusted.
// The httptest peer (127.0.0.1) is outside the trusted range (10.0.0.0/8), so XFF is ignored
// and all requests share the same RemoteAddr-based rate limit bucket.
func TestUntrustedDirectPeer(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := Config{
		TrustedProxies: []string{"10.0.0.0/8"},
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

	// Register from untrusted IP with XFF header - XFF should be ignored
	makeReg := func(xff string) int {
		req, _ := http.NewRequest("POST", httpSrv.URL+"/v1/register", strings.NewReader(`{"name":"test"}`))
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		// httptest's RemoteAddr (127.0.0.1) is outside 10.0.0.0/8, so XFF is ignored
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
// registration (regLim) in addition to GET routes.
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
}

// TestFailedAuthKeyingUsesClientIP verifies that failed authentication attempts
// (invalid API keys) are keyed by clientIP, not r.RemoteAddr. This test would fail
// if the authMiddleware used r.RemoteAddr directly. Includes leftmost-keying case.
func TestFailedAuthKeyingUsesClientIP(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	frozenNow := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		TrustedProxies:    []string{"127.0.0.0/8"},
		AuthFailPerMinute: 2,
		AuthFailBurst:     2,
		Clock:             clocktest.New(frozenNow),
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	makeAuthReq := func(xff ...string) int {
		req, err := http.NewRequest("GET", httpSrv.URL+"/v1/me", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer pl_invalid_key_that_does_not_exist")
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

	// Client A: XFF [203.0.113.60, 127.0.0.2] → clientIP 203.0.113.60
	xffA := []string{"203.0.113.60, 127.0.0.2"}
	if status := makeAuthReq(xffA...); status != 401 {
		t.Errorf("client A req 1: got %d, want 401", status)
	}
	if status := makeAuthReq(xffA...); status != 401 {
		t.Errorf("client A req 2: got %d, want 401", status)
	}

	// Client B: XFF [203.0.113.61, 127.0.0.2] → clientIP 203.0.113.61 (different bucket)
	xffB := []string{"203.0.113.61, 127.0.0.2"}
	if status := makeAuthReq(xffB...); status != 401 {
		t.Errorf("client B req 1: got %d, want 401", status)
	}

	// Client A third request: should be rate limited
	if status := makeAuthReq(xffA...); status != 429 {
		t.Errorf("client A req 3: got %d, want 429 (same clientIP exhausted)", status)
	}

	// Client B second request: different clientIP, should still be 401
	if status := makeAuthReq(xffB...); status != 401 {
		t.Errorf("client B req 2: got %d, want 401 (different bucket)", status)
	}

	// Leftmost-keying case: spoofed leftmost entry doesn't change the key
	// Client C: XFF [198.51.100.10, 203.0.113.62, 127.0.0.3]
	// Walk right-to-left: 127.0.0.3 (trusted), 203.0.113.62 (untrusted → use this)
	// The leftmost 198.51.100.10 is ignored
	xffC := []string{"198.51.100.10, 203.0.113.62, 127.0.0.3"}
	if status := makeAuthReq(xffC...); status != 401 {
		t.Errorf("client C req 1 (leftmost ignored): got %d, want 401", status)
	}
	if status := makeAuthReq(xffC...); status != 401 {
		t.Errorf("client C req 2: got %d, want 401", status)
	}

	// Client D: XFF [198.51.100.99, 203.0.113.62, 127.0.0.3]
	// Different leftmost, same rightmost untrusted → same key (203.0.113.62)
	xffD := []string{"198.51.100.99, 203.0.113.62, 127.0.0.3"}
	if status := makeAuthReq(xffD...); status != 429 {
		t.Errorf("client D req 1 (same rightmost untrusted): got %d, want 429 (proves leftmost is ignored)", status)
	}
}

// TestPairingAcceptKeyingUsesClientIP verifies that unauthenticated pairing token checks
// are keyed by clientIP (pairLim), not r.RemoteAddr. This test would fail if
// checkPairingToken used r.RemoteAddr directly. We use invalid tokens (not in DB)
// so they're not consumed and we can test the rate limiter behavior. Includes leftmost-keying case.
func TestPairingAcceptKeyingUsesClientIP(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	frozenNow := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		TrustedProxies: []string{"127.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
		Clock:          clocktest.New(frozenNow),
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	withLimiterOverride(t, srv, func(lm *LimiterManager, newLimiter func(int, int) *msg.Limiter) {
		lm.pairLim = newLimiter(2, 2)
	})

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Use invalid pairing tokens so they're never consumed
	makeAccept := func(token string, xff ...string) int {
		req, err := http.NewRequest("POST", httpSrv.URL+"/v1/pairing/"+token, strings.NewReader(`{"name":"acceptor","scopes":["messages"]}`))
		if err != nil {
			t.Fatal(err)
		}
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

	// Client X: XFF [203.0.113.70, 127.0.0.2] → clientIP 203.0.113.70
	xffX := []string{"203.0.113.70, 127.0.0.2"}
	if status := makeAccept("pair_nonexistent_token_1", xffX...); status != 404 {
		t.Errorf("client X req 1: got %d, want 404 (token doesn't exist)", status)
	}
	if status := makeAccept("pair_nonexistent_token_2", xffX...); status != 404 {
		t.Errorf("client X req 2: got %d, want 404 (token doesn't exist)", status)
	}

	// Client Y: XFF [203.0.113.71, 127.0.0.2] → clientIP 203.0.113.71 (different bucket)
	xffY := []string{"203.0.113.71, 127.0.0.2"}
	if status := makeAccept("pair_nonexistent_token_3", xffY...); status != 404 {
		t.Errorf("client Y req 1: got %d, want 404 (different bucket, token doesn't exist)", status)
	}

	// Client X third request: should be rate limited before checking token existence
	if status := makeAccept("pair_nonexistent_token_4", xffX...); status != 429 {
		t.Errorf("client X req 3: got %d, want 429 (same clientIP exhausted)", status)
	}

	// Client Y second request: different clientIP, should still get 404
	if status := makeAccept("pair_nonexistent_token_5", xffY...); status != 404 {
		t.Errorf("client Y req 2: got %d, want 404 (different bucket, token doesn't exist)", status)
	}

	// Leftmost-keying case: spoofed leftmost entry doesn't change the key
	// Client Z: XFF [198.51.100.20, 203.0.113.72, 127.0.0.3]
	// Walk right-to-left: 127.0.0.3 (trusted), 203.0.113.72 (untrusted → use this)
	xffZ := []string{"198.51.100.20, 203.0.113.72, 127.0.0.3"}
	if status := makeAccept("pair_nonexistent_token_6", xffZ...); status != 404 {
		t.Errorf("client Z req 1 (leftmost ignored): got %d, want 404", status)
	}
	if status := makeAccept("pair_nonexistent_token_7", xffZ...); status != 404 {
		t.Errorf("client Z req 2: got %d, want 404", status)
	}

	// Client W: XFF [198.51.100.88, 203.0.113.72, 127.0.0.3]
	// Different leftmost, same rightmost untrusted → same key (203.0.113.72)
	xffW := []string{"198.51.100.88, 203.0.113.72, 127.0.0.3"}
	if status := makeAccept("pair_nonexistent_token_8", xffW...); status != 429 {
		t.Errorf("client W req 1 (same rightmost untrusted): got %d, want 429 (proves leftmost is ignored)", status)
	}
}

// TestMalformedXFFSharedBucket verifies that requests with malformed XFF entries
// share a rate limit bucket, and that well-formed requests with different client IPs
// use separate buckets (proving clientIP is used, not r.RemoteAddr).
func TestMalformedXFFSharedBucket(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	frozenNow := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		TrustedProxies: []string{"127.0.0.0/8"},
		MsgPerMinute:   10,
		MsgBurst:       10,
		Clock:          clocktest.New(frozenNow),
	}
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}

	withLimiterOverride(t, srv, func(lm *LimiterManager, newLimiter func(int, int) *msg.Limiter) {
		lm.regLim = newLimiter(2, 2)
	})

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	makeReg := func(xff string) int {
		req, err := http.NewRequest("POST", httpSrv.URL+"/v1/register", strings.NewReader(`{"name":"test"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Control: well-formed XFF with two different client IPs → separate buckets
	if status := makeReg("198.51.100.10, 127.0.0.2"); status != 201 {
		t.Errorf("control 1: got %d, want 201", status)
	}
	if status := makeReg("198.51.100.99, 127.0.0.2"); status != 201 {
		t.Errorf("control 2: got %d, want 201 (different client IP, different bucket)", status)
	}

	// Malformed case: different left-hand IPs, same malformed entry, different trusted hop
	// All three stop at bad_entry and key to 127.0.0.3
	if status := makeReg("198.51.100.20, bad_entry, 127.0.0.3"); status != 201 {
		t.Errorf("malformed 1: got %d, want 201", status)
	}

	if status := makeReg("198.51.100.88, bad_entry, 127.0.0.3"); status != 201 {
		t.Errorf("malformed 2: got %d, want 201 (different left IP, same bucket)", status)
	}

	if status := makeReg("198.51.100.77, bad_entry, 127.0.0.3"); status != 429 {
		t.Errorf("malformed 3: got %d, want 429 (shared bucket exhausted)", status)
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

// TestNoRequestPanicAfterValidConfig verifies that request handling never panics
// after any valid configuration is accepted, including clientIP extraction with
// zoned and IPv4-mapped RemoteAddr via real handler invocation.
func TestNoRequestPanicAfterValidConfig(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tests := []struct {
		name       string
		proxies    []string
		remoteAddr string
		xff        string
		wantStatus int
	}{
		{
			name:       "empty config",
			proxies:    []string{},
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			wantStatus: 200,
		},
		{
			name:       "IPv4 trusted proxy",
			proxies:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.10",
			wantStatus: 200,
		},
		{
			name:       "IPv4-mapped trusted RemoteAddr with XFF",
			proxies:    []string{"::ffff:10.0.0.0/104"},
			remoteAddr: "[::ffff:10.0.0.5]:1",
			xff:        "203.0.113.9",
			wantStatus: 200,
		},
		{
			name:       "zoned IPv6 untrusted RemoteAddr",
			proxies:    []string{"10.0.0.0/8"},
			remoteAddr: "[fe80::1%eth0]:2",
			xff:        "203.0.113.11",
			wantStatus: 200,
		},
		{
			name:       "IPv6 trusted proxy",
			proxies:    []string{"2001:db8::/32"},
			remoteAddr: "[2001:db8::1]:1234",
			xff:        "203.0.113.12",
			wantStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TrustedProxies: tt.proxies,
			}
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				t.Fatal(err)
			}
			srv, err := New(st, cfg)
			if err != nil {
				t.Fatalf("New() with %v failed: %v", tt.proxies, err)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("request panicked with config %v, remoteAddr %q, XFF %q: %v", tt.proxies, tt.remoteAddr, tt.xff, r)
				}
			}()

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}

	// Direct clientIP unit tests with zoned and IPv4-mapped RemoteAddr
	t.Run("clientIP unit tests", func(t *testing.T) {
		// Parse ::ffff:10.0.0.0/104 -> should unmap to 10.0.0.0/8
		trustedNets, err := ParseTrustedProxies([]string{"::ffff:10.0.0.0/104"})
		if err != nil {
			t.Fatal(err)
		}
		if len(trustedNets) != 1 {
			t.Fatalf("expected 1 trusted network, got %d", len(trustedNets))
		}
		if trustedNets[0].String() != "10.0.0.0/8" {
			t.Errorf("mapped network = %q, want 10.0.0.0/8", trustedNets[0].String())
		}

		// IPv4-mapped RemoteAddr with XFF should return XFF (proves trust)
		ip := clientIP("[::ffff:10.0.0.5]:1", []string{"203.0.113.9"}, trustedNets)
		if ip != "203.0.113.9" {
			t.Errorf("clientIP([::ffff:10.0.0.5]:1, [203.0.113.9]) = %q, want 203.0.113.9 (proves mapped peer is trusted)", ip)
		}

		// Verify Contains works on unmapped IP
		testIP := net.ParseIP("10.0.0.5")
		if !trustedNets[0].Contains(testIP) {
			t.Errorf("trusted network %s should contain 10.0.0.5", trustedNets[0])
		}

		// Zoned RemoteAddr with untrusted IP should strip zone and use RemoteAddr
		zonedNets, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
		if err != nil {
			t.Fatal(err)
		}
		zonedIP := clientIP("[fe80::1%eth0]:2", []string{"203.0.113.10"}, zonedNets)
		if zonedIP != "fe80::1" {
			t.Errorf("clientIP([fe80::1%%eth0]:2) = %q, want fe80::1 (zone stripped, RemoteAddr used because untrusted)", zonedIP)
		}
	})
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
	srv := mustNew(t, st, Config{TrustedProxies: []string{" ", ""}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	t.Cleanup(srv.lim.Stop)
	logOutput := logs.String()
	if !strings.Contains(logOutput, "no trusted proxies configured") {
		t.Fatalf("api.New must warn when the parsed list is empty, got logs: %q", logOutput)
	}
	// Verify api.New emits exactly one warning (this test only calls api.New,
	// so it cannot detect a duplicate warning added elsewhere, e.g. in main.go).
	count := strings.Count(logOutput, "no trusted proxies configured")
	if count != 1 {
		t.Fatalf("api.New emitted %d warnings, want 1, in logs: %q", count, logOutput)
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
		{name: "ULA fd12:3456:789a::/48 allowed (default)", input: []string{"fd12:3456:789a::/48"}, allowBroad: false, wantNet: "fd12:3456:789a::/48"},
		{name: "ULA bare fd00::1 allowed (default)", input: []string{"fd00::1"}, allowBroad: false, wantNet: "fd00::1/128"},

		// Opt-in floor /29
		{name: "IPv6 /29 allowed (opt-in)", input: []string{"2a06:98c0::/29"}, allowBroad: true, wantNet: "2a06:98c0::/29"},
		{name: "IPv6 /32 allowed (opt-in)", input: []string{"2001:db8::/32"}, allowBroad: true},
		{name: "IPv6 /28 rejected (opt-in)", input: []string{"2a06:98c0::/28"}, allowBroad: true, wantError: "must be at least /29"},
		{name: "ULA fc00::/7 allowed (opt-in)", input: []string{"fc00::/7"}, allowBroad: true, wantNet: "fc00::/7"},
		{name: "ULA fc00::/6 rejected (opt-in, too broad)", input: []string{"fc00::/6"}, allowBroad: true, wantError: "must be at least "},
		{name: "ULA fd00::/8 allowed (opt-in)", input: []string{"fd00::/8"}, allowBroad: true, wantNet: "fd00::/8"},
		{name: "ULA fc00::1/7 (unmasked) allowed (opt-in)", input: []string{"fc00::1/7"}, allowBroad: true, wantNet: "fc00::/7"},
		{name: "ULA fdff::/7 (unmasked) allowed (opt-in)", input: []string{"fdff::/7"}, allowBroad: true, wantNet: "fc00::/7"},
		{name: "ULA fd12::1/7 (unmasked) rejected (default)", input: []string{"fd12::1/7"}, allowBroad: false, wantError: "must be at least /32"},
		{name: "ULA fd12::1/7 (unmasked) allowed (opt-in)", input: []string{"fd12::1/7"}, allowBroad: true, wantNet: "fc00::/7"},
		{name: "fe00::/7 (near ULA) rejected (opt-in)", input: []string{"fe00::/7"}, allowBroad: true, wantError: "must be at least /29"},
		{name: "fe80::/10 (link-local) rejected (opt-in)", input: []string{"fe80::/10"}, allowBroad: true, wantError: "must be at least /29"},
		{name: "2000::/3 rejected (opt-in)", input: []string{"2000::/3"}, allowBroad: true, wantError: "must be at least /29"},

		// Transition/translation prefixes rejected regardless of opt-in (#320)
		{name: "Teredo 2001::/32 rejected (default)", input: []string{"2001::/32"}, allowBroad: false, wantError: "overlaps Teredo prefix 2001::/32"},
		{name: "Teredo 2001::/32 rejected (opt-in)", input: []string{"2001::/32"}, allowBroad: true, wantError: "overlaps Teredo prefix 2001::/32"},
		{name: "Teredo /48 2001:0:4136::/48 rejected (default)", input: []string{"2001:0:4136::/48"}, allowBroad: false, wantError: "overlaps Teredo prefix 2001::/32"},
		{name: "Teredo /48 2001:0:4136::/48 rejected (opt-in)", input: []string{"2001:0:4136::/48"}, allowBroad: true, wantError: "overlaps Teredo prefix 2001::/32"},
		{name: "NAT64 64:ff9b::/96 rejected (default)", input: []string{"64:ff9b::/96"}, allowBroad: false, wantError: "overlaps NAT64 well-known prefix 64:ff9b::/96"},
		{name: "NAT64 64:ff9b::/96 rejected (opt-in)", input: []string{"64:ff9b::/96"}, allowBroad: true, wantError: "overlaps NAT64 well-known prefix 64:ff9b::/96"},
		{name: "NAT64 host 64:ff9b::c000:201 rejected (default)", input: []string{"64:ff9b::c000:201"}, allowBroad: false, wantError: "overlaps NAT64 well-known prefix 64:ff9b::/96"},
		{name: "NAT64 host 64:ff9b::c000:201 rejected (opt-in)", input: []string{"64:ff9b::c000:201"}, allowBroad: true, wantError: "overlaps NAT64 well-known prefix 64:ff9b::/96"},
		{name: "NAT64 local 64:ff9b:1::/48 rejected (default)", input: []string{"64:ff9b:1::/48"}, allowBroad: false, wantError: "overlaps NAT64 local prefix 64:ff9b:1::/48"},
		{name: "NAT64 local 64:ff9b:1::/48 rejected (opt-in)", input: []string{"64:ff9b:1::/48"}, allowBroad: true, wantError: "overlaps NAT64 local prefix 64:ff9b:1::/48"},
		{name: "6to4 2002::/16 rejected (default)", input: []string{"2002::/16"}, allowBroad: false, wantError: "must be at least /32"},
		{name: "6to4 2002::/16 rejected (opt-in)", input: []string{"2002::/16"}, allowBroad: true, wantError: "must be at least /29"},
		{name: "6to4 /32 2002:c000::/32 rejected (default)", input: []string{"2002:c000::/32"}, allowBroad: false, wantError: "overlaps 6to4 prefix 2002::/16"},
		{name: "6to4 /32 2002:c000::/32 rejected (opt-in)", input: []string{"2002:c000::/32"}, allowBroad: true, wantError: "overlaps 6to4 prefix 2002::/16"},
		{name: "broad 2001::/29 contains Teredo (opt-in)", input: []string{"2001::/29"}, allowBroad: true, wantError: "overlaps Teredo"},
		{name: "broad 64:ff9b::/32 contains NAT64 (default)", input: []string{"64:ff9b::/32"}, allowBroad: false, wantError: "overlaps NAT64"},

		// Positive controls: normal prefixes near transition ranges still allowed
		{name: "2001:db8::/32 allowed (default)", input: []string{"2001:db8::/32"}, allowBroad: false, wantNet: "2001:db8::/32"},
		{name: "2001:db8::/32 allowed (opt-in)", input: []string{"2001:db8::/32"}, allowBroad: true, wantNet: "2001:db8::/32"},
		{name: "Google 2001:4860::/32 allowed (default)", input: []string{"2001:4860::/32"}, allowBroad: false, wantNet: "2001:4860::/32"},
		{name: "Google 2001:4860::/32 allowed (opt-in)", input: []string{"2001:4860::/32"}, allowBroad: true, wantNet: "2001:4860::/32"},

		// Still rejected even with opt-in
		{name: "::/0 rejected (opt-in)", input: []string{"::/0"}, allowBroad: true, wantError: "too broad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, _, err := ParseTrustedProxiesWithOpts(tt.input, tt.allowBroad)
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
	srv := mustNew(t, st, Config{
		TrustedProxies: []string{"2a06:98c0::/29", "fd00::/8"},
		AllowBroadIPv6: true,
		Logger:         slog.New(slog.NewTextHandler(&logs, nil)),
	})
	t.Cleanup(srv.lim.Stop)

	logOutput := logs.String()
	if !strings.Contains(logOutput, "PEERLINE_TRUSTED_PROXIES_ALLOW_BROAD is enabled") {
		t.Errorf("expected warning about ALLOW_BROAD, got logs: %q", logOutput)
	}
	if !strings.Contains(logOutput, "spoof X-Forwarded-For") {
		t.Errorf("expected security warning about spoofing, got logs: %q", logOutput)
	}
	if !strings.Contains(logOutput, "ULA (fc00::/7)") {
		t.Errorf("expected warning to mention ULA exemption, got logs: %q", logOutput)
	}
	// Check that the relaxed log line contains both entries (not just the "trusted proxy networks configured" line)
	lines := strings.Split(logOutput, "\n")
	var relaxedLine string
	for _, line := range lines {
		if strings.Contains(line, "relaxed=") {
			relaxedLine = line
			break
		}
	}
	if relaxedLine == "" {
		t.Errorf("expected log line with relaxed= attribute, got logs: %q", logOutput)
	} else {
		if !strings.Contains(relaxedLine, "2a06:98c0::/29") {
			t.Errorf("expected relaxed log line to list 2a06:98c0::/29, got: %q", relaxedLine)
		}
		if !strings.Contains(relaxedLine, "fd00::/8") {
			t.Errorf("expected relaxed log line to list fd00::/8, got: %q", relaxedLine)
		}
	}
}

func TestAllowBroadIPv6NoEntriesNeeded(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	srv := mustNew(t, st, Config{
		TrustedProxies: []string{"10.0.0.0/8", "2001:db8::/32"},
		AllowBroadIPv6: true,
		Logger:         slog.New(slog.NewTextHandler(&logs, nil)),
	})
	t.Cleanup(srv.lim.Stop)

	logOutput := logs.String()
	if !strings.Contains(logOutput, "no entries needed it") {
		t.Errorf("expected warning that no entries needed opt-in, got logs: %q", logOutput)
	}
	if strings.Contains(logOutput, "relaxed") {
		t.Errorf("expected no relaxed log when no entries needed it, got logs: %q", logOutput)
	}
}

func TestParseTrustedProxiesWithOptsRelaxedList(t *testing.T) {
	// Mix of entries: public /29, broad ULA, narrow /32, specific ULA
	input := []string{"2a06:98c0::/29", "fd00::/8", "2001:db8::/32", "fd12:3456:789a::/48"}
	nets, relaxed, err := ParseTrustedProxiesWithOpts(input, true)
	if err != nil {
		t.Fatalf("ParseTrustedProxiesWithOpts failed: %v", err)
	}
	if len(nets) != 4 {
		t.Errorf("got %d networks, want 4", len(nets))
	}
	// relaxed should contain exactly the entries that needed the opt-in:
	// 2a06:98c0::/29 (public /29, would be rejected at /32 floor)
	// fd00::/8 (broad ULA, would be rejected at /32 floor)
	// NOT 2001:db8::/32 (meets /32 floor without opt-in)
	// NOT fd12:3456:789a::/48 (ULA but meets /32 floor without opt-in)
	want := []string{"2a06:98c0::/29", "fd00::/8"}
	if len(relaxed) != len(want) {
		t.Errorf("relaxed list has %d entries, want %d: got %v, want %v", len(relaxed), len(want), relaxed, want)
	}
	for i, w := range want {
		if i >= len(relaxed) || relaxed[i] != w {
			t.Errorf("relaxed[%d] = %q, want %q (full list: %v)", i, safeIndex(relaxed, i), w, relaxed)
		}
	}
}

func safeIndex(s []string, i int) string {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return "<out of range>"
}

package api

import (
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

	// Test with /16 as well
	mapped16, err := ParseTrustedProxies([]string{"::ffff:192.168.0.0/112"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies(mapped /112) failed: %v", err)
	}
	native16, err := ParseTrustedProxies([]string{"192.168.0.0/16"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies(native /16) failed: %v", err)
	}

	if mapped16[0].String() != "192.168.0.0/16" {
		t.Errorf("mapped /16 network = %q, want 192.168.0.0/16", mapped16[0].String())
	}
	if native16[0].String() != "192.168.0.0/16" {
		t.Errorf("native /16 network = %q, want 192.168.0.0/16", native16[0].String())
	}

	// Verify ::1 is NOT trusted by ::ffff:0:0/104 (would be by /80)
	loopback := net.ParseIP("::1")
	if mapped[0].Contains(loopback) {
		t.Error("::ffff:10.0.0.0/104 should not trust ::1")
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
		resp, _ := http.DefaultClient.Do(req)
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
}

// TestUntrustedDirectPeer verifies that XFF is ignored when RemoteAddr is not trusted.
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
	makeReg := func(remoteOverride string, xff string) int {
		req, _ := http.NewRequest("POST", httpSrv.URL+"/v1/register", strings.NewReader(`{"name":"test"}`))
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		// Can't actually override RemoteAddr in test, but the server will see httptest's address
		// which is 127.0.0.1 (trusted). Let's use a different endpoint instead.
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Two registrations - keyed on RemoteAddr not XFF
	if status := makeReg("", "1.2.3.4"); status != 201 {
		t.Errorf("reg 1: got %d, want 201", status)
	}
	if status := makeReg("", "5.6.7.8"); status != 201 {
		t.Errorf("reg 2: got %d, want 201", status)
	}
	// Third should be rate limited - same RemoteAddr bucket
	if status := makeReg("", "9.10.11.12"); status != 429 {
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
		resp, _ := http.DefaultClient.Do(req)
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
// after any valid configuration is accepted.
func TestNoRequestPanicAfterValidConfig(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	validConfigs := [][]string{
		{},                          // empty
		{"10.0.0.0/8"},              // simple IPv4
		{"2001:db8::/32"},           // IPv6
		{"::ffff:10.0.0.0/104"},     // IPv4-mapped
		{"10.0.0.1", "192.168.1.1"}, // bare IPs
	}

	for _, proxies := range validConfigs {
		cfg := Config{
			TrustedProxies: proxies,
		}
		if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv, err := New(st, cfg)
		if err != nil {
			t.Fatalf("New() with %v failed: %v", proxies, err)
		}

		httpSrv := httptest.NewServer(srv.Handler())

		// Make a request and ensure no panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("request panicked with config %v: %v", proxies, r)
				}
			}()
			resp, _ := http.Get(httpSrv.URL + "/healthz")
			if resp != nil {
				resp.Body.Close()
			}
		}()

		httpSrv.Close()
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

package api

import (
	"encoding/json"
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
		},
		{
			name:  "IPv4-mapped IPv6 /112 (valid, unmaps to /16)",
			input: []string{"::ffff:192.168.0.0/112"},
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
	srv := New(st, cfg)

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

	// Request with malformed right-hand XFF entry
	// "203.0.113.12, malformed_entry" with trusted proxy "127.0.0.4"
	// Walk right-to-left: 127.0.0.4 (trusted), malformed_entry (invalid → stop, fall back to 127.0.0.4)
	// This uses the proxy's bucket (127.0.0.4)
	xffMalformed := []string{"203.0.113.12, malformed_entry", "127.0.0.4"}
	statusMalformed1, _ := makeRequest(xffMalformed...)
	if statusMalformed1 != 200 {
		t.Errorf("malformed XFF request 1: got status %d, want 200", statusMalformed1)
	}

	// Another request with same malformed pattern - uses same proxy bucket
	statusMalformed2, _ := makeRequest(xffMalformed...)
	if statusMalformed2 != 200 {
		t.Errorf("malformed XFF request 2: got status %d, want 200", statusMalformed2)
	}

	// Third request should exhaust the proxy bucket
	statusMalformed3, _ := makeRequest(xffMalformed...)
	if statusMalformed3 != 429 {
		t.Errorf("malformed XFF request 3: got status %d, want 429 (proxy bucket exhausted)", statusMalformed3)
	}
}

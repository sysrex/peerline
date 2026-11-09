package webhook

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPublicIPAndURL(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::ffff:127.0.0.1", "2001:db8::1", "64:ff9b::a00:1", "fec0::1", "::a00:1", "100::1", "2001:4860:4860::8888%eth0"} {
		if PublicIP(netip.MustParseAddr(ip)) {
			t.Fatal("allowed", ip)
		}
	}
	if !PublicIP(netip.MustParseAddr("8.8.8.8")) || !PublicIP(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("public address blocked")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("private endpoint reached")
	}))
	defer srv.Close()
	if _, err := NewSafeClient(false).Get(srv.URL); err == nil {
		t.Fatal("private target allowed")
	}
	c := NewSafeClient(true)
	if c.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect allowed")
	}
	for _, u := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?token=x", "https://example.com#fragment"} {
		if _, err := ValidateHTTPSURL(u); err == nil {
			t.Fatal("invalid URL accepted", u)
		}
	}
}

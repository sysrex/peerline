package webhook

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// NewSafeClient rejects redirects, proxies, userinfo, and non-public
// destinations at dial time so a DNS rebind cannot slip through.
// allowPrivate is the operator opt-in used by local MCP tests.
func NewSafeClient(allowPrivate bool) *http.Client {
	t := &http.Transport{
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
	}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid destination")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("destination resolution failed")
		}
		for _, ip := range ips {
			if !allowPrivate && !PublicIP(ip) {
				return nil, errors.New("nonpublic destination blocked")
			}
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		var conn net.Conn
		for _, ip := range ips {
			conn, err = d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("destination connection failed")
	}
	return &http.Client{
		Transport: httpsOnly{t},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect blocked")
		},
	}
}

type httpsOnly struct{ base http.RoundTripper }

func (t httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errors.New("HTTPS required")
	}
	return t.base.RoundTrip(r)
}

// PublicIP reports whether ip is a global unicast address we will dial.
func PublicIP(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:db8::/32", "2001::/23", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
	} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

// ValidateHTTPSURL rejects non-HTTPS URLs, userinfo, queries, and fragments.
func ValidateHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\"\\") {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

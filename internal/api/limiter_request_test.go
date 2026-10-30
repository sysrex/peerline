package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/store"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newLimitedServer(t *testing.T, trusted []string, clk *fakeClock) http.Handler {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := mustNew(t, st, Config{TrustedProxies: trusted, Now: clk.now})
	t.Cleanup(srv.lim.Stop)
	return srv.Handler()
}

func do(h http.Handler, method, path, remote string, xff ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.RemoteAddr = remote
	req.Header["X-Forwarded-For"] = xff
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// Each IP-keyed endpoint, its literal burst, and a request that charges it.
var ipKeyedEndpoints = []struct {
	name, method, path string
	burst              int
}{
	{"get", "GET", "/", 20},
	{"register", "POST", "/v1/register", 5},
	{"pairing lookup", "POST", "/v1/pairing/pair_nosuchtoken0123456789", 5},
}

func TestIPKeyingPerEndpoint(t *testing.T) {
	for _, ep := range ipKeyedEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			clk := &fakeClock{time.Unix(1000, 0)}
			h := newLimitedServer(t, []string{"10.0.0.0/8"}, clk)

			for i := 0; i < ep.burst; i++ {
				if rr := do(h, ep.method, ep.path, "10.0.0.1:1", "203.0.113.9"); rr.Code == 429 {
					t.Fatalf("request %d limited early", i+1)
				}
			}
			if rr := do(h, ep.method, ep.path, "10.0.0.1:1", "203.0.113.9"); rr.Code != 429 {
				t.Fatalf("client over burst: got %d, want 429", rr.Code)
			}
			if rr := do(h, ep.method, ep.path, "10.0.0.1:1", "198.51.100.7"); rr.Code == 429 {
				t.Fatal("different client behind the same proxy must have its own bucket")
			}

			// Untrusted peer: spoofed XFF must not mint fresh buckets.
			limited := false
			for i := 0; i < ep.burst+1; i++ {
				xff := "192.0.2." + string(rune('1'+i%9)) + string(rune('0'+i/9))
				limited = do(h, ep.method, ep.path, "8.8.8.8:1", xff).Code == 429
			}
			if !limited {
				t.Fatal("untrusted peer rotating XFF values must still be limited")
			}
		})
	}
}

// A malformed right-most entry must fall back to the trusted hop, so two
// clients differing only in the left-hand IP share one bucket (#61).
func TestMalformedXFFSharesTrustedHopBucket(t *testing.T) {
	clk := &fakeClock{time.Unix(1000, 0)}
	h := newLimitedServer(t, []string{"10.0.0.0/8"}, clk)

	for i := 0; i < 20; i++ {
		do(h, "GET", "/", "10.0.0.1:1", "203.0.113.12, not-an-ip", "10.0.0.2")
	}
	if rr := do(h, "GET", "/", "10.0.0.1:1", "198.51.100.7, not-an-ip", "10.0.0.2"); rr.Code != 429 {
		t.Fatalf("got %d, want 429: malformed entry must not be skipped", rr.Code)
	}
	if rr := do(h, "GET", "/", "10.0.0.1:1", "203.0.113.12", "10.0.0.2"); rr.Code != 200 {
		t.Fatalf("got %d, want 200: left-hand IP must not have been charged", rr.Code)
	}
}

func TestMappedPeerAgainstMappedTrustEntry(t *testing.T) {
	clk := &fakeClock{time.Unix(1000, 0)}
	h := newLimitedServer(t, []string{"::ffff:10.0.0.0/104"}, clk)
	for i := 0; i < 20; i++ {
		do(h, "GET", "/", "[::ffff:10.0.0.5]:1", "203.0.113.9")
	}
	if rr := do(h, "GET", "/", "[::ffff:10.0.0.5]:1", "203.0.113.9"); rr.Code != 429 {
		t.Fatalf("got %d, want 429", rr.Code)
	}
	if rr := do(h, "GET", "/", "[::ffff:10.0.0.5]:1", "203.0.113.10"); rr.Code != 200 {
		t.Fatalf("got %d, want 200: XFF must be honored from a mapped trusted peer", rr.Code)
	}
}

func TestLimiter429ContractAndRefill(t *testing.T) {
	clk := &fakeClock{time.Unix(1000, 0)}
	h := newLimitedServer(t, nil, clk)

	for i := 0; i < 20; i++ {
		if rr := do(h, "GET", "/", "1.2.3.4:1"); rr.Code != 200 {
			t.Fatalf("request %d: got %d", i+1, rr.Code)
		}
	}
	a := do(h, "GET", "/", "1.2.3.4:1")
	if a.Code != 429 || a.Header().Get("Retry-After") != "10" {
		t.Fatalf("got %d Retry-After=%q, want 429 and 10", a.Code, a.Header().Get("Retry-After"))
	}
	if b := do(h, "GET", "/", "1.2.3.4:1", "5.6.7.8"); b.Code != 429 {
		t.Fatal("untrusted peer's XFF must be ignored when no proxies are trusted")
	}

	clk.t = clk.t.Add(time.Second) // 60/min refills exactly one token
	if rr := do(h, "GET", "/", "1.2.3.4:1"); rr.Code != 200 {
		t.Fatalf("after refill: got %d, want 200", rr.Code)
	}
	if rr := do(h, "GET", "/", "1.2.3.4:1"); rr.Code != 429 {
		t.Fatalf("got %d, want 429 after the single refilled token", rr.Code)
	}
}

func TestZonedTrustedProxyRejectedAtStartup(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := New(st, Config{TrustedProxies: []string{"fe80::1%eth0"}}); err == nil {
		t.Fatal("zone-indexed trusted proxy must be rejected before serving requests")
	}
}

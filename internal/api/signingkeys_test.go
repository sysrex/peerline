package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/msg"
)

func TestSigningKeyPossessionReplayAndListing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, apiSrv, st := newServerWithAccess(t, Config{Clock: funcClock{fn: func() time.Time { return now }}})
	apiSrv.signingKeyLim = msg.NewLimiter(1000, 100, msg.WithClock(apiSrv.clk.Now))
	a := register(t, srv, "alice")
	b := register(t, srv, "bob")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := signingKeyBody(t, a.id, "k1", pub, priv, now.Unix(), now.Unix()+3600)
	resp, raw := a.do("PUT", "/v1/me/signing-keys", body, nil)
	want(t, resp, raw, 201)
	if strings.Contains(string(raw), base64.StdEncoding.EncodeToString(priv)) || strings.Contains(string(raw), "private") {
		t.Fatalf("response leaked private key: %s", raw)
	}
	resp, raw = a.do("PUT", "/v1/me/signing-keys", body, nil)
	want(t, resp, raw, 409)

	wrong := signingKeyBody(t, a.id, "k2", otherPub, priv, now.Unix(), 0)
	resp, raw = a.do("PUT", "/v1/me/signing-keys", wrong, nil)
	want(t, resp, raw, 400)

	resp, raw = b.do("GET", "/v1/peers/"+a.id+"/signing-keys", nil, nil)
	want(t, resp, raw, 404)

	pairUp(t, a, b, []string{"messages"}, nil, nil)
	resp, raw = b.do("GET", "/v1/peers/"+a.id+"/signing-keys", nil, nil)
	want(t, resp, raw, 200)
	if !strings.Contains(string(raw), `"kid":"k1"`) || strings.Contains(string(raw), "signature") {
		t.Fatalf("list: %s", raw)
	}

	ok, err := st.SigningKeyUsable(t.Context(), a.id, "k1", now.Unix()-1)
	if err != nil || ok {
		t.Fatalf("before window: %v %v", ok, err)
	}
	ok, err = st.SigningKeyUsable(t.Context(), a.id, "k1", now.Unix())
	if err != nil || !ok {
		t.Fatalf("in window: %v %v", ok, err)
	}
	resp, raw = a.do("DELETE", "/v1/me/signing-keys/k1", nil, nil)
	want(t, resp, raw, 204)
	ok, err = st.SigningKeyUsable(t.Context(), a.id, "k1", now.Unix())
	if err != nil || ok {
		t.Fatalf("revoked: %v %v", ok, err)
	}
	resp, raw = b.do("GET", "/v1/peers/"+a.id+"/signing-keys", nil, nil)
	want(t, resp, raw, 200)
	if strings.Contains(string(raw), `"kid":"k1"`) {
		t.Fatalf("revoked key still listed: %s", raw)
	}
}

func TestSigningKeyRegistrationRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, _, _ := newServerWithAccess(t, Config{Clock: funcClock{fn: func() time.Time { return now }}})
	a := register(t, srv, "alice")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := a.do("PUT", "/v1/me/signing-keys", signingKeyBody(t, a.id, "k1", pub, priv, now.Unix(), 0), nil)
	want(t, resp, raw, 201)
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw = a.do("PUT", "/v1/me/signing-keys", signingKeyBody(t, a.id, "k2", pub2, priv2, now.Unix(), 0), nil)
	want(t, resp, raw, 429)
}

func signingKeyBody(t *testing.T, peerID, kid string, pub ed25519.PublicKey, priv ed25519.PrivateKey, validFrom, validTo int64) map[string]any {
	t.Helper()
	sig := ed25519.Sign(priv, signingKeyRegistrationMessage(peerID, kid, validFrom))
	return map[string]any{
		"kid": kid, "pubkey": base64.StdEncoding.EncodeToString(pub),
		"signature":  base64.StdEncoding.EncodeToString(sig),
		"valid_from": validFrom, "valid_to": validTo,
	}
}

func TestSigningKeyOpenAPIFragment(t *testing.T) {
	spec := mustRead(t, "signingkeys_openapi.yaml")
	src := mustRead(t, "signingkeys.go")
	for _, path := range []string{"/v1/me/signing-keys", "/v1/peers/{peer_id}/signing-keys"} {
		if !strings.Contains(spec, path) || !strings.Contains(src, path) {
			t.Errorf("missing %s", path)
		}
	}
	if strings.Contains(spec, "private_key") {
		t.Fatal("spec mentions a private key")
	}
}

func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

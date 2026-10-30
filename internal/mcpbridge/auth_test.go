package mcpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOAuthIntrospectionAccountIsolation(t *testing.T) {
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	upstreamStatus := 0
	malformed := false
	claims := map[string]any{"active": true, "sub": "subject-a", "iss": "https://issuer.example", "aud": "https://mcp.example/mcp", "scope": "peerline:messages", "exp": time.Now().Add(time.Hour).Unix()}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "id" || secret != "secret" {
			t.Error("missing introspection credentials")
		}
		r.ParseForm()
		if r.Form.Get("token") != "access-token" {
			t.Error("missing token")
		}
		if upstreamStatus != 0 {
			w.WriteHeader(upstreamStatus)
			return
		}
		if malformed {
			w.Write([]byte(`not-json`))
			return
		}
		json.NewEncoder(w).Encode(claims)
	}))
	defer srv.Close()
	account := Account{ID: "a", Subject: "subject-a", PeerID: "peer-a", RelayURL: "https://relay.example", APIKeyEnv: "KEY_A", Peers: map[string]string{"bob": "peer-b"}}
	a, err := NewOAuthAuthenticator(OAuthConfig{ResourceURL: "https://mcp.example/mcp", IssuerURL: "https://issuer.example", IntrospectionURL: srv.URL, ClientIDEnv: "TEST_OAUTH_ID", ClientSecretEnv: "TEST_OAUTH_SECRET", Scopes: []string{"peerline:messages"}, Accounts: []Account{account}})
	if err != nil {
		t.Fatal(err)
	}
	a.client = srv.Client()
	req := httptest.NewRequest("POST", "https://mcp.example/mcp", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	got, err := a.Authenticate(req)
	if err != nil || got.ID != "a" {
		t.Fatalf("authenticate: %v", err)
	}
	if got.AccessToken != "access-token" {
		t.Fatal("missing transient token")
	}
	if ok, err := a.CheckAccess(context.Background(), account, "access-token"); !ok || err != nil {
		t.Fatal("valid subscription denied")
	}
	for _, field := range []string{"id", "subject", "relay", "peer", "key"} {
		different := cloneAccount(account)
		switch field {
		case "id":
			different.ID = "other"
		case "subject":
			different.Subject = "other"
		case "relay":
			different.RelayURL = "https://other.example"
		case "peer":
			different.PeerID = "other"
		case "key":
			different.APIKeyEnv = "OTHER_KEY"
		}
		if ok, err := a.CheckAccess(context.Background(), different, "access-token"); ok || err != nil {
			t.Fatal("cross-account access accepted", field)
		}
	}
	claims["active"] = false
	if ok, err := a.CheckAccess(context.Background(), account, "access-token"); ok || err != nil {
		t.Fatal("revoked subscription accepted")
	}
	claims["active"] = true
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	if ok, err := a.CheckAccess(context.Background(), account, "access-token"); ok || err != nil {
		t.Fatal("expired subscription accepted")
	}
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	if got.AccessTokenExpiresAt.Unix() != claims["exp"].(int64) {
		t.Fatal("missing access token expiry")
	}
	for _, status := range []int{400, 401, 403, 404, 429, 500, 503} {
		upstreamStatus = status
		if ok, err := a.CheckAccess(context.Background(), account, "access-token"); ok || err == nil {
			t.Fatal("transient status treated as revocation", status)
		}
	}
	upstreamStatus = 0
	malformed = true
	if ok, err := a.CheckAccess(context.Background(), account, "access-token"); ok || err == nil {
		t.Fatal("malformed response treated as revocation")
	}
	malformed = false
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "access-token") {
		t.Fatal("token serialized")
	}
	got.Peers["bob"] = "evil"
	got, _ = a.Authenticate(req)
	if got.Peers["bob"] != "peer-b" {
		t.Fatal("mutable account binding")
	}
	if !strings.Contains(a.Challenge(), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatal(a.Challenge())
	}
	for _, tc := range []struct {
		field string
		bad   any
	}{{"active", false}, {"sub", "other"}, {"iss", "https://evil.example"}, {"aud", "https://other.example"}, {"scope", "other"}, {"exp", time.Now().Add(-time.Hour).Unix()}, {"nbf", time.Now().Add(time.Hour).Unix()}} {
		t.Run(tc.field, func(t *testing.T) {
			old := claims[tc.field]
			claims[tc.field] = tc.bad
			if _, err := a.Authenticate(req); err == nil {
				t.Fatal("accepted invalid claims")
			}
			if old == nil {
				delete(claims, tc.field)
			} else {
				claims[tc.field] = old
			}
		})
	}
	req.Header.Del("Authorization")
	req.Header.Set("X-Account-ID", "a")
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("trusted unverified identity header")
	}
}
func TestOAuthRejectsDuplicateBindings(t *testing.T) {
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	c := OAuthConfig{ResourceURL: "https://mcp.example/mcp", IssuerURL: "https://issuer.example", IntrospectionURL: "https://issuer.example/introspect", ClientIDEnv: "TEST_OAUTH_ID", ClientSecretEnv: "TEST_OAUTH_SECRET", Scopes: []string{"peerline:messages"}}
	a := Account{ID: "a", Subject: "s", PeerID: "p", RelayURL: "https://relay.example", APIKeyEnv: "KEY_A"}
	c.Accounts = []Account{a, a}
	if _, err := NewOAuthAuthenticator(c); err == nil {
		t.Fatal("duplicate accounts accepted")
	}
}

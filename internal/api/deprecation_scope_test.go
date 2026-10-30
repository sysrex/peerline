package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeprecationHeadersScopedToAcceptPath(t *testing.T) {
	h := deprecateQueryCodeOnAccept("@1", "<https://example.test>")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cases := []struct {
		target string
		want   bool
	}{
		{"/v1/invites/accept?code=inv_x", true},
		{"/v1/me?code=inv_x", false},
		{"/v1/inbox?code=inv_x", false},
		{"/v1/pairing/pair_x?code=inv_x", false},
		{"/v1/invites/accept/?code=inv_x", false},
		{"/V1/invites/accept?code=inv_x", false},
		{"/v1/invites/accept?code=", false},
		{"/v1/invites/accept?Code=inv_x", false},
		{"/v1/invites/accept", false},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", c.target, nil))
		got := rec.Header().Get("Deprecation") != "" || rec.Header().Get("Link") != ""
		if got != c.want {
			t.Errorf("%s: deprecation headers = %v, want %v", c.target, got, c.want)
		}
	}
}

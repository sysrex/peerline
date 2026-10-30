package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeysAndHash(t *testing.T) {
	k1, k2 := NewKey(), NewKey()
	if k1 == k2 || !strings.HasPrefix(k1, KeyPrefix) || len(k1) < 40 {
		t.Fatalf("bad keys %q %q", k1, k2)
	}
	if Hash(k1) == k1 || Hash(k1) != Hash(k1) {
		t.Fatal("hash")
	}
}

func TestMiddleware(t *testing.T) {
	key := NewKey()
	h := Middleware(func(_ context.Context, kh string) (string, error) {
		if kh == Hash(key) {
			return "p_1", nil
		}
		return "", context.Canceled
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(PeerID(r.Context()))) }))
	for tok, code := range map[string]int{"": 401, "Bearer nope": 401, "Bearer pl_x": 401, "Bearer " + key: 200, "bearer " + key: 200} {
		r := httptest.NewRequest("GET", "/", nil)
		if tok != "" {
			r.Header.Set("Authorization", tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != code {
			t.Errorf("%q: got %d want %d", tok, w.Code, code)
		}
	}
}

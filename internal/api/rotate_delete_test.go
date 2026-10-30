package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRotateKeyInvalidatesOldKeepsData(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	pairUp(t, a, b, []string{"messages", "bags:read"}, []string{"notes"}, nil)
	resp, body := a.do("PUT", "/v1/bags/notes", []byte("v1"), nil)
	want(t, resp, body, 201)

	oldKey := a.key
	resp, body = a.do("POST", "/v1/me/rotate-key", nil, nil)
	want(t, resp, body, 200)
	var out struct {
		APIKey string `json:"api_key"`
	}
	json.Unmarshal(body, &out)
	if out.APIKey == "" || out.APIKey == oldKey {
		t.Fatalf("bad new key %q", out.APIKey)
	}

	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 401)
	a.key = out.APIKey
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	resp, body = a.do("GET", "/v1/bags/notes", nil, nil)
	want(t, resp, body, 200)
	resp, body = a.do("GET", "/v1/grants", nil, nil)
	want(t, resp, body, 200)
	if string(body) == "" || !contains(body, b.id) {
		t.Fatalf("grants lost after rotation: %s", body)
	}
}

func TestDeleteMeCascades(t *testing.T) {
	srv := newServer(t, Config{})
	a, b := register(t, srv, "alice"), register(t, srv, "bob")
	pairUp(t, a, b, []string{"messages", "bags:read"}, []string{"notes"}, []string{"messages"})

	resp, body := a.do("DELETE", "/v1/me", nil, nil)
	want(t, resp, body, 204)
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 401)
	resp, body = b.do("GET", "/v1/grants", nil, nil)
	want(t, resp, body, 200)
	if contains(body, a.id) {
		t.Fatalf("grant to deleted peer survives: %s", body)
	}
	resp, body = b.do("POST", "/v1/peers/"+a.id+"/messages", map[string]any{"type": "note", "body": "x"}, nil)
	if resp.StatusCode == 201 {
		t.Fatalf("message to deleted peer accepted: %s", body)
	}
}

func contains(b []byte, s string) bool { return len(s) > 0 && strings.Contains(string(b), s) }

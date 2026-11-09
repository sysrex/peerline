package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sysrex/peerline/internal/clock/clocktest"
	"github.com/sysrex/peerline/internal/store"
)

func TestOpenAPIDocument(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("spec yaml: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	info, _ := doc["info"].(map[string]any)
	if info["title"] == "" || info["version"] == "" {
		t.Fatal("info.title and info.version are required")
	}
	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("paths is empty")
	}
	comps, _ := doc["components"].(map[string]any)
	schemes, _ := comps["securitySchemes"].(map[string]any)
	bearer, _ := schemes["bearerAuth"].(map[string]any)
	if bearer["scheme"] != "bearer" {
		t.Fatal("bearerAuth scheme missing")
	}
	raw := string(openAPISpec)
	if strings.Contains(raw, "pl_") && !strings.Contains(raw, "pl_EXAMPLE") {
		t.Fatal("spec mentions a pl_ key that is not the placeholder")
	}
	for _, bad := range []string{"sk_live", "whsec_", "BEGIN PRIVATE"} {
		if strings.Contains(raw, bad) {
			t.Fatalf("spec contains %q", bad)
		}
	}
	for path, item := range paths {
		ops, _ := item.(map[string]any)
		for method, op := range ops {
			switch method {
			case "get", "post", "put", "delete", "patch", "parameters":
			default:
				t.Fatalf("%s has unknown key %s", path, method)
			}
			if method == "parameters" {
				continue
			}
			body, _ := op.(map[string]any)
			if body["responses"] == nil {
				t.Fatalf("%s %s has no responses", method, path)
			}
			if scope, ok := body["x-peerline-scope"]; ok {
				switch scope {
				case "", "messages", "bags":
				default:
					t.Fatalf("%s %s has bad x-peerline-scope %v", method, path, scope)
				}
			}
		}
	}

	srv := newServer(t, Config{})
	resp, err := http.Get(srv.URL + "/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var served map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&served); err != nil {
		t.Fatal(err)
	}
	if served["openapi"] != "3.1.0" {
		t.Fatalf("served openapi = %v", served["openapi"])
	}
}

func TestOpenAPIDrift(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := mustNew(t, st, Config{})
	srv.SetClaimStore(st)
	t.Cleanup(srv.Stop)

	missing, extra := openAPIDrift(srv.routePatterns(), openAPIOperations(t))
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("drift missing=%v extra=%v", missing, extra)
	}

	// An undocumented route must fail the comparison.
	missing, _ = openAPIDrift(append(srv.routePatterns(), "GET /v1/not-a-route"), openAPIOperations(t))
	if len(missing) != 1 || missing[0] != "GET /v1/not-a-route" {
		t.Fatalf("undocumented route not reported: %v", missing)
	}
}

func openAPIOperations(t *testing.T) map[string]bool {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	out := map[string]bool{}
	for path, item := range paths {
		p := path
		if p == "/" {
			p = "/{$}"
		}
		ops := item.(map[string]any)
		for method := range ops {
			switch method {
			case "get", "post", "put", "delete", "patch":
				out[strings.ToUpper(method)+" "+p] = true
			}
		}
	}
	return out
}

func openAPIDrift(patterns []string, documented map[string]bool) (missing, extra []string) {
	seen := map[string]bool{}
	for _, pattern := range patterns {
		seen[pattern] = true
		if !documented[pattern] {
			missing = append(missing, pattern)
		}
	}
	for op := range documented {
		if !seen[op] {
			extra = append(extra, op)
		}
	}
	return missing, extra
}

func TestRotateKeyGraceWindow(t *testing.T) {
	clk := clocktest.New(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	srv := newServer(t, Config{Clock: clk})
	a := register(t, srv, "alice")
	oldKey := a.key

	resp, body := a.do("POST", "/v1/me/rotate-key", map[string]any{"grace_seconds": 60}, nil)
	want(t, resp, body, 200)
	var out struct {
		APIKey       string `json:"api_key"`
		GraceSeconds int    `json:"grace_seconds"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.APIKey == "" || out.APIKey == oldKey || strings.Contains(string(body), oldKey) {
		t.Fatal("response must contain only the new key")
	}
	if out.GraceSeconds != 60 {
		t.Fatalf("grace = %d", out.GraceSeconds)
	}

	newKey := out.APIKey
	a.key = oldKey
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)
	a.key = newKey
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)

	clk.Advance(61 * time.Second)
	a.key = oldKey
	resp, body = a.do("GET", "/v1/me", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("old key after grace: %d %s", resp.StatusCode, body)
	}
	a.key = newKey
	resp, body = a.do("GET", "/v1/me", nil, nil)
	want(t, resp, body, 200)

	resp, body = a.do("POST", "/v1/me/rotate-key", map[string]any{"grace_seconds": 3601}, nil)
	want(t, resp, body, 400)
}

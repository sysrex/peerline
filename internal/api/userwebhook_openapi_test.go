package api

import (
	"os"
	"strings"
	"testing"
)

// The full OpenAPI document and drift test live with #253. This fragment is the
// webhook contract that document has to absorb, and it must name the routes
// this binary actually registers.
func TestUserWebhookOpenAPIFragment(t *testing.T) {
	spec, err := os.ReadFile("userwebhook_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("userwebhook.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/me/webhook",
		"/v1/me/webhook/rotate-secret",
		"/v1/me/webhook/deliveries",
	} {
		if !strings.Contains(string(spec), path) {
			t.Errorf("spec missing %s", path)
		}
		if !strings.Contains(string(src), path) {
			t.Errorf("routes missing %s", path)
		}
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	raw, err := os.ReadFile("../../examples/mcp/config.json")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(string(raw))
	c, err := loadConfig(p)
	if err != nil || len(c.OAuth.Accounts) != 2 {
		t.Fatal(c, err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"scopes": ["peerline:messages"]`, `"scopes": ["admin"]`, 1),
		strings.Replace(string(raw), `https://mcp.example.com/mcp`, `https://mcp.example.com/not-mcp`, 1),
		strings.Replace(string(raw), `"accounts": [`, `"unknown": true, "accounts": [`, 1),
		string(raw) + " {}",
		string(raw) + strings.Repeat(" ", 1<<20),
	} {
		write(bad)
		if _, err := loadConfig(p); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

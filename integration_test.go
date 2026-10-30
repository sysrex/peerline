//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/api"
	"github.com/sysrex/peerline/internal/mailer"
	"github.com/sysrex/peerline/internal/store"
)

type testClient struct {
	t       *testing.T
	baseURL string
	key     string
	id      string
}

func (c *testClient) do(method, path string, body interface{}, headers map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		r = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		c.t.Fatal(err)
	}
	return resp, data
}

func (c *testClient) register(name string) {
	c.t.Helper()
	resp, data := c.do("POST", "/v1/register", map[string]string{"name": name}, nil)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("register failed: %d %s", resp.StatusCode, data)
	}
	var out struct {
		PeerID string `json:"peer_id"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		c.t.Fatal(err)
	}
	c.id = out.PeerID
	c.key = out.APIKey
}

func (c *testClient) sendMessage(recipient, msgType, body string, expectCode int) {
	c.t.Helper()
	resp, data := c.do("POST", fmt.Sprintf("/v1/peers/%s/messages", recipient), map[string]interface{}{
		"type": msgType,
		"body": body,
	}, nil)
	if resp.StatusCode != expectCode {
		c.t.Fatalf("sendMessage expected %d, got %d: %s", expectCode, resp.StatusCode, data)
	}
}

func (c *testClient) getMessages() []map[string]interface{} {
	c.t.Helper()
	resp, data := c.do("GET", "/v1/inbox", nil, nil)
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("getMessages failed: %d %s", resp.StatusCode, data)
	}
	var out struct {
		Messages []map[string]interface{} `json:"messages"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		c.t.Fatal(err)
	}
	return out.Messages
}

func (c *testClient) createInvite(scopes, bags []string, ttlSeconds int) string {
	c.t.Helper()
	req := map[string]interface{}{
		"scopes": scopes,
		"bags":   bags,
	}
	if ttlSeconds > 0 {
		req["ttl_seconds"] = ttlSeconds
	}
	resp, data := c.do("POST", "/v1/invites", req, nil)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("createInvite failed: %d %s", resp.StatusCode, data)
	}
	var out struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		c.t.Fatal(err)
	}
	return out.Code
}

func (c *testClient) acceptInvite(code string) {
	c.t.Helper()
	resp, data := c.do("POST", "/v1/invites/accept", map[string]string{"code": code}, nil)
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("acceptInvite failed: %d %s", resp.StatusCode, data)
	}
}

func TestIntegration_RegisterAndPair(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	bob := &testClient{t: t, baseURL: srv.URL}

	alice.register("alice")
	bob.register("bob")

	if alice.id == "" || alice.key == "" {
		t.Fatal("alice registration failed")
	}
	if bob.id == "" || bob.key == "" {
		t.Fatal("bob registration failed")
	}
	if alice.id == bob.id {
		t.Fatal("alice and bob got the same ID")
	}

	codeAlice := alice.createInvite([]string{"messages"}, []string{}, 0)
	if codeAlice == "" {
		t.Fatal("invite code empty")
	}

	bob.acceptInvite(codeAlice)

	codeBob := bob.createInvite([]string{"messages"}, []string{}, 0)
	alice.acceptInvite(codeBob)

	alice.sendMessage(bob.id, "test", "hello bob", http.StatusCreated)

	msgs := bob.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0]["type"] != "test" || msgs[0]["body"] != "hello bob" {
		t.Fatalf("unexpected message: %+v", msgs[0])
	}
}

func TestIntegration_ShareablePairingLinks(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	alice.register("alice")

	resp, data := alice.do("POST", "/v1/invites", map[string]interface{}{
		"scopes":           []string{"messages"},
		"bags":             []string{},
		"generate_pairing": true,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("shareable invite failed: %d %s", resp.StatusCode, data)
	}

	var out struct {
		PublicID   string `json:"public_id"`
		PairingURL string `json:"pairing_url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}

	if out.PublicID == "" {
		t.Fatal("shareable invite missing public_id")
	}
	if out.PairingURL == "" {
		t.Fatal("pairing_url is empty")
	}
	if !strings.Contains(out.PairingURL, "/v1/pairing/pair_") {
		t.Fatalf("pairing_url does not contain expected pattern: %q", out.PairingURL)
	}
}

func TestIntegration_MessageRoundtrip(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	bob := &testClient{t: t, baseURL: srv.URL}

	alice.register("alice")
	bob.register("bob")

	codeAB := alice.createInvite([]string{"messages"}, []string{}, 0)
	bob.acceptInvite(codeAB)

	codeBA := bob.createInvite([]string{"messages"}, []string{}, 0)
	alice.acceptInvite(codeBA)

	alice.sendMessage(bob.id, "ping", "message 1", http.StatusCreated)
	bob.sendMessage(alice.id, "pong", "message 2", http.StatusCreated)
	alice.sendMessage(bob.id, "ping", "message 3", http.StatusCreated)

	aliceMsgs := alice.getMessages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice expected 1 message, got %d", len(aliceMsgs))
	}
	if aliceMsgs[0]["type"] != "pong" || aliceMsgs[0]["body"] != "message 2" {
		t.Fatalf("alice unexpected message: %+v", aliceMsgs[0])
	}

	bobMsgs := bob.getMessages()
	if len(bobMsgs) != 2 {
		t.Fatalf("bob expected 2 messages, got %d", len(bobMsgs))
	}
	if bobMsgs[0]["body"] != "message 1" || bobMsgs[1]["body"] != "message 3" {
		t.Fatalf("bob unexpected messages: %+v, %+v", bobMsgs[0], bobMsgs[1])
	}
}

func TestIntegration_ExpiredInvite(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	bob := &testClient{t: t, baseURL: srv.URL}

	alice.register("alice")
	bob.register("bob")

	code := alice.createInvite([]string{"messages"}, []string{}, 1)

	time.Sleep(2 * time.Second)

	resp, _ := bob.do("POST", "/api/accept", map[string]string{"code": code}, nil)
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 404/400 for expired invite, got %d", resp.StatusCode)
	}
}

func TestIntegration_UnauthenticatedRequest(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	alice.register("alice")

	unauthClient := &testClient{t: t, baseURL: srv.URL, key: "", id: ""}

	resp, _ := unauthClient.do("GET", "/v1/inbox", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}

	resp, _ = unauthClient.do("POST", fmt.Sprintf("/v1/peers/%s/messages", alice.id), map[string]interface{}{
		"type": "test",
		"body": "unauthorized",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated send, got %d", resp.StatusCode)
	}
}

func TestIntegration_BadInviteCode(t *testing.T) {
	srv := setupTestServer(t)

	bob := &testClient{t: t, baseURL: srv.URL}
	bob.register("bob")

	resp, _ := bob.do("POST", "/v1/invites/accept", map[string]string{"code": "invalid-code-12345"}, nil)
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 404/400 for bad invite code, got %d", resp.StatusCode)
	}
}

func TestIntegration_MessageToNonExistentPeer(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	alice.register("alice")

	alice.sendMessage("nonexistent-peer-id", "test", "hello", http.StatusForbidden)
}

func TestIntegration_DoubleAcceptInvite(t *testing.T) {
	srv := setupTestServer(t)

	alice := &testClient{t: t, baseURL: srv.URL}
	bob := &testClient{t: t, baseURL: srv.URL}
	charlie := &testClient{t: t, baseURL: srv.URL}

	alice.register("alice")
	bob.register("bob")
	charlie.register("charlie")

	code := alice.createInvite([]string{"messages"}, []string{}, 0)

	bob.acceptInvite(code)

	resp, _ := charlie.do("POST", "/v1/invites/accept", map[string]string{"code": code}, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected failure on second invite accept, but got 200 OK")
	}
}

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := api.Config{
		RegisterToken:    "",
		Logger:           log,
		Mailer:           mailer.Log{Logger: log},
		PublicURL:        "http://localhost:8787",
		EmailPerHour:     20,
		NotifyPerHour:    20,
		TrustedProxies:   []string{},
		RetentionSeconds: 86400,
	}

	apiServer := api.New(st, cfg)
	srv := httptest.NewServer(apiServer.Handler())
	t.Cleanup(srv.Close)

	return srv
}

func TestMain(m *testing.M) {
	fmt.Println("Running integration tests against real server with temp SQLite database")
	os.Exit(m.Run())
}

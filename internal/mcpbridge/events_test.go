package mcpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type eventRelay struct {
	messages []Message
	allowed  bool
	calls    int
}

func (r *eventRelay) Inbox(_ context.Context, a Account, since int64, limit int) (InboxPage, error) {
	r.calls++
	p := InboxPage{NextSince: since}
	for _, m := range r.messages {
		if m.ID > since && m.To == a.PeerID && len(p.Messages) < limit {
			p.Messages = append(p.Messages, m)
			p.NextSince = m.ID
		}
	}
	return p, nil
}
func (r *eventRelay) Send(context.Context, Account, string, SendInput) (json.RawMessage, error) {
	panic("events must never send replies")
}
func (r *eventRelay) Grants(context.Context, Account) (json.RawMessage, error) { return nil, nil }
func (r *eventRelay) CanReceive(context.Context, Account, string) (bool, error) {
	return r.allowed, nil
}

type eventTransport func(*http.Request) (*http.Response, error)

func (f eventTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func eventAccount() Account {
	return Account{AccessToken: "fixture-token", AccessTokenExpiresAt: time.Now().Add(48 * time.Hour), ID: "account-a", Subject: "subject-a", RelayURL: "https://relay.example", PeerID: "peer-a", Peers: map[string]string{"sender": "peer-b"}}
}
func eventSecret() string {
	return "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
}
func eventRequest(secret string, ttl any) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"name": "message.created", "arguments": map[string]string{"sender": "peer-b"}, "delivery": map[string]string{"mode": "webhook", "url": "https://callback.example/events", "secret": secret}, "ttlMs": ttl, "cursor": nil})
	return b
}
func eventClient(t *testing.T, deliveries *[]string, status *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: eventTransport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		code := 200
		response := `{}`
		if v["type"] == "verification" {
			response = string(b)
		} else {
			*deliveries = append(*deliveries, r.Header.Get("webhook-id"))
			code = *status
			if r.Header.Get("webhook-signature") == "" {
				t.Error("missing signature")
			}
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}
}
func TestEventsDurabilityIsolationRetryAndRevoke(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	path := filepath.Join(t.TempDir(), "private", "events.db")
	e, err := NewEventEngine(path, []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	var deliveries []string
	status := 503
	e.client = eventClient(t, &deliveries, &status)
	now := time.Now()
	e.now = func() time.Time { return now }
	result, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil))
	if rpc != nil {
		t.Fatal(rpc)
	}
	id := result.(map[string]any)["id"]
	again, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil))
	if rpc != nil || again.(map[string]any)["id"] != id {
		t.Fatal("not idempotent")
	}
	wrong := a
	wrong.Subject = "someone-else"
	if _, rpc = e.Call(ctx, wrong, "events/list", nil); rpc == nil {
		t.Fatal("cross-account authorized")
	}
	relay.messages = []Message{{ID: 1, From: "peer-b", To: "peer-a", Body: "untrusted content", CreatedAt: now}}
	if err = e.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err = e.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 {
		t.Fatal(deliveries)
	}
	e.Close()
	e, err = NewEventEngine(path, []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	now = now.Add(time.Minute)
	e.now = func() time.Time { return now }
	status = 200
	e.client = eventClient(t, &deliveries, &status)
	if err = e.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 || deliveries[0] != deliveries[1] {
		t.Fatal("retry did not preserve event ID", deliveries)
	}
	relay.messages = append(relay.messages, Message{ID: 2, From: "peer-b", To: "peer-a", CreatedAt: now})
	if err = e.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	relay.allowed = false
	if err = e.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatal("delivered after revocation")
	}
}
func TestEventsTTLUnsubscribeAndSecret(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var deliveries []string
	status := 200
	e.client = eventClient(t, &deliveries, &status)
	now := time.Now()
	e.now = func() time.Time { return now }
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest("bad", nil)); rpc == nil {
		t.Fatal("accepted bad secret")
	}
	result, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), 1000))
	if rpc != nil {
		t.Fatal(rpc)
	}
	expires, err := time.Parse(time.RFC3339Nano, result.(map[string]any)["refreshBefore"].(string))
	if err != nil || expires.Sub(now) != time.Second {
		t.Fatal("ttl ignored")
	}
	relay.messages = []Message{{ID: 1, From: "peer-b", To: "peer-a", CreatedAt: now}}
	_ = e.PollOnce(ctx)
	now = now.Add(2 * time.Second)
	_ = e.PollOnce(ctx)
	if len(deliveries) != 0 {
		t.Fatal("delivery after expiry")
	}
	for i := 0; i < 2; i++ {
		if _, rpc = e.Call(ctx, a, "events/unsubscribe", eventRequest("", nil)); rpc != nil {
			t.Fatal(rpc)
		}
	}
}
func TestWebhookSignatureKnownVector(t *testing.T) {
	s := webhookSignature("whsec_"+base64.StdEncoding.EncodeToString([]byte("123456789012345678901234")), "evt_1", "1700000000", []byte(`{"ok":true}`))
	if s != "v1,uefHk6HKREUCozIi1oYC1MUb6iphQIBwTkn+nKVio3Q=" {
		t.Fatal("signature mismatch", s)
	}
	if _, err := signingKey("whsec_YQ=="); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEventsRotationAndDisconnectedPurge(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	path := filepath.Join(t.TempDir(), "private", "events.db")
	e, err := NewEventEngine(path, []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e.now = func() time.Time { return now }
	var signatures string
	e.client = &http.Client{Transport: eventTransport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		if v["type"] != "verification" {
			signatures = r.Header.Get("webhook-signature")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})}
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc != nil {
		t.Fatal(rpc)
	}
	secret2 := "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(secret2, nil)); rpc != nil {
		t.Fatal(rpc)
	}
	relay.messages = []Message{{ID: 1, From: "peer-b", To: a.PeerID, CreatedAt: now}}
	_ = e.PollOnce(ctx)
	_ = e.PollOnce(ctx)
	if len(strings.Fields(signatures)) != 2 {
		t.Fatal("rotation must dual-sign", signatures)
	}
	e.Close()
	e, err = NewEventEngine(path, nil, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	counts, err := e.Counts(ctx)
	if err != nil || counts.Messages != 0 || counts.Subscriptions != 0 {
		t.Fatal("disconnected scope retained", counts, err)
	}
}
func TestEventsFailedChallengeDoesNotPersist(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, &eventRelay{allowed: true}, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.client = &http.Client{Transport: eventTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"challenge":"wrong"}`)), Header: make(http.Header)}, nil
	})}
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc == nil || rpc.Code != -32015 {
		t.Fatal("challenge accepted", rpc)
	}
	c, err := e.Counts(ctx)
	if err != nil || c.Subscriptions != 0 {
		t.Fatal(c, err)
	}
}

type eventAuthorizer struct{}

func (eventAuthorizer) CheckAccess(context.Context, Account, string) (bool, error) { return true, nil }

func TestEvents410StopsLoadedBatch(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var deliveries []string
	status := 410
	e.client = eventClient(t, &deliveries, &status)
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc != nil {
		t.Fatal(rpc)
	}
	now := time.Now()
	for i := 1; i <= 3; i++ {
		relay.messages = append(relay.messages, Message{ID: int64(i), From: "peer-b", To: a.PeerID, CreatedAt: now})
	}
	_ = e.PollOnce(ctx)
	_ = e.PollOnce(ctx)
	if len(deliveries) != 1 {
		t.Fatal("sent after 410", deliveries)
	}
}

type mutableEventAuthorizer struct{ active bool }

func (a *mutableEventAuthorizer) CheckAccess(context.Context, Account, string) (bool, error) {
	return a.active, nil
}
func TestEventsOAuthRevocation(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	auth := &mutableEventAuthorizer{active: true}
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var deliveries []string
	status := 200
	e.client = eventClient(t, &deliveries, &status)
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc != nil {
		t.Fatal(rpc)
	}
	relay.messages = []Message{{ID: 1, From: "peer-b", To: a.PeerID, CreatedAt: time.Now()}}
	_ = e.PollOnce(ctx)
	auth.active = false
	_ = e.PollOnce(ctx)
	if len(deliveries) != 0 {
		t.Fatal("delivered revoked token")
	}
	counts, err := e.Counts(ctx)
	if err != nil || counts.Subscriptions != 0 {
		t.Fatal(counts, err)
	}
}
func TestEventsUnsubscribeRemovedPeer(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var deliveries []string
	status := 200
	e.client = eventClient(t, &deliveries, &status)
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc != nil {
		t.Fatal(rpc)
	}
	e.accounts[0].Peers = map[string]string{}
	if _, rpc := e.Call(ctx, a, "events/unsubscribe", eventRequest("", nil)); rpc != nil {
		t.Fatal(rpc)
	}
}

func TestEventsSpoolAndCursorAtomic(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true, messages: []Message{{ID: 1, From: "peer-b", To: a.PeerID, CreatedAt: time.Now()}, {ID: 2, From: "peer-b", To: a.PeerID, CreatedAt: time.Now()}}}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	_, err = e.db.Exec(`CREATE TRIGGER fail_second BEFORE INSERT ON messages WHEN NEW.id=2 BEGIN SELECT RAISE(ABORT,'fixture storage failure');END`)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.fetchAccount(ctx, a); err == nil {
		t.Fatal("expected storage failure")
	}
	counts, err := e.Counts(ctx)
	if err != nil || counts.Messages != 0 {
		t.Fatal("partial page committed", counts, err)
	}
	var cursors int
	_ = e.db.QueryRow("SELECT count(*) FROM cursors").Scan(&cursors)
	if cursors != 0 {
		t.Fatal("cursor advanced despite rollback")
	}
	_, _ = e.db.Exec("DROP TRIGGER fail_second")
	if err = e.fetchAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	counts, _ = e.Counts(ctx)
	if counts.Messages != 2 {
		t.Fatal("refetch lost message", counts)
	}
}

func TestEventsExpiredSubscriptionsDoNotExhaustQuota(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 32; i++ {
		_, err = e.db.Exec("INSERT INTO subscriptions(id,scope,sender,url,secret,old_secret,expires,auth_token) VALUES(?,?,?,?,?,'',?,?)", string(rune('a'+i)), eventScope(a), "peer-b", "https://old.example/", eventSecret(), time.Now().Add(-time.Hour).UnixMilli(), a.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
	}
	var deliveries []string
	status := 200
	e.client = eventClient(t, &deliveries, &status)
	if _, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil)); rpc != nil {
		t.Fatal("expired rows exhausted quota", rpc)
	}
	counts, err := e.Counts(ctx)
	if err != nil || counts.Subscriptions != 1 {
		t.Fatal(counts, err)
	}
}

type unavailableEventAuthorizer struct{}

func (unavailableEventAuthorizer) CheckAccess(context.Context, Account, string) (bool, error) {
	return false, errors.New("fixture authorization service unavailable")
}
func TestEventsIntrospectionOutageRetriesAndCapsTokenTTL(t *testing.T) {
	ctx := context.Background()
	a := eventAccount()
	now := time.Now()
	a.AccessTokenExpiresAt = now.Add(10 * time.Minute)
	relay := &eventRelay{allowed: true}
	e, err := NewEventEngine(filepath.Join(t.TempDir(), "private", "events.db"), []Account{a}, relay, eventAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.now = func() time.Time { return now }
	var deliveries []string
	status := 200
	e.client = eventClient(t, &deliveries, &status)
	result, rpc := e.Call(ctx, a, "events/subscribe", eventRequest(eventSecret(), nil))
	if rpc != nil {
		t.Fatal(rpc)
	}
	expires, err := time.Parse(time.RFC3339Nano, result.(map[string]any)["refreshBefore"].(string))
	if err != nil || !expires.Equal(now.Add(9*time.Minute)) {
		t.Fatal("subscription exceeds token renewal window", expires, err)
	}
	relay.messages = []Message{{ID: 1, From: "peer-b", To: a.PeerID, CreatedAt: now}}
	_ = e.PollOnce(ctx)
	e.authorizer = unavailableEventAuthorizer{}
	_ = e.PollOnce(ctx)
	counts, err := e.Counts(ctx)
	if err != nil || counts.Subscriptions != 1 || counts.Pending != 1 || len(deliveries) != 0 {
		t.Fatal("outage destroyed subscription", counts, deliveries, err)
	}
	e.authorizer = eventAuthorizer{}
	now = now.Add(time.Minute)
	_ = e.PollOnce(ctx)
	if len(deliveries) != 1 {
		t.Fatal("did not resume after introspection outage", deliveries)
	}
}

func TestEventOperationalStatusIsAggregateOnly(t *testing.T) {
	got := eventStatusLine(EventCounts{Messages: 3, Subscriptions: 1, Pending: 2, Retrying: 1, Failed: 4, Delivered: 5, Stopped: 6}, 2, false)
	want := "peerline events: poll_error=true poll_errors=2 state_error=false messages=3 subscriptions=1 pending=2 retrying=1 failed=4 delivered=5 stopped=6"
	if got != want {
		t.Fatalf("status mismatch: %q", got)
	}
}

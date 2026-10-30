package mcpbridge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventEngine retains inbox messages and retry state in an operator-private DB.
// Replay is not supported by the protocol. New subscriptions include retained
// local backlog (up to 24h), including messages fetched before subscription.
// Queue saturation applies backpressure: the inbox cursor is not advanced.
type EventEngine struct {
	mu         sync.Mutex
	pollMu     sync.Mutex
	locks      map[string]*sync.Mutex
	db         *sql.DB
	accounts   []Account
	relay      Relay
	authorizer EventAuthorizer
	client     *http.Client
	now        func() time.Time
	verified   map[string]time.Time
	failures   map[string]int
	nextPoll   map[string]time.Time
}

func NewEventEngine(path string, accounts []Account, relay Relay, authorizer EventAuthorizer) (*EventEngine, error) {
	if authorizer == nil {
		return nil, errors.New("event authorizer is required")
	}
	if path == "" || path == ":memory:" {
		return nil, errors.New("event state requires a private filesystem path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("event state directory must be mode 0700")
	}
	if st, err := os.Lstat(path); err == nil && (st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("event state file must be private and not a symlink")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(eventSchema); err != nil {
		db.Close()
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err = tx.Exec("CREATE TEMP TABLE connected_scopes(scope TEXT PRIMARY KEY)"); err == nil {
		for _, a := range accounts {
			_, err = tx.Exec("INSERT OR IGNORE INTO connected_scopes(scope) VALUES(?)", eventScope(a))
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		for _, table := range []string{"subscriptions", "deliveries", "messages", "cursors"} {
			_, err = tx.Exec("DELETE FROM " + table + " WHERE scope NOT IN(SELECT scope FROM connected_scopes)")
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		_, err = tx.Exec("DROP TABLE connected_scopes")
	}
	if err == nil {
		err = tx.Commit()
	} else {
		tx.Rollback()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &EventEngine{db: db, accounts: accounts, relay: relay, authorizer: authorizer, client: NewSafeHTTPClient(false), now: time.Now, locks: map[string]*sync.Mutex{}, verified: map[string]time.Time{}, failures: map[string]int{}, nextPoll: map[string]time.Time{}}, nil
}
func (e *EventEngine) Close() error { return e.db.Close() }
func eventScope(a Account) string   { return digest(a.ID, a.Subject, a.RelayURL, a.PeerID) }
func digest(parts ...string) string {
	b, _ := json.Marshal(parts)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func eventErr(code int, msg string) *RPCError { return &RPCError{Code: code, Message: msg} }

type eventParams struct {
	Name      string `json:"name"`
	Arguments struct {
		Sender string `json:"sender"`
	} `json:"arguments"`
	Delivery struct {
		Mode   string `json:"mode"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	} `json:"delivery"`
	TTL    json.RawMessage `json:"ttlMs"`
	Cursor json.RawMessage `json:"cursor"`
}

func (e *EventEngine) Call(ctx context.Context, a Account, method string, raw json.RawMessage) (any, *RPCError) {
	accessToken := a.AccessToken
	tokenExpiry := a.AccessTokenExpiresAt
	found := false
	for _, trusted := range e.accounts {
		if eventScope(trusted) == eventScope(a) {
			a = trusted
			found = true
			break
		}
	}
	if !found {
		return nil, eventErr(-32001, "Account unavailable")
	}
	lock := e.accountLock(eventScope(a))
	lock.Lock()
	defer lock.Unlock()
	if method == "events/list" {
		return map[string]any{"events": []any{map[string]any{"name": "message.created", "description": "New incoming Peerline message. Sender must be an operator-allowlisted peer ID. Includes retained local backlog (up to 24h); no protocol replay.", "delivery": []string{"webhook"}, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"sender": map[string]any{"type": "string"}}, "required": []string{"sender"}, "additionalProperties": false}, "payloadSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]string{"type": "integer"}, "from": map[string]string{"type": "string"}, "to": map[string]string{"type": "string"}, "type": map[string]string{"type": "string"}, "body": map[string]string{"type": "string"}, "created_at": map[string]string{"type": "string", "format": "date-time"}, "reply_to": map[string]string{"type": "integer"}}}}}}, nil
	}
	if method != "events/subscribe" && method != "events/unsubscribe" {
		return nil, eventErr(-32601, "Unknown event method")
	}
	var p eventParams
	if json.Unmarshal(raw, &p) != nil || p.Name != "message.created" || p.Delivery.Mode != "webhook" {
		return nil, eventErr(-32602, "Invalid event parameters")
	}
	var arg map[string]any
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(raw, &envelope)
	if json.Unmarshal(envelope["arguments"], &arg) != nil || len(arg) != 1 || p.Arguments.Sender == "" {
		return nil, eventErr(-32602, "Exactly one sender filter is required")
	}
	allowed := false
	for _, peer := range a.Peers {
		if peer == p.Arguments.Sender {
			allowed = true
		}
	}
	if !allowed && method != "events/unsubscribe" {
		return nil, eventErr(-32602, "Sender is not allowlisted")
	}
	u, err := url.Parse(p.Delivery.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(p.Delivery.URL) > 4096 {
		return nil, eventErr(-32602, "Invalid HTTPS callback")
	}
	scope := eventScope(a)
	id := "sub_" + digest(scope, p.Delivery.URL, p.Name, p.Arguments.Sender)
	if method == "events/unsubscribe" {
		tx, err := e.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, eventErr(-32603, "State unavailable")
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, "DELETE FROM deliveries WHERE sub=?", id)
		if err == nil {
			_, err = tx.ExecContext(ctx, "DELETE FROM subscriptions WHERE id=? AND scope=?", id, scope)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			return nil, eventErr(-32603, "State unavailable")
		}
		return map[string]any{}, nil
	}
	if len(p.Cursor) > 0 && string(p.Cursor) != "null" {
		return nil, eventErr(-32602, "Replay is not supported")
	}
	if _, err := signingKey(p.Delivery.Secret); err != nil {
		return nil, eventErr(-32602, "Invalid webhook signing secret")
	}
	ttl := 24 * time.Hour
	if len(p.TTL) > 0 && string(p.TTL) != "null" {
		var ms int64
		if json.Unmarshal(p.TTL, &ms) != nil || ms <= 0 {
			return nil, eventErr(-32602, "ttlMs must be a positive integer or null")
		}
		if ms < int64(ttl/time.Millisecond) {
			ttl = time.Duration(ms) * time.Millisecond
		}
	}
	// Deliberately grant finite expiration even for ttlMs:null.
	authorized, authErr := e.authorizer.CheckAccess(ctx, a, accessToken)
	if accessToken == "" || !authorized || authErr != nil || !tokenExpiry.After(e.now()) {
		return nil, eventErr(-32001, "Account authorization unavailable")
	}
	ok, err := e.relay.CanReceive(ctx, a, p.Arguments.Sender)
	if err != nil || !ok {
		return nil, eventErr(-32001, "Message access unavailable")
	}
	// Expired callbacks are no longer authoritative and must not retain secrets.
	if _, err = e.db.ExecContext(ctx, "UPDATE deliveries SET status='stopped' WHERE scope=? AND status='pending' AND sub IN(SELECT id FROM subscriptions WHERE expires<=?)", scope, e.now().UnixMilli()); err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	if _, err = e.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE scope=? AND expires<=?", scope, e.now().UnixMilli()); err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	var deliveryCount, existing int
	if err = e.db.QueryRowContext(ctx, "SELECT count(*) FROM deliveries WHERE scope=?", scope).Scan(&deliveryCount); err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	if err = e.db.QueryRowContext(ctx, "SELECT count(*) FROM subscriptions WHERE id=?", id).Scan(&existing); err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	if existing == 0 && deliveryCount > 310000 {
		return nil, eventErr(-32000, "Delivery capacity reached")
	}
	var subscriptionCount int
	if err := e.db.QueryRowContext(ctx, "SELECT count(*) FROM subscriptions WHERE scope=? AND id<>?", scope, id).Scan(&subscriptionCount); err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	if subscriptionCount >= 32 {
		return nil, eventErr(-32000, "Subscription capacity reached")
	}
	cacheKey := digest(scope, p.Delivery.URL, p.Delivery.Secret)
	e.mu.Lock()
	verifiedUntil := e.verified[cacheKey]
	e.mu.Unlock()
	if verifiedUntil.Before(e.now()) {
		if err := e.verify(ctx, id, p.Delivery.URL, p.Delivery.Secret); err != nil {
			return nil, &RPCError{Code: -32015, Message: "Callback verification failed", Data: map[string]string{"reason": "challenge_failed"}}
		}
		e.mu.Lock()
		if len(e.verified) >= 256 {
			clear(e.verified)
		}
		e.verified[cacheKey] = e.now().Add(5 * time.Minute)
		e.mu.Unlock()
	}
	now := e.now()
	remaining := tokenExpiry.Sub(now)
	if remaining <= 0 {
		return nil, eventErr(-32001, "Access token expired during callback verification")
	}
	renewalMargin := min(time.Minute, remaining/10)
	ttl = min(ttl, remaining-renewalMargin)
	expires := now.Add(ttl)
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	defer tx.Rollback()
	var old string
	_ = tx.QueryRowContext(ctx, "SELECT secret FROM subscriptions WHERE id=?", id).Scan(&old)
	oldUntil := int64(0)
	if old != p.Delivery.Secret && old != "" {
		oldUntil = now.Add(5 * time.Minute).UnixMilli()
	} else {
		old = ""
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO subscriptions(id,scope,sender,url,secret,old_secret,old_until,expires,auth_token) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,old_secret=CASE WHEN subscriptions.secret=excluded.secret THEN subscriptions.old_secret ELSE excluded.old_secret END,old_until=CASE WHEN subscriptions.secret=excluded.secret THEN subscriptions.old_until ELSE excluded.old_until END,expires=excluded.expires,auth_token=excluded.auth_token`, id, scope, p.Arguments.Sender, p.Delivery.URL, p.Delivery.Secret, old, oldUntil, expires.UnixMilli(), accessToken)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO deliveries(sub,scope,message_id) SELECT ?,scope,id FROM messages WHERE scope=? AND sender=? AND stored>?`, id, scope, p.Arguments.Sender, now.Add(-24*time.Hour).UnixMilli())
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE deliveries SET status='pending',attempts=0,next_attempt=0 WHERE sub=? AND status='stopped' AND message_id IN(SELECT id FROM messages WHERE scope=? AND stored>?)", id, scope, now.Add(-24*time.Hour).UnixMilli())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return nil, eventErr(-32603, "State unavailable")
	}
	return map[string]any{"id": id, "refreshBefore": expires.UTC().Format(time.RFC3339Nano), "cursor": nil, "truncated": false}, nil
}

func (e *EventEngine) accountLock(scope string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.locks[scope] == nil {
		e.locks[scope] = &sync.Mutex{}
	}
	return e.locks[scope]
}

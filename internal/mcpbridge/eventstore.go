package mcpbridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

const eventSchema = `PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS cursors(scope TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,scope TEXT NOT NULL,sender TEXT NOT NULL,url TEXT NOT NULL,secret TEXT NOT NULL,old_secret TEXT NOT NULL DEFAULT '',old_until INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL,auth_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(scope TEXT NOT NULL,id INTEGER NOT NULL,sender TEXT NOT NULL,body BLOB NOT NULL,stored INTEGER NOT NULL,PRIMARY KEY(scope,id));
CREATE TABLE IF NOT EXISTS deliveries(sub TEXT NOT NULL,scope TEXT NOT NULL,message_id INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',PRIMARY KEY(sub,message_id));
CREATE INDEX IF NOT EXISTS delivery_due ON deliveries(scope,status,next_attempt);
`

// EventCounts contains operational counters only, never message bodies or secrets.
type EventCounts struct{ Messages, Pending, Retrying, Failed, Delivered, Stopped, Subscriptions int64 }

func (e *EventEngine) Counts(ctx context.Context) (EventCounts, error) {

	var c EventCounts
	for _, q := range []struct {
		query string
		dest  *int64
	}{{"SELECT count(*) FROM messages", &c.Messages}, {"SELECT count(*) FROM subscriptions", &c.Subscriptions}, {"SELECT count(*) FROM deliveries WHERE status='pending'", &c.Pending}, {"SELECT count(*) FROM deliveries WHERE status='failed'", &c.Failed}, {"SELECT count(*) FROM deliveries WHERE status='delivered'", &c.Delivered}, {"SELECT count(*) FROM deliveries WHERE status='stopped'", &c.Stopped}, {"SELECT count(*) FROM deliveries WHERE status='pending' AND attempts>0", &c.Retrying}} {
		if err := e.db.QueryRowContext(ctx, q.query).Scan(q.dest); err != nil {
			return c, err
		}
	}
	return c, nil
}
func (e *EventEngine) Run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	var nextLog time.Time
	pollErrors := 0
	for {
		if err := e.PollOnce(ctx); err != nil {
			pollErrors++
		}
		if ctx.Err() != nil {
			return
		}
		if !e.now().Before(nextLog) {
			statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			counts, err := e.Counts(statusCtx)
			cancel()
			// Only fixed labels, booleans and aggregate counters reach stderr. Never
			// log the underlying error, which could contain a URL or credential.
			log.Print(eventStatusLine(counts, pollErrors, err != nil))
			pollErrors = 0
			nextLog = e.now().Add(time.Minute)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (e *EventEngine) PollOnce(ctx context.Context) error {
	e.pollMu.Lock()
	defer e.pollMu.Unlock()
	var wg sync.WaitGroup
	results := make(chan error, len(e.accounts))
	slots := make(chan struct{}, 4)
	for _, a := range e.accounts {
		wg.Add(1)
		go func(a Account) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				results <- ctx.Err()
				return
			}
			defer func() { <-slots }()
			results <- e.pollAccount(ctx, a)
		}(a)
	}
	wg.Wait()
	close(results)
	var errs []error
	for err := range results {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (e *EventEngine) pollAccount(ctx context.Context, a Account) error {
	scope := eventScope(a)
	lock := e.accountLock(scope)
	lock.Lock()
	defer lock.Unlock()
	deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	deliveryErr := e.deliverAccount(deliveryCtx, a)
	cancel()
	e.mu.Lock()
	next := e.nextPoll[scope]
	e.mu.Unlock()
	if e.now().Before(next) {
		return deliveryErr
	}
	ac, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := e.fetchAccount(ac, a)
	cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.failures[scope]++
		delay := time.Second * time.Duration(1<<min(e.failures[scope], 8))
		var re *RelayError
		if errors.As(err, &re) && re.RetryAfter > 0 {
			delay = max(delay, time.Duration(min(re.RetryAfter, 86400))*time.Second)
		}
		e.nextPoll[scope] = e.now().Add(delay)
		return errors.Join(deliveryErr, fmt.Errorf("account inbox unavailable: %s", a.ID))
	}
	e.failures[scope] = 0
	delete(e.nextPoll, scope)
	return deliveryErr
}

func (e *EventEngine) fetchAccount(ctx context.Context, a Account) error {
	scope := eventScope(a)
	for page := 0; page < 2; page++ {
		var count int
		err := e.db.QueryRowContext(ctx, "SELECT count(*) FROM messages WHERE scope=?", scope).Scan(&count)
		if err != nil {
			return err
		}
		if count >= 10000 {
			return errors.New("event spool capacity reached")
		}
		var cursor int64
		err = e.db.QueryRowContext(ctx, "SELECT cursor FROM cursors WHERE scope=?", scope).Scan(&cursor)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		var deliveries int
		if err = e.db.QueryRowContext(ctx, "SELECT count(*) FROM deliveries WHERE scope=?", scope).Scan(&deliveries); err != nil {
			return err
		}
		limit := min(100, 10000-count, (320000-deliveries)/32)
		if limit <= 0 {
			return errors.New("delivery spool capacity reached")
		}
		p, err := e.relay.Inbox(ctx, a, cursor, limit)
		if err != nil {
			return err
		}
		if len(p.Messages) > limit {
			return errors.New("inbox page exceeds requested bound")
		}
		if p.NextSince < cursor {
			return errors.New("inbox cursor regressed")
		}
		// Reject malformed pages rather than advancing beyond unpersisted input.
		for _, m := range p.Messages {
			if m.ID <= cursor || m.ID > p.NextSince || m.To != a.PeerID {
				return errors.New("invalid inbox page")
			}
		}
		tx, err := e.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = func() error {
			defer tx.Rollback()
			for _, m := range p.Messages {
				b, err := json.Marshal(m)
				if err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO messages(scope,id,sender,body,stored) VALUES(?,?,?,?,?)", scope, m.ID, m.From, b, e.now().UnixMilli()); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO deliveries(sub,scope,message_id) SELECT id,scope,? FROM subscriptions WHERE scope=? AND sender=? AND expires>?`, m.ID, scope, m.From, e.now().UnixMilli()); err != nil {
					return err
				}
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO cursors(scope,cursor) VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET cursor=excluded.cursor", scope, p.NextSince); err != nil {
				return err
			}
			return tx.Commit()
		}()
		if err != nil {
			return err
		}
		if len(p.Messages) < limit || p.NextSince == cursor {
			break
		}
	}
	return nil
}

type queuedEvent struct {
	sub, url, secret, old, sender, token string
	oldUntil, expires, id                int64
	body                                 []byte
	attempts                             int
}

func (e *EventEngine) deliverAccount(ctx context.Context, a Account) error {
	scope := eventScope(a)
	now := e.now().UnixMilli()
	// Keep completed records for dedupe through the bounded local-backlog window.
	_, err := e.db.ExecContext(ctx, `UPDATE deliveries SET status='stopped' WHERE scope=? AND status='pending' AND sub IN(SELECT id FROM subscriptions WHERE expires<=?)`, scope, now)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE scope=? AND expires<=?", scope, now)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `DELETE FROM messages WHERE scope=? AND stored<? AND NOT EXISTS(SELECT 1 FROM deliveries WHERE deliveries.scope=messages.scope AND message_id=messages.id AND status='pending')`, scope, now-int64(24*time.Hour/time.Millisecond))
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `DELETE FROM deliveries WHERE scope=? AND NOT EXISTS(SELECT 1 FROM messages WHERE messages.scope=deliveries.scope AND messages.id=deliveries.message_id)`, scope)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `UPDATE subscriptions SET old_secret='',old_until=0 WHERE scope=? AND old_until<=?`, scope, now)
	if err != nil {
		return err
	}
	rows, err := e.db.QueryContext(ctx, `SELECT s.id,s.url,s.secret,s.old_secret,s.old_until,s.expires,m.id,m.sender,m.body,d.attempts,s.auth_token FROM deliveries d JOIN subscriptions s ON s.id=d.sub JOIN messages m ON m.scope=d.scope AND m.id=d.message_id WHERE d.scope=? AND d.status='pending' AND d.next_attempt<=? AND s.expires>? ORDER BY d.next_attempt,m.id LIMIT 16`, scope, now, now)
	if err != nil {
		return err
	}
	var queue []queuedEvent
	for rows.Next() {
		var q queuedEvent
		if err = rows.Scan(&q.sub, &q.url, &q.secret, &q.old, &q.oldUntil, &q.expires, &q.id, &q.sender, &q.body, &q.attempts, &q.token); err != nil {
			rows.Close()
			return err
		}
		queue = append(queue, q)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	type accessResult struct {
		ok  bool
		err error
	}
	access := map[string]accessResult{}
	tokenAccess := map[string]accessResult{}
	for _, q := range queue {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var currentExpiry int64
		if err = e.db.QueryRowContext(ctx, "SELECT expires FROM subscriptions WHERE id=? AND scope=?", q.sub, scope).Scan(&currentExpiry); err == sql.ErrNoRows {
			continue
		} else if err != nil {
			return err
		}
		if e.now().UnixMilli() >= currentExpiry {
			continue
		}
		if e.now().UnixMilli() >= q.expires {
			continue
		}
		tokenResult, checked := tokenAccess[q.token]
		if !checked {
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			tokenResult.ok, tokenResult.err = e.authorizer.CheckAccess(check, a, q.token)
			cancel()
			tokenAccess[q.token] = tokenResult
		}
		if tokenResult.err != nil {
			if err = e.retry(ctx, q, 0); err != nil {
				return err
			}
			continue
		}
		authorized := tokenResult.ok
		if !authorized {
			_, err = e.db.ExecContext(ctx, "UPDATE deliveries SET status='stopped' WHERE sub=?", q.sub)
			if err != nil {
				return err
			}
			_, err = e.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE id=?", q.sub)
			if err != nil {
				return err
			}
			continue
		}
		allowed := false
		for _, peer := range a.Peers {
			if peer == q.sender {
				allowed = true
			}
		}
		ar, cached := access[q.sender]
		if !cached {
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			ar.ok, ar.err = e.relay.CanReceive(check, a, q.sender)
			cancel()
			access[q.sender] = ar
		}
		ok, accessErr := ar.ok, ar.err
		if accessErr != nil {
			if err = e.retry(ctx, q, 0); err != nil {
				return err
			}
			continue
		}
		if !allowed || !ok {
			_, err = e.db.ExecContext(ctx, "UPDATE deliveries SET status='stopped' WHERE sub=?", q.sub)
			if err != nil {
				return err
			}
			_, err = e.db.ExecContext(ctx, "DELETE FROM subscriptions WHERE id=?", q.sub)
			if err != nil {
				return err
			}
			continue
		}
		var m Message
		if json.Unmarshal(q.body, &m) != nil {
			return errors.New("corrupt event state")
		}
		id := "evt_" + digest(scope, fmt.Sprint(q.id))
		body, _ := json.Marshal(map[string]any{"eventId": id, "name": "message.created", "timestamp": m.CreatedAt.UTC().Format(time.RFC3339Nano), "data": m, "cursor": nil})
		if e.now().UnixMilli() >= q.oldUntil {
			q.old = ""
		}
		deadline := time.UnixMilli(q.expires)
		dc, cancel := context.WithDeadline(ctx, deadline)
		status, _, postErr := e.post(dc, id, q.sub, q.url, q.secret, q.old, body)
		cancel()
		if postErr == nil && status >= 200 && status < 300 {
			_, err = e.db.ExecContext(ctx, "UPDATE deliveries SET status='delivered' WHERE sub=? AND message_id=?", q.sub, q.id)
		} else {
			err = e.retry(ctx, q, status)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (e *EventEngine) retry(ctx context.Context, q queuedEvent, status int) error {
	attempts := q.attempts + 1
	state := "pending"
	if attempts >= 8 || status == 410 || status == 413 || (status >= 400 && status < 500 && status != 408 && status != 429) {
		state = "failed"
	}
	if status == 410 {
		_, err := e.db.ExecContext(ctx, "UPDATE subscriptions SET expires=? WHERE id=?", e.now().UnixMilli(), q.sub)
		if err != nil {
			return err
		}
	}
	_, err := e.db.ExecContext(ctx, "UPDATE deliveries SET attempts=?,next_attempt=?,status=? WHERE sub=? AND message_id=?", attempts, e.now().Add(time.Second*time.Duration(1<<min(attempts, 8))).UnixMilli(), state, q.sub, q.id)
	return err
}

func eventStatusLine(c EventCounts, pollErrors int, stateError bool) string {
	return fmt.Sprintf("peerline events: poll_error=%t poll_errors=%d state_error=%t messages=%d subscriptions=%d pending=%d retrying=%d failed=%d delivered=%d stopped=%d", pollErrors > 0, pollErrors, stateError, c.Messages, c.Subscriptions, c.Pending, c.Retrying, c.Failed, c.Delivered, c.Stopped)
}

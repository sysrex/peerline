// Package store is the SQLite persistence layer (modernc.org/sqlite, no CGO).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct{ db *sql.DB }

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS peers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  notify_email TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS invites (
  code_hash TEXT PRIMARY KEY,
  from_peer TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  bags TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_by TEXT
);
-- grants are directional: grantee may act on owner's resources within scopes/bags.
CREATE TABLE IF NOT EXISTS grants (
  owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  grantee TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  scopes TEXT NOT NULL,
  bags TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner, grantee)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  recipient TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  body TEXT NOT NULL,
  reply_to INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages(recipient, id);
CREATE TABLE IF NOT EXISTS bags (
  owner TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  content BLOB NOT NULL,
  version INTEGER NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner, name)
);
`

// Open opens (and migrates) the database at path. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers, avoids SQLITE_BUSY; keeps :memory: on one conn
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate adds columns that CREATE TABLE IF NOT EXISTS will not backfill on
// databases created before they existed.
func migrate(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name = 'notify_email'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Plaintext: Peerline has to address the wake-up mail later. The address
	// is returned only to the peer who set it.
	_, err := db.Exec(`ALTER TABLE peers ADD COLUMN notify_email TEXT NOT NULL DEFAULT ''`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

// ---- peers ----

type Peer struct {
	ID        string    `json:"peer_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreatePeer(ctx context.Context, id, name, keyHash, notifyEmail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES(?,?,?,?,?)`, id, name, keyHash, now(), notifyEmail)
	return err
}

// NotifyEmail returns the peer's wake-up address, or "" when unset.
func (s *Store) NotifyEmail(ctx context.Context, id string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT notify_email FROM peers WHERE id=?`, id).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

// SetNotifyEmail sets or clears the wake-up address. email is "" to clear.
func (s *Store) SetNotifyEmail(ctx context.Context, id, email string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET notify_email=? WHERE id=?`, email, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PeerByKeyHash(ctx context.Context, keyHash string) (*Peer, error) {
	var p Peer
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM peers WHERE key_hash=?`, keyHash).Scan(&p.ID, &p.Name, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CreatedAt = time.Unix(ts, 0).UTC()
	return &p, nil
}

// PeerName returns the display name of peer id.
func (s *Store) PeerName(ctx context.Context, id string) (string, error) {
	var n string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM peers WHERE id=?`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return n, err
}

func (s *Store) PeerExists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM peers WHERE id=?`, id).Scan(&n)
	return n > 0, err
}

// Stats is the public, aggregate size of the relay. It has no peer ids, names,
// message bodies, bag contents, or invite codes.
type Stats struct {
	Peers    int64 `json:"peers"`
	Messages int64 `json:"messages"`
	Grants   int64 `json:"grants"`
	Bags     int64 `json:"bags"`
}

// Stats counts peers, messages, directional grants, and bags.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM peers),
			(SELECT COUNT(*) FROM messages),
			(SELECT COUNT(*) FROM grants),
			(SELECT COUNT(*) FROM bags)`).Scan(&st.Peers, &st.Messages, &st.Grants, &st.Bags)
	return st, err
}

// ---- invites & grants ----

type Grant struct {
	Owner   string   `json:"owner"`
	Grantee string   `json:"grantee"`
	Scopes  []string `json:"scopes"`
	Bags    []string `json:"bags"`
}

func join(v []string) string { return strings.Join(v, ",") }
func split(v string) []string {
	if v == "" {
		return []string{}
	}
	return strings.Split(v, ",")
}

func (s *Store) CreateInvite(ctx context.Context, codeHash, from string, scopes, bags []string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at) VALUES(?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix())
	return err
}

// AcceptInvite atomically consumes an invite and creates the inviter->accepter grant
// plus, optionally, a reciprocal accepter->inviter grant. Returns the inviter's grant.
func (s *Store) AcceptInvite(ctx context.Context, codeHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var from, scopes, bags string
	var exp int64
	var used sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT from_peer,scopes,bags,expires_at,used_by FROM invites WHERE code_hash=?`, codeHash).
		Scan(&from, &scopes, &bags, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < now() {
		return nil, ErrNotFound
	}
	if from == accepter {
		return nil, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invites SET used_by=? WHERE code_hash=?`, accepter, codeHash); err != nil {
		return nil, err
	}
	up := `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)
	       ON CONFLICT(owner,grantee) DO UPDATE SET scopes=excluded.scopes, bags=excluded.bags, created_at=excluded.created_at`
	if _, err := tx.ExecContext(ctx, up, from, accepter, scopes, bags, now()); err != nil {
		return nil, err
	}
	if len(backScopes) > 0 {
		if _, err := tx.ExecContext(ctx, up, accepter, from, join(backScopes), join(backBags), now()); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Grant{Owner: from, Grantee: accepter, Scopes: split(scopes), Bags: split(bags)}, nil
}

// GetGrant returns what grantee may do on owner's resources. ErrNotFound = deny.
func (s *Store) GetGrant(ctx context.Context, owner, grantee string) (*Grant, error) {
	var scopes, bags string
	err := s.db.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, owner, grantee).Scan(&scopes, &bags)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Grant{Owner: owner, Grantee: grantee, Scopes: split(scopes), Bags: split(bags)}, nil
}

// ListGrants returns grants where peer is owner or grantee.
func (s *Store) ListGrants(ctx context.Context, peer string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT owner,grantee,scopes,bags FROM grants WHERE owner=? OR grantee=? ORDER BY created_at`, peer, peer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		var sc, bg string
		if err := rows.Scan(&g.Owner, &g.Grantee, &sc, &bg); err != nil {
			return nil, err
		}
		g.Scopes, g.Bags = split(sc), split(bg)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant removes the grant owner->grantee.
func (s *Store) RevokeGrant(ctx context.Context, owner, grantee string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE owner=? AND grantee=?`, owner, grantee)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- messages ----

type Message struct {
	ID        int64     `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Type      string    `json:"type"`
	Body      string    `json:"body"`
	ReplyTo   *int64    `json:"reply_to,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) InsertMessage(ctx context.Context, m *Message) error {
	ts := now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO messages(sender,recipient,type,body,reply_to,created_at) VALUES(?,?,?,?,?,?)`,
		m.From, m.To, m.Type, m.Body, m.ReplyTo, ts)
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	m.CreatedAt = time.Unix(ts, 0).UTC()
	return nil
}

// MessageVisible reports whether message id was sent to or by peer (for reply_to checks).
func (s *Store) MessageVisible(ctx context.Context, id int64, peer string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM messages WHERE id=? AND (sender=? OR recipient=?)`, id, peer, peer).Scan(&n)
	return n > 0, err
}

func (s *Store) Inbox(ctx context.Context, recipient string, since int64, limit int) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,sender,recipient,type,body,reply_to,created_at FROM messages
		WHERE recipient=? AND id>? ORDER BY id LIMIT ?`, recipient, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		var rt sql.NullInt64
		var ts int64
		if err := rows.Scan(&m.ID, &m.From, &m.To, &m.Type, &m.Body, &rt, &ts); err != nil {
			return nil, err
		}
		if rt.Valid {
			v := rt.Int64
			m.ReplyTo = &v
		}
		m.CreatedAt = time.Unix(ts, 0).UTC()
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- bags ----

type Bag struct {
	Owner     string
	Name      string
	Content   []byte
	Version   int64
	UpdatedBy string
	UpdatedAt time.Time
}

func (s *Store) GetBag(ctx context.Context, owner, name string) (*Bag, error) {
	b := Bag{Owner: owner, Name: name}
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT content,version,updated_by,updated_at FROM bags WHERE owner=? AND name=?`, owner, name).
		Scan(&b.Content, &b.Version, &b.UpdatedBy, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.UpdatedAt = time.Unix(ts, 0).UTC()
	return &b, nil
}

// PutBag writes a bag. If ifVersion >= 0 it must match the current version
// (0 = must not exist yet); otherwise ErrConflict. ifVersion < 0 = unconditional.
func (s *Store) PutBag(ctx context.Context, owner, name string, content []byte, by string, ifVersion int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur int64
	err = tx.QueryRowContext(ctx, `SELECT version FROM bags WHERE owner=? AND name=?`, owner, name).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if ifVersion >= 0 && ifVersion != cur {
		return cur, ErrConflict
	}
	next := cur + 1
	_, err = tx.ExecContext(ctx, `INSERT INTO bags(owner,name,content,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(owner,name) DO UPDATE SET content=excluded.content, version=excluded.version,
		updated_by=excluded.updated_by, updated_at=excluded.updated_at`, owner, name, content, next, by, now())
	if err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

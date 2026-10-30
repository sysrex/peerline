// Package store is the SQLite persistence layer (modernc.org/sqlite, no CGO).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrTooManyInvites = errors.New("too many outstanding invites")

var memDBCounter uint64

type Store struct{ db *sql.DB }

const schema = `
PRAGMA journal_mode=WAL;
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
  used_by TEXT,
  pairing_token_hash TEXT
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
	dsn := buildDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers, avoids SQLITE_BUSY; keeps :memory: on one conn
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func buildDSN(path string) string {
	pragmas := "_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		// Use file-based shared-cache for :memory: so pragmas apply.
		// Generate unique name per Open to prevent test bleed.
		id := atomic.AddUint64(&memDBCounter, 1)
		return fmt.Sprintf("file:memdb-%d?mode=memory&cache=shared&%s", id, pragmas)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + pragmas
}

// migrate applies ordered, idempotent schema upgrades tracked by PRAGMA user_version.
func migrate(db *sql.DB) error {
	migrations := []func(*sql.Tx) error{
		migrateV1NotifyEmail,
		migrateV2PairingTokenHash,
		migrateV3InvitePublicID,
	}

	for i, mig := range migrations {
		target := i + 1
		if err := runMigrationStep(db, target, mig); err != nil {
			return err
		}
	}
	return nil
}

// runMigrationStep runs a single migration step in its own transaction.
func runMigrationStep(db *sql.DB, target int, mig func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration v%d: %w", target, err)
	}
	defer tx.Rollback()

	// Read user_version inside tx to ensure consistent view
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version in migration v%d: %w", target, err)
	}

	if version >= target {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d skip: %w", target, err)
		}
		return nil
	}

	// Run migration step on tx (not db) to avoid deadlock with MaxOpenConns=1
	if err := mig(tx); err != nil {
		return fmt.Errorf("migration v%d: %w", target, err)
	}

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, target)); err != nil {
		return fmt.Errorf("update user_version to %d: %w", target, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration v%d: %w", target, err)
	}
	return nil
}

// migrateV1NotifyEmail adds the notify_email column to peers.
func migrateV1NotifyEmail(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name = 'notify_email'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Plaintext: Peerline has to address the wake-up mail later. The address
	// is returned only to the peer who set it.
	_, err := tx.Exec(`ALTER TABLE peers ADD COLUMN notify_email TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateV2PairingTokenHash adds the pairing_token_hash column and unique index to invites.
// PR #11 already added both (without user_version tracking), so this checks before acting.
// Also normalizes the index to the partial form if it differs.
func migrateV2PairingTokenHash(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name = 'pairing_token_hash'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE invites ADD COLUMN pairing_token_hash TEXT`); err != nil {
			return err
		}
	}

	// Check if the index exists and verify its definition
	var indexSQL sql.NullString
	err := tx.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='invites_pairing_token_hash'`).Scan(&indexSQL)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	expectedSQL := "CREATE UNIQUE INDEX invites_pairing_token_hash ON invites(pairing_token_hash) WHERE pairing_token_hash IS NOT NULL"
	needsRecreate := false

	if indexSQL.Valid {
		// Normalize both SQLs for comparison (remove extra whitespace)
		normalize := func(s string) string {
			return strings.Join(strings.Fields(s), " ")
		}
		if normalize(indexSQL.String) != normalize(expectedSQL) {
			needsRecreate = true
		}
	} else {
		needsRecreate = true
	}

	if needsRecreate {
		// Drop existing index if present
		if indexSQL.Valid {
			if _, err := tx.Exec(`DROP INDEX IF EXISTS invites_pairing_token_hash`); err != nil {
				return err
			}
		}
		// Create the partial index
		if _, err := tx.Exec(expectedSQL); err != nil {
			return err
		}
	}

	return nil
}

// migrateV3InvitePublicID adds the public_id column to invites and backfills existing rows.
// public_id is a random 16-byte hex string used in the API to avoid exposing reusable ROWIDs.
func migrateV3InvitePublicID(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('invites') WHERE name = 'public_id'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE invites ADD COLUMN public_id TEXT`); err != nil {
			return err
		}
	}

	// Backfill existing rows with random public_id
	rows, err := tx.Query(`SELECT ROWID FROM invites WHERE public_id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rowids []int64
	for rows.Next() {
		var rowid int64
		if err := rows.Scan(&rowid); err != nil {
			return err
		}
		rowids = append(rowids, rowid)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Update each row with a unique public_id
	for _, rowid := range rowids {
		publicID, err := generatePublicID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE invites SET public_id = ? WHERE ROWID = ?`, publicID, rowid); err != nil {
			return err
		}
	}

	// Create unique index if it doesn't exist
	var hasIndex int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='invites_public_id'`).Scan(&hasIndex); err != nil {
		return err
	}
	if hasIndex == 0 {
		if _, err := tx.Exec(`CREATE UNIQUE INDEX invites_public_id ON invites(public_id) WHERE public_id IS NOT NULL`); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

// generatePublicID returns a random 16-byte hex string for invite public_id.
func generatePublicID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

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
	publicID, err := generatePublicID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,public_id) VALUES(?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), publicID)
	return err
}

func (s *Store) CreateInviteWithPairing(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time) error {
	publicID, err := generatePublicID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,pairing_token_hash,public_id) VALUES(?,?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), pairingTokenHash, publicID)
	return err
}

// CreateInviteAtomic checks the per-peer invite cap and creates an invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's ROWID on success.
// CreateInviteAtomic checks the per-peer invite cap and creates an invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's public_id on success.
func (s *Store) CreateInviteAtomic(ctx context.Context, codeHash, from string, scopes, bags []string, expires time.Time, cap int) (string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE from_peer=? AND used_by IS NULL AND expires_at>=?`, from, now()).Scan(&count)
	if err != nil {
		return "", err
	}
	if count >= cap {
		return "", ErrTooManyInvites
	}

	publicID, err := generatePublicID()
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,public_id) VALUES(?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), publicID)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return publicID, nil
}

// CreateInviteWithPairingAtomic checks the per-peer invite cap and creates a pairing invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's ROWID on success.
// CreateInviteWithPairingAtomic checks the per-peer invite cap and creates a pairing invite atomically within one transaction.
// Returns ErrTooManyInvites if the cap would be exceeded. Returns the invite's public_id on success.
func (s *Store) CreateInviteWithPairingAtomic(ctx context.Context, codeHash, pairingTokenHash, from string, scopes, bags []string, expires time.Time, cap int) (string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE from_peer=? AND used_by IS NULL AND expires_at>=?`, from, now()).Scan(&count)
	if err != nil {
		return "", err
	}
	if count >= cap {
		return "", ErrTooManyInvites
	}

	publicID, err := generatePublicID()
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash,from_peer,scopes,bags,expires_at,pairing_token_hash,public_id) VALUES(?,?,?,?,?,?,?)`,
		codeHash, from, join(scopes), join(bags), expires.Unix(), pairingTokenHash, publicID)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return publicID, nil
}

// InviteMetadata holds non-secret information about an invite for listing.
type InviteMetadata struct {
	PublicID      string    `json:"public_id"`
	Scopes        []string  `json:"scopes"`
	Bags          []string  `json:"bags"`
	ExpiresAt     time.Time `json:"expires_at"`
	Used          bool      `json:"used"`
	IsPairingLink bool      `json:"is_pairing_link"`
}

// CountOutstandingInvites returns the number of active (non-expired, unused) invites created by the peer.
func (s *Store) CountOutstandingInvites(ctx context.Context, peerID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM invites WHERE from_peer=? AND used_by IS NULL AND expires_at>=?`,
		peerID, now()).Scan(&count)
	return count, err
}

// ListInvitesByPeer returns non-secret metadata for active invites created by the peer.
// Results are ordered by creation (ROWID) and support pagination.
func (s *Store) ListInvitesByPeer(ctx context.Context, peerID string, limit, offset int) ([]InviteMetadata, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT COALESCE(public_id, ''), scopes, bags, expires_at, used_by IS NOT NULL, 
		        pairing_token_hash IS NOT NULL
		 FROM invites 
		 WHERE from_peer=? AND expires_at>=? AND public_id IS NOT NULL
		 ORDER BY ROWID
		 LIMIT ? OFFSET ?`,
		peerID, now(), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []InviteMetadata
	for rows.Next() {
		var im InviteMetadata
		var scopes, bags string
		var exp int64
		var used, hasPairingToken bool
		if err := rows.Scan(&im.PublicID, &scopes, &bags, &exp, &used, &hasPairingToken); err != nil {
			return nil, err
		}
		// Skip entries with empty public_id (defensive, should not happen after v3 migration)
		if im.PublicID == "" {
			continue
		}
		im.Scopes = split(scopes)
		im.Bags = split(bags)
		im.ExpiresAt = time.Unix(exp, 0).UTC()
		im.Used = used
		im.IsPairingLink = hasPairingToken
		invites = append(invites, im)
	}
	return invites, rows.Err()
}

// DeleteInvite removes an invite by ID if it belongs to the specified peer and is unused.
// DeleteInvite revokes an unused invite by public_id (owner-only).
// Returns ErrNotFound if the invite doesn't exist, already used, or doesn't belong to owner.
func (s *Store) DeleteInvite(ctx context.Context, publicID, ownerID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM invites WHERE public_id=? AND from_peer=? AND used_by IS NULL`,
		publicID, ownerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeExpiredInvites removes expired and unused invite rows.
// It does NOT delete used invites, since those may be useful for audit.
func (s *Store) PurgeExpiredInvites(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM invites WHERE expires_at<? AND used_by IS NULL`,
		now())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

type InviteInfo struct {
	FromPeer  string
	Scopes    []string
	Bags      []string
	ExpiresAt time.Time
}

// GetInviteByPairingToken retrieves invite details by pairing token (does not consume it).
func (s *Store) GetInviteByPairingToken(ctx context.Context, pairingTokenHash string) (*InviteInfo, error) {
	var from, scopes, bags string
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT from_peer,scopes,bags,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
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
	return &InviteInfo{
		FromPeer:  from,
		Scopes:    split(scopes),
		Bags:      split(bags),
		ExpiresAt: time.Unix(exp, 0).UTC(),
	}, nil
}

// AcceptInviteByPairingToken atomically consumes an invite via pairing token and creates grants.
func (s *Store) AcceptInviteByPairingToken(ctx context.Context, pairingTokenHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	// Read-only pre-check to avoid taking write lock for invalid tokens
	var codeHash string
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT code_hash,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
		Scan(&codeHash, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < now() {
		return nil, ErrNotFound
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	grant, err := acceptInviteInTx(ctx, tx, codeHash, accepter, backScopes, backBags)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// PairingTokenExists checks if a pairing token exists (is valid and not yet redeemed).
func (s *Store) PairingTokenExists(ctx context.Context, pairingTokenHash string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM invites WHERE pairing_token_hash=? AND used_by IS NULL AND expires_at >= ?`, pairingTokenHash, time.Now().Unix()).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// AcceptInvite atomically consumes an invite and creates the inviter->accepter grant
// plus, optionally, a reciprocal accepter->inviter grant. Returns the inviter's grant.
func (s *Store) AcceptInvite(ctx context.Context, codeHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	// Read-only pre-check to avoid taking write lock for invalid codes
	var exp int64
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT expires_at,used_by FROM invites WHERE code_hash=?`, codeHash).
		Scan(&exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used.Valid || exp < now() {
		return nil, ErrNotFound
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	grant, err := acceptInviteInTx(ctx, tx, codeHash, accepter, backScopes, backBags)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// RegisterAndAcceptByPairing atomically registers a new peer and accepts a pairing invite.
// Returns the grant from the inviter.
func (s *Store) RegisterAndAcceptByPairing(ctx context.Context, pairingTokenHash, peerID, name, keyHash, notifyEmail string, backScopes, backBags []string) (grant *Grant, err error) {
	// #14 fix: Read-only check before BeginTx to avoid taking write lock for invalid tokens
	var codeHash, fromPeer string
	var exp int64
	var used sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT code_hash,from_peer,expires_at,used_by FROM invites WHERE pairing_token_hash=?`, pairingTokenHash).
		Scan(&codeHash, &fromPeer, &exp, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ts := now()
	if used.Valid || exp < ts {
		return nil, ErrNotFound
	}

	// Now begin transaction for writes
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `INSERT INTO peers(id,name,key_hash,created_at,notify_email) VALUES(?,?,?,?,?)`,
		peerID, name, keyHash, ts, notifyEmail)
	if err != nil {
		return nil, err
	}

	grant, err = acceptInviteInTx(ctx, tx, codeHash, peerID, backScopes, backBags)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return grant, nil
}

// acceptInviteInTx is the shared helper that atomically consumes an invite using a guarded
// update and creates grants. Must be called within a transaction.
func acceptInviteInTx(ctx context.Context, tx *sql.Tx, codeHash, accepter string, backScopes, backBags []string) (*Grant, error) {
	var from, scopes, bags string
	err := tx.QueryRowContext(ctx, `SELECT from_peer,scopes,bags FROM invites WHERE code_hash=?`, codeHash).
		Scan(&from, &scopes, &bags)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if from == accepter {
		return nil, ErrConflict
	}

	ts := now()
	res, err := tx.ExecContext(ctx,
		`UPDATE invites SET used_by=? WHERE code_hash=? AND used_by IS NULL AND expires_at>=?`,
		accepter, codeHash, ts)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrNotFound
	}

	up := `INSERT INTO grants(owner,grantee,scopes,bags,created_at) VALUES(?,?,?,?,?)
	       ON CONFLICT(owner,grantee) DO UPDATE SET scopes=excluded.scopes, bags=excluded.bags, created_at=excluded.created_at`
	if _, err := tx.ExecContext(ctx, up, from, accepter, scopes, bags, ts); err != nil {
		return nil, err
	}
	if len(backScopes) > 0 {
		if _, err := tx.ExecContext(ctx, up, accepter, from, join(backScopes), join(backBags), ts); err != nil {
			return nil, err
		}
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

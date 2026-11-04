package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// Claim states.
const (
	ClaimOffered  = "offered"
	ClaimClaimed  = "claimed"
	ClaimActive   = "active"
	ClaimDeclined = "declined"
)

// confirmWindow is how long a claimed invite waits for its inviter, past expires_at.
const confirmWindow = 24 * time.Hour

// Claim is a confirm-mode invite as the claim handlers see it.
type Claim struct {
	PublicID, Inviter, State string
	Claimant, ClaimantName   string
	Scopes, Bags             []string
	BackScopes, BackBags     []string
	Nonce                    []byte

	// Replaces holds existing grants that would be overwritten, if any.
	Replaces *ReplacedGrants

	codeHash string
}

// ReplacedGrants describes grants that exist between inviter and claimant.
type ReplacedGrants struct {
	InviterToClaimant *Grant
	ClaimantToInviter *Grant
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// loadClaim reads the confirm-mode invite matching where (args are ?2...; ?1 is now). Rows that
// are no longer live (offered past expires_at, claimed past confirm_by) are ErrNotFound.
func (s *Store) loadClaim(ctx context.Context, q rowQuerier, where string, args ...any) (*Claim, error) {
	var c Claim
	var scopes, bags, bs, bb string
	var used bool
	var declined, confirmBy, expires int64
	now := s.nowUnix()
	err := q.QueryRowContext(ctx, `SELECT i.code_hash,i.public_id,i.from_peer,i.scopes,i.bags,i.back_scopes,i.back_bags,i.nonce,
		COALESCE(i.claimed_by,''),COALESCE(p.name,''),i.used_by IS NOT NULL,COALESCE(i.declined_at,0),COALESCE(i.confirm_by,0),i.expires_at
		FROM invites i LEFT JOIN peers p ON p.id=i.claimed_by WHERE i.require_confirm=1 AND `+where,
		append([]any{now}, args...)...).
		Scan(&c.codeHash, &c.PublicID, &c.Inviter, &scopes, &bags, &bs, &bb, &c.Nonce,
			&c.Claimant, &c.ClaimantName, &used, &declined, &confirmBy, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Scopes, c.Bags, c.BackScopes, c.BackBags = split(scopes), split(bags), split(bs), split(bb)
	switch {
	case declined > 0:
		c.State = ClaimDeclined
	case used:
		c.State = ClaimActive
	case c.Claimant != "":
		c.State = ClaimClaimed
		if confirmBy < now {
			return nil, ErrNotFound
		}
	default:
		c.State = ClaimOffered
		if expires < now {
			return nil, ErrNotFound
		}
	}

	// Check for existing grants between inviter and claimant only for claimed (not yet active) invites.
	// On an active invite, replaces would show the grants this confirm just wrote, breaking idempotency.
	if c.Claimant != "" && c.State == ClaimClaimed {
		var err error
		c.Replaces, err = s.loadExistingGrants(ctx, q, c.Inviter, c.Claimant)
		if err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// loadExistingGrants checks for grants in both directions between inviter and claimant.
// Returns an error if a database error occurs (not including ErrNoRows).
func (s *Store) loadExistingGrants(ctx context.Context, q rowQuerier, inviter, claimant string) (*ReplacedGrants, error) {
	var r ReplacedGrants

	// Check inviter -> claimant grant
	var sc1, bg1 string
	err := q.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, inviter, claimant).
		Scan(&sc1, &bg1)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		r.InviterToClaimant = &Grant{Owner: inviter, Grantee: claimant, Scopes: split(sc1), Bags: split(bg1)}
	}

	// Check claimant -> inviter grant
	var sc2, bg2 string
	err = q.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, claimant, inviter).
		Scan(&sc2, &bg2)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		r.ClaimantToInviter = &Grant{Owner: claimant, Grantee: inviter, Scopes: split(sc2), Bags: split(bg2)}
	}

	if r.InviterToClaimant == nil && r.ClaimantToInviter == nil {
		return nil, nil
	}
	return &r, nil
}

// ClaimByToken claims an offered invite for claimant, or returns the existing claim if
// claimant already holds it. Self-claim and any other state are ErrNotFound.
func (s *Store) ClaimByToken(ctx context.Context, tokenHash, claimant string, nonce []byte, backScopes, backBags []string) (*Claim, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := s.loadClaim(ctx, tx, `i.pairing_token_hash=?2 AND `+outstandingInvite, tokenHash)
	if err != nil {
		return nil, err
	}
	if c.Inviter == claimant || (c.Claimant != "" && c.Claimant != claimant) {
		return nil, ErrNotFound
	}
	if c.State == ClaimOffered {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM peers WHERE id=?`, claimant).Scan(&name); err != nil {
			return nil, err
		}
		confirmBy := time.Unix(s.nowUnix(), 0).Add(confirmWindow).Unix()
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET claimed_by=?,nonce=?,back_scopes=?,back_bags=?,confirm_by=?
			WHERE code_hash=? AND claimed_by IS NULL`,
			claimant, nonce, join(backScopes), join(backBags), confirmBy, c.codeHash); err != nil {
			return nil, err
		}
		c.State, c.Claimant, c.ClaimantName, c.Nonce, c.BackScopes, c.BackBags = ClaimClaimed, claimant, name, nonce, backScopes, backBags
	}
	return c, tx.Commit()
}

// ClaimStatus returns the invite only to its claimant.
func (s *Store) ClaimStatus(ctx context.Context, tokenHash, claimant string) (*Claim, error) {
	return s.loadClaim(ctx, s.db, `i.pairing_token_hash=?2 AND i.claimed_by=?3`, tokenHash, claimant)
}

// InviterView returns the invite only to its inviter, reading the invite and grants in one transaction.
func (s *Store) InviterView(ctx context.Context, publicID, inviter string) (*Claim, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, err := s.loadClaim(ctx, tx, `i.public_id=?2 AND i.from_peer=?3`, publicID, inviter)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CheckResult distinguishes check failures: code mismatch counts toward maxFails, digest mismatch does not.
type CheckResult int

const (
	CheckOK          CheckResult = iota // All checks passed
	CheckCodeFail                       // Code mismatch (counts toward auto-decline)
	CheckDigestStale                    // Digest mismatch (does not count)
	CheckPeerIDFail                     // peer_id mismatch (counts toward auto-decline)
)

// ConfirmClaim runs check on a claimed invite in one transaction. On CheckOK it writes the
// grants and activates it; on CheckCodeFail or CheckPeerIDFail it counts a failure and declines at maxFails.
// CheckDigestStale does not count toward failures.
// Idempotent: repeated confirm by the same inviter with matching peer_id returns the same state.
// The claimantPeerID is used for constant-time comparison on active replay.
func (s *Store) ConfirmClaim(ctx context.Context, publicID, inviter string, claimantPeerID string, maxFails int, check func(*Claim) (CheckResult, *Claim)) (string, *Claim, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()

	// First, try to load as outstanding (claimed but not confirmed/declined)
	c, err := s.loadClaim(ctx, tx, `i.public_id=?2 AND i.from_peer=?3 AND i.claimed_by IS NOT NULL AND `+outstandingInvite, publicID, inviter)

	// If not found as outstanding, check if it's already active (idempotent confirm)
	if errors.Is(err, ErrNotFound) {
		cActive, errActive := s.loadClaim(ctx, tx, `i.public_id=?2 AND i.from_peer=?3 AND i.used_by IS NOT NULL`, publicID, inviter)
		if errActive == nil && cActive.State == ClaimActive {
			// Already confirmed - check peer_id only (constant time), no digest or code
			// On replay, replaces would now contain the just-written grants, so the digest would always differ
			if subtle.ConstantTimeCompare([]byte(claimantPeerID), []byte(cActive.Claimant)) != 1 {
				// Different claimant - return same 404 as unknown invite
				return "", nil, ErrNotFound
			}
			// Same claimant - idempotent success
			return ClaimActive, nil, nil
		}
		return "", nil, err
	}
	if err != nil {
		return "", nil, err
	}

	now := s.nowUnix()
	result, freshClaim := check(c)
	if result == CheckOK {
		// State-guarded UPDATE: only activate if still outstanding
		res, err := tx.ExecContext(ctx, `UPDATE invites SET used_by=claimed_by 
			WHERE code_hash=? AND used_by IS NULL AND declined_at IS NULL AND confirm_by>=?`, c.codeHash, now)
		if err != nil {
			return "", nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", nil, err
		}
		if n != 1 {
			// Lost the race - invite was concurrently declined, expired, or already confirmed
			return "", nil, ErrNotFound
		}
		if err := writeGrantsInTx(ctx, tx, inviter, c.Claimant, join(c.Scopes), join(c.Bags), c.BackScopes, c.BackBags, now); err != nil {
			return "", nil, err
		}
		return ClaimActive, nil, tx.Commit()
	}
	// Digest mismatch returns stale state but does not count toward failures
	if result == CheckDigestStale {
		return ClaimClaimed, freshClaim, nil
	}
	// Code or peer_id mismatch counts toward auto-decline
	state := ClaimClaimed
	if _, err := tx.ExecContext(ctx, `UPDATE invites SET code_fails=code_fails+1,
		declined_at=CASE WHEN code_fails+1>=? THEN ? END WHERE code_hash=?`, maxFails, now, c.codeHash); err != nil {
		return "", nil, err
	}
	var declined bool
	if err := tx.QueryRowContext(ctx, `SELECT declined_at IS NOT NULL FROM invites WHERE code_hash=?`, c.codeHash).Scan(&declined); err != nil {
		return "", nil, err
	}
	if declined {
		state = ClaimDeclined
	}
	return state, nil, tx.Commit()
}

// DeclineClaim ends a claimed, unconfirmed invite for good.
// Idempotent: repeated decline by the same inviter returns success if already declined.
func (s *Store) DeclineClaim(ctx context.Context, publicID, inviter string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invites SET declined_at=? WHERE require_confirm=1 AND public_id=? AND from_peer=?
		AND claimed_by IS NOT NULL AND used_by IS NULL AND declined_at IS NULL`, s.nowUnix(), publicID, inviter)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Check if already declined (idempotent)
		var declined bool
		err := s.db.QueryRowContext(ctx, `SELECT declined_at IS NOT NULL FROM invites 
			WHERE require_confirm=1 AND public_id=? AND from_peer=? AND claimed_by IS NOT NULL`, publicID, inviter).Scan(&declined)
		if err == nil && declined {
			return nil
		}
		return ErrNotFound
	}
	return nil
}

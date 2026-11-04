package store

import (
	"context"
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
	now := s.now()
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

	// Check for existing grants between inviter and claimant (when claimant is known).
	if c.Claimant != "" {
		c.Replaces = s.loadExistingGrants(ctx, q, c.Inviter, c.Claimant)
	}

	return &c, nil
}

// loadExistingGrants checks for grants in both directions between inviter and claimant.
func (s *Store) loadExistingGrants(ctx context.Context, q rowQuerier, inviter, claimant string) *ReplacedGrants {
	var r ReplacedGrants

	// Check inviter -> claimant grant
	var sc1, bg1 string
	err := q.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, inviter, claimant).
		Scan(&sc1, &bg1)
	if err == nil {
		r.InviterToClaimant = &Grant{Owner: inviter, Grantee: claimant, Scopes: split(sc1), Bags: split(bg1)}
	}

	// Check claimant -> inviter grant
	var sc2, bg2 string
	err = q.QueryRowContext(ctx, `SELECT scopes,bags FROM grants WHERE owner=? AND grantee=?`, claimant, inviter).
		Scan(&sc2, &bg2)
	if err == nil {
		r.ClaimantToInviter = &Grant{Owner: claimant, Grantee: inviter, Scopes: split(sc2), Bags: split(bg2)}
	}

	if r.InviterToClaimant == nil && r.ClaimantToInviter == nil {
		return nil
	}
	return &r
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
		confirmBy := time.Unix(s.now(), 0).Add(confirmWindow).Unix()
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

// InviterView returns the invite only to its inviter.
func (s *Store) InviterView(ctx context.Context, publicID, inviter string) (*Claim, error) {
	return s.loadClaim(ctx, s.db, `i.public_id=?2 AND i.from_peer=?3`, publicID, inviter)
}

// ConfirmClaim runs check on a claimed invite in one transaction. On true it writes the
// grants and activates it; on false it counts a failure and declines at maxFails.
// Idempotent: repeated confirm by the same inviter with matching check returns the same state.
func (s *Store) ConfirmClaim(ctx context.Context, publicID, inviter string, maxFails int, check func(*Claim) bool) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// First, try to load as outstanding (claimed but not confirmed/declined)
	c, err := s.loadClaim(ctx, tx, `i.public_id=?2 AND i.from_peer=?3 AND i.claimed_by IS NOT NULL AND `+outstandingInvite, publicID, inviter)
	
	// If not found as outstanding, check if it's already active (idempotent confirm)
	if errors.Is(err, ErrNotFound) {
		cActive, errActive := s.loadClaim(ctx, tx, `i.public_id=?2 AND i.from_peer=?3 AND i.used_by IS NOT NULL`, publicID, inviter)
		if errActive == nil && cActive.State == ClaimActive {
			// Already confirmed - verify the check still passes (same claimant)
			if check(cActive) {
				return ClaimActive, nil
			}
			// Different claimant or digest - return 404
			return "", ErrNotFound
		}
		return "", err
	}
	if err != nil {
		return "", err
	}
	
	now := s.now()
	if check(c) {
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET used_by=claimed_by WHERE code_hash=?`, c.codeHash); err != nil {
			return "", err
		}
		if err := writeGrantsInTx(ctx, tx, inviter, c.Claimant, join(c.Scopes), join(c.Bags), c.BackScopes, c.BackBags, now); err != nil {
			return "", err
		}
		return ClaimActive, tx.Commit()
	}
	state := ClaimClaimed
	if _, err := tx.ExecContext(ctx, `UPDATE invites SET code_fails=code_fails+1,
		declined_at=CASE WHEN code_fails+1>=? THEN ? END WHERE code_hash=?`, maxFails, now, c.codeHash); err != nil {
		return "", err
	}
	var declined bool
	if err := tx.QueryRowContext(ctx, `SELECT declined_at IS NOT NULL FROM invites WHERE code_hash=?`, c.codeHash).Scan(&declined); err != nil {
		return "", err
	}
	if declined {
		state = ClaimDeclined
	}
	return state, tx.Commit()
}

// DeclineClaim ends a claimed, unconfirmed invite for good.
// Idempotent: repeated decline by the same inviter returns success if already declined.
func (s *Store) DeclineClaim(ctx context.Context, publicID, inviter string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invites SET declined_at=? WHERE require_confirm=1 AND public_id=? AND from_peer=?
		AND claimed_by IS NOT NULL AND used_by IS NULL AND declined_at IS NULL`, s.now(), publicID, inviter)
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

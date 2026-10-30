package store

import (
	"context"
	"sync"
	"time"
)

// keyIndex is an in-memory index of API key hashes to peer IDs.
// It is loaded once at startup and kept in sync with the peers table.
//
// Timing safety: The index is keyed ONLY by SHA-256(key), never by raw keys.
// Lookups are O(1) map accesses on the hash and never compare raw key bytes.
// An attacker controls the input being hashed and looked up, so learning anything
// about the hash prefix (via timing or otherwise) reveals no preimage. No raw keys
// are ever stored or compared in memory.
//
// Keys are added AFTER a successful commit/exec in CreatePeer and RegisterAndAcceptByPairing.
// Keys MUST be removed using the remove-before/after-commit pattern (fail closed):
//
//	s.keyIndexRemove(peerID)                     // before commit
//	if err := tx.Commit(); err != nil {
//	    return err
//	}
//	s.keyIndexRemove(peerID)                     // after commit
//
// Future handlers that delete peers (#19 DeletePeer, RotateKey) or purge (#3 v4)
// MUST follow this pattern to maintain consistency.
type keyIndex struct {
	mu      sync.RWMutex
	entries map[string]string // keyHash -> peerID
}

func newKeyIndex() *keyIndex {
	return &keyIndex{
		entries: make(map[string]string),
	}
}

// Lookup returns the peer ID for the given key hash, or empty string if not found.
func (idx *keyIndex) Lookup(keyHash string) (peerID string, ok bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	peerID, ok = idx.entries[keyHash]
	return peerID, ok
}

// add inserts or updates a key hash -> peer ID mapping.
func (idx *keyIndex) add(keyHash, peerID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[keyHash] = peerID
}

// remove deletes all key hashes for the given peer ID.
func (idx *keyIndex) remove(peerID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for keyHash, p := range idx.entries {
		if p == peerID {
			delete(idx.entries, keyHash)
		}
	}
}

// Len returns the number of entries in the index.
func (idx *keyIndex) Len() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

// clear removes all entries (for rebuilding).
func (idx *keyIndex) clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries = make(map[string]string)
}

// LoadKeyIndex loads all key hashes from the peers table into the index.
// Returns the number of keys loaded, the load duration, and any error.
// This must be called once at startup before the server begins serving requests.
func (s *Store) LoadKeyIndex(ctx context.Context) (n int, dur time.Duration, err error) {
	start := time.Now()

	rows, err := s.db.QueryContext(ctx, `SELECT key_hash, id FROM peers`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	s.keyIndex.clear()

	for rows.Next() {
		var keyHash, peerID string
		if err := rows.Scan(&keyHash, &peerID); err != nil {
			return 0, 0, err
		}
		s.keyIndex.add(keyHash, peerID)
		n++
	}

	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	s.keyIndexLoaded = true
	dur = time.Since(start)
	return n, dur, nil
}

// KeyIndexLookup returns the peer ID for the given key hash, or ("", false) if not found.
func (s *Store) KeyIndexLookup(keyHash string) (peerID string, ok bool) {
	return s.keyIndex.Lookup(keyHash)
}

// InvalidatePeerCache removes all key hashes for the given peer ID from the index.
// Must be called by future delete/purge/rotate handlers (#19, #3) after peer deletion.
func (s *Store) InvalidatePeerCache(peerID string) {
	s.keyIndex.remove(peerID)
}

// keyIndexRemove removes all key hashes for the given peer ID from the index.
// Must be called before AND after any commit that deletes a peer or rotates a key (fail closed).
// Required callers: DeletePeer (#19), RotateKey (#19), and provisional purge (#3 PR 2, v4).
// TODO(#3 PR 2): ensure v4 provisional purge uses this pattern.
func (s *Store) keyIndexRemove(peerID string) {
	s.keyIndex.remove(peerID)
}

// KeyIndexLen returns the number of entries in the key index.
func (s *Store) KeyIndexLen() int {
	return s.keyIndex.Len()
}

// KeyIndexLoaded returns true if LoadKeyIndex has been called.
func (s *Store) KeyIndexLoaded() bool {
	return s.keyIndexLoaded
}

// ReconcileKeyIndex compares the peer count with the index size and rebuilds if they differ.
// Returns true if a rebuild was performed.
func (s *Store) ReconcileKeyIndex(ctx context.Context) (rebuilt bool, err error) {
	var count int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers`).Scan(&count)
	if err != nil {
		return false, err
	}

	indexLen := s.KeyIndexLen()
	if count == indexLen {
		return false, nil
	}

	// Mismatch: rebuild
	_, _, err = s.LoadKeyIndex(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
}

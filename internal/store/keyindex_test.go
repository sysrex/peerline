package store

import (
	"context"
	"testing"

	"github.com/sysrex/peerline/internal/auth"
)

// TestKeyIndexRebuildOnStart verifies guarantee (2): the index is rebuilt from the DB on startup,
// and every existing key authenticates on its first request.
func TestKeyIndexRebuildOnStart(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"

	// Open store and create multiple peers
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	// Load initial empty index
	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Create peers
	peers := []struct {
		name   string
		id     string
		apiKey string
	}{}
	for _, name := range []string{"alice", "bob", "charlie"} {
		// Generate peer ID and API key
		id := auth.NewID()
		apiKey := auth.NewKey()
		keyHash := auth.Hash(apiKey)

		// Create peer in store
		if err := st.CreatePeer(context.Background(), id, name, keyHash, ""); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, struct {
			name   string
			id     string
			apiKey string
		}{name, id, apiKey})
	}

	// Close the store
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the store (index is empty until LoadKeyIndex is called)
	st, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Rebuild the index from the DB
	n, _, err := st.LoadKeyIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify index count equals peer count
	if n != len(peers) {
		t.Fatalf("index count: want %d, got %d", len(peers), n)
	}

	// Verify every existing key authenticates on its first request (lookup succeeds)
	for _, peer := range peers {
		keyHash := auth.Hash(peer.apiKey)
		peerID, ok := st.KeyIndexLookup(keyHash)
		if !ok {
			t.Fatalf("peer %s: key not in index after rebuild", peer.name)
		}
		if peerID != peer.id {
			t.Fatalf("peer %s: index has wrong peer ID: want %s, got %s", peer.name, peer.id, peerID)
		}

		// Verify store lookup also works
		p, err := st.PeerByKeyHash(context.Background(), keyHash)
		if err != nil {
			t.Fatalf("peer %s: PeerByKeyHash failed: %v", peer.name, err)
		}
		if p.ID != peer.id {
			t.Fatalf("peer %s: store returned wrong peer ID: want %s, got %s", peer.name, peer.id, p.ID)
		}
	}

	// Verify index size matches row count
	var rowCount int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM peers").Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if st.KeyIndexLen() != rowCount {
		t.Fatalf("index size: want %d (row count), got %d", rowCount, st.KeyIndexLen())
	}
}

// TestKeyIndexRevokeRemoval verifies guarantee (3): after a remove (delete or rotation),
// the old key gets 401 on the very next request, and the index no longer contains the hash.
func TestKeyIndexRevokeRemoval(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Create a peer
	peerID := auth.NewID()
	oldKey := auth.NewKey()
	oldHash := auth.Hash(oldKey)
	if err := st.CreatePeer(context.Background(), peerID, "alice", oldHash, ""); err != nil {
		t.Fatal(err)
	}

	// Verify the key is in the index
	indexPeerID, ok := st.KeyIndexLookup(oldHash)
	if !ok {
		t.Fatal("old key not in index after creation")
	}
	if indexPeerID != peerID {
		t.Fatalf("index peer ID mismatch: want %s, got %s", peerID, indexPeerID)
	}

	// Simulate deletion using the remove-before/after-commit pattern
	// (This is a test helper; real DeletePeer will follow this pattern per #19)
	st.keyIndexRemove(peerID) // before delete

	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("DELETE FROM peers WHERE id = ?", peerID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	st.keyIndexRemove(peerID) // after delete

	// Verify the old key is no longer in the index (immediate removal)
	_, ok = st.KeyIndexLookup(oldHash)
	if ok {
		t.Fatal("old key still in index after deletion")
	}

	// Verify the store lookup returns ErrNotFound (next request gets 401)
	_, err = st.PeerByKeyHash(context.Background(), oldHash)
	if err != ErrNotFound {
		t.Fatalf("store lookup after delete: want ErrNotFound, got %v", err)
	}

	// Simulate key rotation: create a new peer, then "rotate" by updating key_hash
	bobID := auth.NewID()
	oldKey2 := auth.NewKey()
	oldHash2 := auth.Hash(oldKey2)
	if err := st.CreatePeer(context.Background(), bobID, "bob", oldHash2, ""); err != nil {
		t.Fatal(err)
	}

	// Verify old key is in index
	if _, ok := st.KeyIndexLookup(oldHash2); !ok {
		t.Fatal("bob's key not in index after creation")
	}

	// Generate a new key and its hash
	newKey := auth.NewKey()
	newHash := auth.Hash(newKey)

	// Simulate rotation: remove old, update DB, add new (following the pattern)
	st.keyIndexRemove(bobID) // before commit

	tx, err = st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE peers SET key_hash = ? WHERE id = ?", newHash, bobID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	st.keyIndexRemove(bobID)        // after commit (clears old)
	st.keyIndex.add(newHash, bobID) // add new key

	// Verify old key is gone from index
	if _, ok := st.KeyIndexLookup(oldHash2); ok {
		t.Fatal("old key still in index after rotation")
	}

	// Verify old key gets 401 (ErrNotFound) on next request
	_, err = st.PeerByKeyHash(context.Background(), oldHash2)
	if err != ErrNotFound {
		t.Fatalf("old key after rotation: want ErrNotFound, got %v", err)
	}

	// Verify new key works
	newPeerID, ok := st.KeyIndexLookup(newHash)
	if !ok {
		t.Fatal("new key not in index after rotation")
	}
	if newPeerID != bobID {
		t.Fatalf("new key peer ID: want %s, got %s", bobID, newPeerID)
	}

	bobAfter, err := st.PeerByKeyHash(context.Background(), newHash)
	if err != nil {
		t.Fatalf("new key lookup failed: %v", err)
	}
	if bobAfter.ID != bobID {
		t.Fatalf("new key returned wrong peer: want %s, got %s", bobID, bobAfter.ID)
	}
}

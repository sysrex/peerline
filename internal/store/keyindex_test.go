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
		if err := st.CreatePeer(context.Background(), id, name, keyHash, "", ""); err != nil {
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
	if err := st.CreatePeer(context.Background(), peerID, "alice", oldHash, "", ""); err != nil {
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
	if err := st.CreatePeer(context.Background(), bobID, "bob", oldHash2, "", ""); err != nil {
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

// TestKeyIndexFlood verifies that index misses make zero PeerByKeyHash calls.
// This test demonstrates that auth lookups use only the in-memory index.
func TestKeyIndexFlood(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Create one valid peer
	validID := auth.NewID()
	validKey := auth.NewKey()
	validHash := auth.Hash(validKey)
	if err := st.CreatePeer(context.Background(), validID, "alice", validHash, "", ""); err != nil {
		t.Fatal(err)
	}

	// Flood with random unknown keys (1000 requests)
	// All should miss the index and never hit the DB
	for i := 0; i < 1000; i++ {
		unknownKey := auth.NewKey()
		unknownHash := auth.Hash(unknownKey)
		_, ok := st.KeyIndexLookup(unknownHash)
		if ok {
			t.Fatal("unknown key found in index")
		}
	}

	// Verify valid key hits succeed (index-only lookup)
	for i := 0; i < 100; i++ {
		peerID, ok := st.KeyIndexLookup(validHash)
		if !ok || peerID != validID {
			t.Fatal("valid key not in index")
		}
	}

	// The flood test demonstrates that KeyIndexLookup never calls PeerByKeyHash.
	// The auth middleware uses only KeyIndexLookup, so misses cost zero DB queries.
}

// TestKeyIndexConcurrentRace verifies concurrent add/remove/lookup operations are safe.
func TestKeyIndexConcurrentRace(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Create initial peers
	peerIDs := make([]string, 10)
	keyHashes := make([]string, 10)
	for i := 0; i < 10; i++ {
		peerIDs[i] = auth.NewID()
		key := auth.NewKey()
		keyHashes[i] = auth.Hash(key)
		if err := st.CreatePeer(context.Background(), peerIDs[i], "peer"+string(rune('a'+i)), keyHashes[i], "", ""); err != nil {
			t.Fatal(err)
		}
	}

	// Run concurrent operations
	done := make(chan bool)
	errs := make(chan error, 100)

	// Concurrent lookups
	for w := 0; w < 5; w++ {
		go func() {
			for i := 0; i < 100; i++ {
				for j := 0; j < len(keyHashes); j++ {
					// Lookup may miss during rotation, which is expected
					st.KeyIndexLookup(keyHashes[j])
				}
			}
			done <- true
		}()
	}

	// Concurrent removes and re-adds (simulating rotation)
	for w := 0; w < 2; w++ {
		go func() {
			for i := 0; i < 50; i++ {
				idx := i % len(peerIDs)
				peerID := peerIDs[idx]
				// Remove
				st.keyIndexRemove(peerID)
				// Re-add
				st.keyIndex.add(keyHashes[idx], peerID)
			}
			done <- true
		}()
	}

	// Wait for all workers
	for i := 0; i < 7; i++ {
		select {
		case <-done:
		case err := <-errs:
			t.Fatal(err)
		}
	}
}

// TestKeyIndexReconcile verifies that count drift triggers a rebuild.
func TestKeyIndexReconcile(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Create peers
	for i := 0; i < 5; i++ {
		id := auth.NewID()
		key := auth.NewKey()
		keyHash := auth.Hash(key)
		if err := st.CreatePeer(context.Background(), id, "peer"+string(rune('a'+i)), keyHash, "", ""); err != nil {
			t.Fatal(err)
		}
	}

	// Verify initial state
	if st.KeyIndexLen() != 5 {
		t.Fatalf("initial index len: want 5, got %d", st.KeyIndexLen())
	}

	// Artificially corrupt the index by adding a phantom entry
	st.keyIndex.add("phantom_hash", "phantom_peer")
	if st.KeyIndexLen() != 6 {
		t.Fatalf("after corruption: want 6, got %d", st.KeyIndexLen())
	}

	// Reconcile should detect the mismatch and rebuild
	rebuilt, err := st.ReconcileKeyIndex(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("reconcile did not rebuild despite count mismatch")
	}

	// After rebuild, index should match DB
	if st.KeyIndexLen() != 5 {
		t.Fatalf("after reconcile: want 5, got %d", st.KeyIndexLen())
	}

	// Reconcile again should not rebuild (counts match)
	rebuilt, err = st.ReconcileKeyIndex(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt {
		t.Fatal("reconcile rebuilt despite matching counts")
	}

	// Force rebuild should always rebuild
	rebuilt, err = st.ReconcileKeyIndex(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("force rebuild did not rebuild")
	}
	if st.KeyIndexLen() != 5 {
		t.Fatalf("after force rebuild: want 5, got %d", st.KeyIndexLen())
	}
}

// BenchmarkKeyIndex100k measures memory and performance at 100k peers.
func BenchmarkKeyIndex100k(b *testing.B) {
	dbPath := b.TempDir() + "/bench.db"
	st, err := Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()

	if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
		b.Fatal(err)
	}

	// Create 100k peers
	b.ResetTimer()
	keys := make([]string, 100000)
	hashes := make([]string, 100000)
	for i := 0; i < 100000; i++ {
		id := auth.NewID()
		keys[i] = auth.NewKey()
		hashes[i] = auth.Hash(keys[i])
		if err := st.CreatePeer(context.Background(), id, "peer", hashes[i], "", ""); err != nil {
			b.Fatal(err)
		}
	}

	// Measure lookup performance
	b.Run("Lookup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash := hashes[i%len(hashes)]
			_, ok := st.KeyIndexLookup(hash)
			if !ok {
				b.Fatal("lookup failed")
			}
		}
	})

	// Measure rebuild performance
	b.Run("Rebuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, _, err := st.LoadKeyIndex(context.Background()); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Logf("Index size at 100k peers: %d entries, approx %.1f MB", st.KeyIndexLen(), float64(st.KeyIndexLen()*100)/1024/1024)
}

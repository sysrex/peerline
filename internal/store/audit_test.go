package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestAuditSchemaSurvivesPeerDelete(t *testing.T) {
	clk := clocktest.New(time.Unix(1_700_000_000, 0))
	s := openAuditStore(t, true, clk)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.auditSigner = priv
	if err := s.CreatePeer(t.Context(), "p1", "ada", "hash-1", "", ""); err != nil {
		t.Fatal(err)
	}
	seq, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "peer.deleted", FromPeer: "p1"})
	if err != nil || seq != 1 {
		t.Fatalf("seq %d err %v", seq, err)
	}
	if err := s.DeletePeer(t.Context(), "p1"); err != nil {
		t.Fatal(err)
	}
	var peers, records, pairings, keys int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&peers); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pairings`).Scan(&pairings); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pairing_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	// The explicit append plus the peer.deleted hook.
	if peers != 0 || records != 2 || pairings != 1 || keys != 1 {
		t.Fatalf("peers=%d records=%d pairings=%d keys=%d", peers, records, pairings, keys)
	}
}

func TestAuditDisabledIsNoop(t *testing.T) {
	s := openAuditStore(t, false, clocktest.New(time.Unix(1_700_000_000, 0)))
	var tables int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('pairings','pairing_keys','audit_records','audit_chain_heads')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 4 {
		t.Fatalf("tables %d", tables)
	}
	seq, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "message.sent", FromPeer: "a", ToPeer: "b"})
	if err != nil || seq != 0 {
		t.Fatalf("seq %d err %v", seq, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("wrote %d records while disabled", n)
	}
}

func TestAuditChainGapFree(t *testing.T) {
	s := openAuditStore(t, true, clocktest.New(time.Unix(1_700_000_000, 0)))
	const n = 24
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AppendAudit(t.Context(), nil, AuditRecord{EventType: "message.sent", FromPeer: "a", ToPeer: "b"})
			errc <- err
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.db.Query(`SELECT pair_seq FROM audit_records ORDER BY pair_seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			t.Fatal(err)
		}
		got++
		if seq != got {
			t.Fatalf("pair_seq %d, want %d", seq, got)
		}
	}
	if got != n {
		t.Fatalf("rows %d", got)
	}
}

func TestAuditShapeRequiresTables(t *testing.T) {
	s := openAuditStore(t, true, clocktest.New(time.Unix(1_700_000_000, 0)))
	if _, err := s.db.Exec(`DROP TABLE audit_records`); err != nil {
		t.Fatal(err)
	}
	if err := checkSchemaShape(s.db); err == nil {
		t.Fatal("expected damaged schema")
	}
}

func TestAuditMigratesFromPriorVersion(t *testing.T) {
	path := t.TempDir() + "/prior.db"
	clk := clocktest.New(time.Unix(1_700_000_000, 0))
	s, err := OpenWithOptions(path, OpenOptions{Clock: clk, SkipMigrationBackup: true, AuditEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`
DROP TABLE audit_chain_heads;
DROP TABLE audit_records;
DROP TABLE pairing_keys;
DROP TABLE pairings;
PRAGMA user_version = 8`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = OpenWithOptions(path, OpenOptions{Clock: clk, SkipMigrationBackup: true, AuditEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if s.SchemaVersionInUse() != SchemaVersion() {
		t.Fatalf("version %d", s.SchemaVersionInUse())
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('pairings','pairing_keys','audit_records','audit_chain_heads')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("tables after migrate %d", n)
	}
}

func openAuditStore(t *testing.T, enabled bool, clk *clocktest.Fake) *Store {
	t.Helper()
	s, err := OpenWithOptions(":memory:", OpenOptions{Clock: clk, AuditEnabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

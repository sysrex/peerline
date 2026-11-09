// Package mem is an in-memory audit.LogStore for tests.
package mem

import (
	"context"
	"slices"
	"sync"

	"github.com/sysrex/peerline/internal/audit"
)

// Store is a process-local audit log. It ignores the DBTX argument; the
// signature still matches the port so call sites pass a real transaction.
type Store struct {
	mu   sync.Mutex
	now  func() int64
	rows []audit.LogRecord
	seq  map[string]int64
}

// New returns an empty log. now supplies CreatedAt when the record's is zero.
func New(now func() int64) *Store {
	if now == nil {
		now = func() int64 { return 0 }
	}
	return &Store{now: now, seq: map[string]int64{}}
}

func (s *Store) Append(_ context.Context, _ audit.Tx, rec audit.LogRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq[rec.PairingID]++
	rec.Seq = s.seq[rec.PairingID]
	if rec.CreatedAt == 0 {
		rec.CreatedAt = s.now()
	}
	rec.Payload = append([]byte(nil), rec.Payload...)
	s.rows = append(s.rows, rec)
	return rec.Seq, nil
}

func (s *Store) ReadRange(_ context.Context, pairingID string, fromSeq, toSeq int64) ([]audit.LogRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []audit.LogRecord
	for _, rec := range s.rows {
		if rec.PairingID != pairingID || rec.Seq < fromSeq {
			continue
		}
		if toSeq >= 0 && rec.Seq > toSeq {
			continue
		}
		out = append(out, rec)
	}
	slices.SortFunc(out, func(a, b audit.LogRecord) int {
		if a.Seq < b.Seq {
			return -1
		}
		if a.Seq > b.Seq {
			return 1
		}
		return 0
	})
	return out, nil
}

func (s *Store) MarkBatched(_ context.Context, _ audit.Tx, pairingID string, throughSeq int64, batchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		rec := &s.rows[i]
		if rec.PairingID == pairingID && rec.Seq <= throughSeq && rec.BatchID == "" {
			rec.BatchID = batchID
		}
	}
	return nil
}

func (s *Store) MarkAnchored(_ context.Context, _ audit.Tx, batchID, anchorRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rows {
		if s.rows[i].BatchID == batchID {
			s.rows[i].AnchorRef = anchorRef
		}
	}
	return nil
}

func (s *Store) DeleteBefore(_ context.Context, _ audit.Tx, beforeUnix int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.rows[:0]
	n := 0
	for _, rec := range s.rows {
		if rec.CreatedAt < beforeUnix {
			n++
			continue
		}
		kept = append(kept, rec)
	}
	s.rows = kept
	return n, nil
}

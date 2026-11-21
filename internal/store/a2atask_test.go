package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/sysrex/peerline/internal/clock/clocktest"
)

func TestA2ATransitions(t *testing.T) {
	ok := [][2]string{{"submitted", "working"}, {"working", "completed"}, {"working", "canceled"}, {"input_required", "working"}}
	for _, pair := range ok {
		if err := A2ATransition(pair[0], pair[1]); err != nil {
			t.Fatalf("%s -> %s: %v", pair[0], pair[1], err)
		}
	}
	if err := A2ATransition("completed", "working"); err != ErrA2ATerminal {
		t.Fatalf("terminal message: %v", err)
	}
	if err := A2ATransition("completed", "canceled"); err != ErrA2ANotCancelable {
		t.Fatalf("cancel terminal: %v", err)
	}
}

func TestA2ATaskPrivacySizeAndAudit(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := openSignedAudit(t, priv)
	ctx := t.Context()
	if err := s.CreateA2ATask(ctx, "task-1", "ctx-1", "client", "exec", `{"type":"a2a.message"}`, "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetA2ATask(ctx, "task-1", "stranger"); err != ErrNotFound {
		t.Fatalf("stranger: %v", err)
	}
	got, err := s.GetA2ATask(ctx, "task-1", "client")
	if err != nil || got.State != "submitted" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := s.CreateA2ATask(ctx, "big", "c", "client", "exec", strings.Repeat("x", A2AMaxEnvelope+1), "", time.Hour); err != ErrA2ATooLarge {
		t.Fatalf("envelope: %v", err)
	}
	if err := s.AnswerA2ATask(ctx, "task-1", "client", "working", "", ""); err != ErrNotFound {
		t.Fatalf("client answer: %v", err)
	}
	if err := s.AnswerA2ATask(ctx, "task-1", "exec", "completed", "", `{"name":"out"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.AnswerA2ATask(ctx, "task-1", "exec", "working", "again", ""); err != ErrA2ATerminal {
		t.Fatalf("second answer: %v", err)
	}
	rows, err := s.db.Query(`SELECT event_type FROM audit_records ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if strings.Join(events, ",") != "task.created,task.status,artifact.update" {
		t.Fatalf("events %v", events)
	}
}

func TestA2ATaskPurgeBatch(t *testing.T) {
	prevB, prevM, prevY := a2aPurgeBatch, a2aPurgeMaxBatches, a2aPurgeYield
	a2aPurgeBatch, a2aPurgeMaxBatches, a2aPurgeYield = 1, 1, 0
	t.Cleanup(func() { a2aPurgeBatch, a2aPurgeMaxBatches, a2aPurgeYield = prevB, prevM, prevY })
	clk := clocktest.New(time.Unix(1_800_000_000, 0))
	s := openAuditStore(t, false, clk)
	ctx := t.Context()
	for _, id := range []string{"t1", "t2"} {
		if err := s.CreateA2ATask(ctx, id, "c", "client", "exec", "{}", "", time.Second); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(2 * time.Second)
	n, more, err := s.PurgeA2ATasks(ctx)
	if err != nil || !more || n != 1 {
		t.Fatalf("first %d more %v err %v", n, more, err)
	}
	a2aPurgeMaxBatches = 10
	n, more, err = s.PurgeA2ATasks(ctx)
	if err != nil || more || n != 1 {
		t.Fatalf("second %d more %v err %v", n, more, err)
	}
}

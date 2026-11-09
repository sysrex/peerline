package webhook

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testSecret(t *testing.T) string {
	t.Helper()
	return "whsec_" + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef01234567"))
}

func TestSignVerifyAndOverlap(t *testing.T) {
	secret := testSecret(t)
	old := "whsec_" + base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef01"))
	body := []byte(`{"type":"message.received","id":"1"}`)
	id := "msg_1"
	stamp := "1700000000"
	sig, err := Sign(secret, id, stamp, body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "v1,") {
		t.Fatalf("sig %q", sig)
	}
	now := time.Unix(1700000000, 0)
	if err := Verify([]string{secret}, id, stamp, body, sig, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	oldSig, err := Sign(old, id, stamp, body)
	if err != nil {
		t.Fatal(err)
	}
	header := sig + " " + oldSig
	if err := Verify([]string{secret, old}, id, stamp, body, header, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]string{secret}, id, stamp, body, oldSig, now, 5*time.Minute); err == nil {
		t.Fatal("old secret alone was accepted as current")
	}
	if err := Verify([]string{secret}, id, stamp, []byte("other"), sig, now, 5*time.Minute); err == nil {
		t.Fatal("tampered body accepted")
	}
	late := now.Add(6 * time.Minute)
	if err := Verify([]string{secret}, id, stamp, body, sig, late, 5*time.Minute); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestDecideBackoffDeadAndGone(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	d := Decide(500, 1, now, 0)
	if d.Dead || d.Next.Sub(now) != 500*time.Millisecond {
		t.Fatalf("first retry = %+v", d)
	}
	d = Decide(500, 8, now, 0)
	if !d.Dead || d.Disable {
		t.Fatalf("eighth attempt = %+v, want dead", d)
	}
	d = Decide(410, 1, now, 0)
	if !d.Dead || !d.Disable {
		t.Fatalf("410 = %+v, want dead and disable", d)
	}
	d = Decide(204, 3, now, 0)
	if d.Dead || !d.Next.IsZero() {
		t.Fatalf("success = %+v", d)
	}
	var m Metrics
	m.Note(d, 204)
	m.Note(Decide(500, 1, now, 0), 500)
	m.Note(Decide(410, 1, now, 0), 410)
	if m.Delivered.Load() != 1 || m.Failed.Load() != 1 || m.Dead.Load() != 1 {
		t.Fatalf("metrics delivered=%d failed=%d dead=%d", m.Delivered.Load(), m.Failed.Load(), m.Dead.Load())
	}
	// Cap: a huge shift must not exceed 6h.
	d = Decide(500, 7, now, 0.999)
	if d.Dead || d.Next.Sub(now) > 6*time.Hour {
		t.Fatalf("capped backoff = %s", d.Next.Sub(now))
	}
}

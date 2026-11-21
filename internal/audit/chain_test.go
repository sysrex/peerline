package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{SigKID(pub): pub}
	first := sample(priv, nil)
	second := sample(priv, first.RecordHash)
	second.RecordID = "rec-2"
	if err := Sign(&second, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain([]Record{first, second}, keys); err != nil {
		t.Fatal(err)
	}

	mod := second
	mod.EventType = "grant.revoked"
	if err := VerifyChain([]Record{first, mod}, keys); err == nil {
		t.Fatal("modification accepted")
	}
	swapped := []Record{second, first}
	if err := VerifyChain(swapped, keys); err == nil {
		t.Fatal("reorder accepted")
	}
	if err := VerifyChain([]Record{second}, keys); err == nil {
		t.Fatal("deletion accepted")
	}
	wrong := second
	wrong.SigKID = "0000000000000000"
	if err := VerifyChain([]Record{first, wrong}, keys); err == nil {
		t.Fatal("wrong kid accepted")
	}
}

func sample(priv ed25519.PrivateKey, prev []byte) Record {
	if prev == nil {
		prev = make([]byte, 32)
	}
	rec := Record{
		RecordID: "rec-1", TS: 1700000000000, Instance: "peerline.example",
		PairingID: "pair-placeholder", EventType: "message.sent",
		ContentHashKind: ContentPlaintext, ContentSize: 4,
		ContentHash: ContentHash([]byte("pairing-key-placeholder-32b!!!!"), []byte(`{"body":"ping","type":"note"}`)),
		PrevHash:    prev,
	}
	if err := Sign(&rec, priv); err != nil {
		panic(err)
	}
	return rec
}

func TestKeyFileModeAndKeyringErase(t *testing.T) {
	dir := t.TempDir()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.Default()) })

	wide := filepath.Join(dir, "wide")
	if err := os.WriteFile(wide, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(wide); err == nil {
		t.Fatal("0644 key accepted")
	}
	priv, err := GenerateSigningKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigningKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("loaded key differs")
	}
	if bytes.Contains(logs.Bytes(), priv.Seed()) {
		t.Fatal("log contains the seed")
	}

	master := filepath.Join(dir, "master")
	if err := os.WriteFile(master, bytes.Repeat([]byte{2}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := OpenFileKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	if err := ring.Seal("pair", key); err != nil {
		t.Fatal(err)
	}
	got, err := ring.Get(context.Background(), "pair")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("get %x %v", got, err)
	}
	if err := ring.Erase(context.Background(), "pair"); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Get(context.Background(), "pair"); err == nil {
		t.Fatal("erased key still readable")
	}
	mem := NewMemKeyring()
	mem.Put("p", key)
	if err := mem.Erase(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Get(context.Background(), "p"); err == nil {
		t.Fatal("memory key survived erase")
	}
}

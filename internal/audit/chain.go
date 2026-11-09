package audit

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	ContentPlaintext  = "plaintext"
	ContentCiphertext = "ciphertext"
)

// Record is one signed audit event. Binary fields are raw bytes; CanonicalRecord
// encodes them as base64 inside the JSON object that is hashed.
type Record struct {
	RecordID        string
	TS              int64
	Instance        string
	PairingID       string
	FromPeer        string
	ToPeer          string
	OrgRef          string
	EventType       string
	A2A             map[string]any
	ContentHash     []byte
	ContentHashKind string
	ContentSize     int
	MediaTypes      []string
	PrevHash        []byte
	RecordHash      []byte
	Sig             []byte
	SigKID          string
}

// ContentHash is HMAC-SHA256(K_pairing, canonical content).
func ContentHash(pairingKey, canonical []byte) []byte {
	m := hmac.New(sha256.New, pairingKey)
	m.Write(canonical)
	return m.Sum(nil)
}

// HashRecord sets RecordHash to SHA-256(0x00 || canonical(record without sig and record_hash)).
func HashRecord(rec *Record) error {
	body, err := Canonical(rec.canonicalMap(false))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte{0x00}, body...))
	rec.RecordHash = sum[:]
	return nil
}

// Sign sets Sig and SigKID using the instance private key. Call HashRecord first.
func Sign(rec *Record, priv ed25519.PrivateKey) error {
	if err := HashRecord(rec); err != nil {
		return err
	}
	rec.Sig = ed25519.Sign(priv, rec.RecordHash)
	rec.SigKID = SigKID(priv.Public().(ed25519.PublicKey))
	return nil
}

// SigKID is the first 8 bytes of SHA-256(pubkey), hex encoded.
func SigKID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 0; i < 8; i++ {
		out[i*2] = hexdigits[sum[i]>>4]
		out[i*2+1] = hexdigits[sum[i]&0xf]
	}
	return string(out)
}

// VerifyChain checks order, hashes, and signatures. keys maps sig_kid to a public key.
// The first record's PrevHash must be 32 zero bytes. Each later PrevHash is the
// previous record's RecordHash.
func VerifyChain(recs []Record, keys map[string]ed25519.PublicKey) error {
	var prev []byte
	for i := range recs {
		rec := recs[i]
		if i == 0 {
			if len(rec.PrevHash) != 32 || !allZero(rec.PrevHash) {
				return errors.New("first prev_hash must be 32 zero bytes")
			}
		} else if !bytesEqual(rec.PrevHash, prev) {
			return fmt.Errorf("record %d prev_hash does not match", i)
		}
		want := rec
		if err := HashRecord(&want); err != nil {
			return err
		}
		if !bytesEqual(want.RecordHash, rec.RecordHash) {
			return fmt.Errorf("record %d hash mismatch", i)
		}
		pub, ok := keys[rec.SigKID]
		if !ok || !ed25519.Verify(pub, rec.RecordHash, rec.Sig) {
			return fmt.Errorf("record %d signature", i)
		}
		prev = rec.RecordHash
	}
	return nil
}

func (rec Record) canonicalMap(includeSig bool) map[string]any {
	m := map[string]any{
		"record_id":         rec.RecordID,
		"ts":                rec.TS,
		"peerline_instance": rec.Instance,
		"pairing_id":        rec.PairingID,
		"event_type":        rec.EventType,
		"content_hash_kind": rec.ContentHashKind,
		"content_size":      rec.ContentSize,
		"prev_hash":         b64(rec.PrevHash),
	}
	if rec.FromPeer != "" {
		m["from_peer"] = rec.FromPeer
	}
	if rec.ToPeer != "" {
		m["to_peer"] = rec.ToPeer
	}
	if rec.OrgRef != "" {
		m["org_ref"] = rec.OrgRef
	}
	if rec.A2A != nil {
		m["a2a"] = rec.A2A
	}
	if len(rec.ContentHash) > 0 {
		m["content_hash"] = b64(rec.ContentHash)
	}
	if len(rec.MediaTypes) > 0 {
		arr := make([]any, len(rec.MediaTypes))
		for i, s := range rec.MediaTypes {
			arr[i] = s
		}
		m["media_types"] = arr
	}
	if includeSig {
		m["sig"] = b64(rec.Sig)
		m["sig_kid"] = rec.SigKID
		m["record_hash"] = b64(rec.RecordHash)
	}
	return m
}

func b64(b []byte) string {
	if b == nil {
		b = []byte{}
	}
	return base64.StdEncoding.EncodeToString(b)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

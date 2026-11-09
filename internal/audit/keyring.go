package audit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
)

// Keyring stores pairing keys wrapped under a master key.
type Keyring interface {
	Get(ctx context.Context, pairingID string) ([]byte, error)
	Erase(ctx context.Context, pairingID string) error
}

// MemKeyring is an in-memory keyring for tests.
type MemKeyring struct {
	keys map[string][]byte
}

func NewMemKeyring() *MemKeyring { return &MemKeyring{keys: map[string][]byte{}} }

func (m *MemKeyring) Put(pairingID string, key []byte) {
	m.keys[pairingID] = append([]byte(nil), key...)
}

func (m *MemKeyring) Get(_ context.Context, pairingID string) ([]byte, error) {
	k, ok := m.keys[pairingID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), k...), nil
}

func (m *MemKeyring) Erase(_ context.Context, pairingID string) error {
	if _, ok := m.keys[pairingID]; !ok {
		return ErrNotFound
	}
	delete(m.keys, pairingID)
	return nil
}

// FileKeyring wraps pairing keys with AES-256-GCM under a 32-byte master key file.
type FileKeyring struct {
	aead cipher.AEAD
	keys map[string][]byte
}

// OpenFileKeyring reads a mode-0600 master key file. The key bytes are not logged.
func OpenFileKeyring(path string) (*FileKeyring, error) {
	raw, err := readMode600(path, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &FileKeyring{aead: aead, keys: map[string][]byte{}}, nil
}

// Seal stores key wrapped under the master key.
func (f *FileKeyring) Seal(pairingID string, key []byte) error {
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	f.keys[pairingID] = f.aead.Seal(nonce, nonce, key, []byte(pairingID))
	return nil
}

func (f *FileKeyring) Get(_ context.Context, pairingID string) ([]byte, error) {
	blob, ok := f.keys[pairingID]
	if !ok {
		return nil, ErrNotFound
	}
	ns := f.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("wrapped key is short")
	}
	return f.aead.Open(nil, blob[:ns], blob[ns:], []byte(pairingID))
}

func (f *FileKeyring) Erase(_ context.Context, pairingID string) error {
	if _, ok := f.keys[pairingID]; !ok {
		return ErrNotFound
	}
	delete(f.keys, pairingID)
	return nil
}

// LoadSigningKey reads an Ed25519 private key from a mode-0600 file.
// The file is a 32-byte seed or a 64-byte private key. The contents are not logged.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm() != 0o600 {
		return nil, errors.New("audit signing key must be mode 0600")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, errors.New("audit signing key must be 32 or 64 bytes")
	}
}

func readMode600(path string, n int) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm() != 0o600 {
		return nil, errors.New("key file must be mode 0600")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != n {
		return nil, errors.New("key file has the wrong length")
	}
	return raw, nil
}

// GenerateSigningKey writes a new seed to path with mode 0600.
func GenerateSigningKey(path string) (ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

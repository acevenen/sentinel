package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// BlobStore is a content-addressed, write-once store for artifact bytes. Files
// are named by their SHA-256 and written read-only, so the stored evidence
// cannot be altered in place without detection: a re-read re-hashes the content
// (for plaintext) and compares it to the id. When a key is set, blobs are
// sealed with AES-256-GCM before hitting disk.
type BlobStore struct {
	Root string
	key  []byte // nil means plaintext
}

// ErrBlobExistsDiffers means a blob path exists but its content id no longer
// matches, which should be impossible without tampering.
var ErrBlobExistsDiffers = errors.New("existing blob content does not match its id")

// ErrInvalidBlobID means an id was not a 64-character lowercase hex SHA-256.
var ErrInvalidBlobID = errors.New("blob id must be a 64-character lowercase hex sha256")

// validBlobID enforces that ids are exactly a hex SHA-256, so a caller can
// never coerce a path outside the store (e.g. via "..") or crash pathFor.
func validBlobID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return false
		}
	}
	return true
}

// NewBlobStore returns a plaintext blob store rooted at root.
func NewBlobStore(root string) *BlobStore {
	return &BlobStore{Root: root}
}

// NewEncryptedBlobStore returns a blob store that seals content with key.
func NewEncryptedBlobStore(root string, key []byte) (*BlobStore, error) {
	if len(key) != KeySize {
		return nil, ErrBadKeyLength
	}
	dup := make([]byte, KeySize)
	copy(dup, key)
	return &BlobStore{Root: root, key: dup}, nil
}

// Encrypted reports whether blobs are sealed at rest.
func (b *BlobStore) Encrypted() bool { return b.key != nil }

func (b *BlobStore) pathFor(id string) string {
	// Shard by the first two hex chars to keep directories small.
	return filepath.Join(b.Root, id[:2], id)
}

// Put stores data under its content id. It is idempotent: writing the same
// content twice is a no-op. It returns the on-disk path. The caller supplies id
// (the verified SHA-256 of the plaintext) so Put never trusts unverified bytes.
func (b *BlobStore) Put(id string, data []byte) (string, error) {
	if !validBlobID(id) {
		return "", ErrInvalidBlobID
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != id {
		return "", fmt.Errorf("refusing to store: data does not hash to id %s", id)
	}
	path := b.pathFor(id)
	if _, err := os.Stat(path); err == nil {
		return path, nil // already stored; content-addressed so identical
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("creating blob directory: %w", err)
	}
	payload := data
	if b.key != nil {
		sealed, err := seal(b.key, data)
		if err != nil {
			return "", err
		}
		payload = sealed
	}
	// Write to a temp file then rename, so a crash never leaves a half-written
	// blob under a valid content id.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating temp blob: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("writing blob: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("syncing blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("closing blob: %w", err)
	}
	if err := os.Chmod(tmpName, 0o400); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("setting read-only blob: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("finalizing blob: %w", err)
	}
	return path, nil
}

// Get returns the plaintext bytes for id, decrypting if needed, and verifies
// the content still hashes to id. A mismatch is reported as tampering.
func (b *BlobStore) Get(id string) ([]byte, error) {
	if !validBlobID(id) {
		return nil, ErrInvalidBlobID
	}
	raw, err := os.ReadFile(b.pathFor(id))
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", id, err)
	}
	data := raw
	if b.key != nil {
		data, err = open(b.key, raw)
		if err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != id {
		return nil, fmt.Errorf("%w: blob %s", ErrBlobExistsDiffers, id)
	}
	return data, nil
}

// Exists reports whether a blob is present. An invalid id is never present.
func (b *BlobStore) Exists(id string) bool {
	if !validBlobID(id) {
		return false
	}
	_, err := os.Stat(b.pathFor(id))
	return err == nil
}

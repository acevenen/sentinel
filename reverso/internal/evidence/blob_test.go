package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func idOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestBlobPutGetPlaintext(t *testing.T) {
	b := NewBlobStore(t.TempDir())
	data := []byte("firmware bytes")
	id := idOf(data)
	path, err := b.Put(id, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Stored blob is read-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o200 != 0 {
		t.Fatalf("blob is writable, mode = %v", info.Mode().Perm())
	}
	got, err := b.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("Get mismatch: %q", got)
	}
}

// Put must refuse content whose hash does not match the claimed id.
func TestBlobPutRejectsHashMismatch(t *testing.T) {
	b := NewBlobStore(t.TempDir())
	if _, err := b.Put(idOf([]byte("a")), []byte("b")); err == nil {
		t.Fatal("Put accepted content that does not hash to its id")
	}
}

// A blob altered on disk must fail the hash check on Get.
func TestBlobGetDetectsTampering(t *testing.T) {
	b := NewBlobStore(t.TempDir())
	data := []byte("original")
	id := idOf(data)
	path, err := b.Put(id, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered!"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := b.Get(id); !errors.Is(err, ErrBlobExistsDiffers) {
		t.Fatalf("Get error = %v, want ErrBlobExistsDiffers", err)
	}
}

func TestEncryptedBlobRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	b, err := NewEncryptedBlobStore(t.TempDir(), key)
	if err != nil {
		t.Fatalf("NewEncryptedBlobStore: %v", err)
	}
	data := []byte("secret firmware")
	id := idOf(data)
	path, err := b.Put(id, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// On-disk bytes must not equal the plaintext.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(onDisk) == string(data) {
		t.Fatal("encrypted blob stored plaintext on disk")
	}
	got, err := b.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("decrypted mismatch: %q", got)
	}
}

func TestEncryptedBlobWrongKeyFails(t *testing.T) {
	key := make([]byte, KeySize)
	_, _ = rand.Read(key)
	root := t.TempDir()
	b, _ := NewEncryptedBlobStore(root, key)
	data := []byte("secret")
	id := idOf(data)
	if _, err := b.Put(id, data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	wrong := make([]byte, KeySize)
	_, _ = rand.Read(wrong)
	b2, _ := NewEncryptedBlobStore(root, wrong)
	if _, err := b2.Get(id); err == nil {
		t.Fatal("Get with the wrong key should fail")
	}
}

func TestEncryptedStoreRejectsBadKeyLength(t *testing.T) {
	if _, err := NewEncryptedBlobStore(t.TempDir(), []byte("short")); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("error = %v, want ErrBadKeyLength", err)
	}
}

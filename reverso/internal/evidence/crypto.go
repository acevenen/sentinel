package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Encryption at rest for artifact blobs. The evidence package takes a 32-byte
// key; deriving it from a passphrase (scrypt/argon2) is the caller's job so key
// handling policy stays in one place. Blobs are sealed with AES-256-GCM and the
// random nonce is prepended to the ciphertext.

// KeySize is the required symmetric key length (AES-256).
const KeySize = 32

// ErrKeyRequired means an encrypted store was asked to operate without a key.
var ErrKeyRequired = errors.New("evidence store encryption key is required")

// ErrBadKeyLength means a key of the wrong size was supplied.
var ErrBadKeyLength = errors.New("evidence store key must be 32 bytes")

func seal(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrBadKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrBadKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is shorter than the nonce")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting blob (wrong key or tampered): %w", err)
	}
	return plaintext, nil
}

package scope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Signatures bind a manifest to an owner key. The trust anchor is the owner's
// Ed25519 public key: REVerso will only act on a manifest whose signature
// verifies against a key the operator has explicitly trusted. An unsigned or
// wrongly-signed manifest is untrusted and, in strict mode, refused.

// Signature errors.
var (
	ErrNoSignature        = errors.New("manifest is not signed")
	ErrMalformedSignature = errors.New("manifest signature is malformed")
	ErrUnknownAlgorithm   = errors.New("manifest signature uses an unknown algorithm")
	ErrBadPublicKey       = errors.New("manifest signature has an invalid public key")
	ErrSignatureInvalid   = errors.New("manifest signature does not verify")
	ErrUntrustedSigner    = errors.New("manifest signer is not in the trusted key set")
)

const sigAlgorithm = "ed25519"

// Keypair is a generated Ed25519 signing identity for an owner.
type Keypair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeypair creates a fresh Ed25519 owner key.
func GenerateKeypair() (Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("generating owner key: %w", err)
	}
	return Keypair{Public: pub, Private: priv}, nil
}

// EncodePublicKey renders a public key as base64 for storage and display.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey parses a base64 Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPublicKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: wrong length %d", ErrBadPublicKey, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// EncodePrivateKey renders a private key as base64 for local storage. The
// caller is responsible for protecting the file (see the evidence store's
// owner-only permissions).
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv)
}

// DecodePrivateKey parses a base64 Ed25519 private key.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has wrong length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// Sign signs the manifest in place, replacing any existing signature with one
// of the form "ed25519:<base64 pubkey>:<base64 sig>".
func (m *Manifest) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("signing key is not a valid Ed25519 private key")
	}
	body, err := m.Authorization.canonicalBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, body)
	pub := priv.Public().(ed25519.PublicKey)
	m.Authorization.Signature = fmt.Sprintf("%s:%s:%s",
		sigAlgorithm,
		base64.StdEncoding.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(sig),
	)
	return nil
}

// parsedSignature is the decoded three-part signature string.
type parsedSignature struct {
	pub ed25519.PublicKey
	sig []byte
}

func parseSignature(s string) (parsedSignature, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return parsedSignature{}, ErrNoSignature
	}
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return parsedSignature{}, fmt.Errorf("%w: expected algorithm:pubkey:sig", ErrMalformedSignature)
	}
	if parts[0] != sigAlgorithm {
		return parsedSignature{}, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, parts[0])
	}
	pub, err := DecodePublicKey(parts[1])
	if err != nil {
		return parsedSignature{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return parsedSignature{}, fmt.Errorf("%w: %v", ErrMalformedSignature, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return parsedSignature{}, fmt.Errorf("%w: wrong signature length", ErrMalformedSignature)
	}
	return parsedSignature{pub: pub, sig: sig}, nil
}

// VerifySignature checks the manifest signature. When trusted is non-empty, the
// signing key must be one of the trusted keys; an empty trusted set means the
// caller accepts any self-consistent signature (trust-on-first-use), which the
// CLI records so the operator can pin it. On success it sets Verified and
// SignerKey. On any failure it clears Verified and returns a specific error.
func (m *Manifest) VerifySignature(trusted []ed25519.PublicKey) error {
	m.Verified = false
	m.SignerKey = ""

	parsed, err := parseSignature(m.Authorization.Signature)
	if err != nil {
		return err
	}
	body, err := m.Authorization.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(parsed.pub, body, parsed.sig) {
		return ErrSignatureInvalid
	}
	if len(trusted) > 0 {
		ok := false
		for _, t := range trusted {
			if t.Equal(parsed.pub) {
				ok = true
				break
			}
		}
		if !ok {
			return ErrUntrustedSigner
		}
	}
	m.Verified = true
	m.SignerKey = EncodePublicKey(parsed.pub)
	return nil
}

package scope

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func signableManifest() *Manifest {
	return &Manifest{Authorization: Authorization{
		ProjectID: "p",
		Owner:     "o@example.test",
		Target:    Target{AssetID: "a", AssetType: AssetFirmwareImage, OwnershipEvidence: "receipt"},
		Permitted: []Capability{CapFirmwareMetadataAnalysis},
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	m := signableManifest()
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature([]ed25519.PublicKey{kp.Public}); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if !m.Verified {
		t.Fatal("Verified should be true after a good verification")
	}
	if m.SignerKey != EncodePublicKey(kp.Public) {
		t.Fatalf("SignerKey = %q, want %q", m.SignerKey, EncodePublicKey(kp.Public))
	}
}

func TestVerifyDetectsTamperedBody(t *testing.T) {
	kp, _ := GenerateKeypair()
	m := signableManifest()
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper after signing: escalate the expiry.
	m.Authorization.ExpiresAt = time.Now().Add(1000 * time.Hour).UTC().Format(time.RFC3339)
	if err := m.VerifySignature(nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifySignature error = %v, want ErrSignatureInvalid", err)
	}
	if m.Verified {
		t.Fatal("Verified must be false after a failed verification")
	}
}

func TestVerifyRejectsUntrustedSigner(t *testing.T) {
	signer, _ := GenerateKeypair()
	other, _ := GenerateKeypair()
	m := signableManifest()
	if err := m.Sign(signer.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature([]ed25519.PublicKey{other.Public}); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("VerifySignature error = %v, want ErrUntrustedSigner", err)
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	m := signableManifest()
	if err := m.VerifySignature(nil); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifySignature error = %v, want ErrNoSignature", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	m := signableManifest()
	m.Authorization.Signature = "ed25519:not-base64"
	if err := m.VerifySignature(nil); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("VerifySignature error = %v, want ErrMalformedSignature", err)
	}
}

// A manifest signed with nil capability slices must still verify after a YAML
// round-trip turns them into empty slices (canonical normalization).
func TestSignVerifySurvivesNilVsEmptySlices(t *testing.T) {
	kp, _ := GenerateKeypair()
	m := &Manifest{Authorization: Authorization{
		ProjectID: "p", Owner: "o@example.test",
		Target:    Target{AssetID: "a", AssetType: AssetFirmwareImage, OwnershipEvidence: "receipt"},
		Permitted: []Capability{CapFirmwareMetadataAnalysis},
		// Prohibited deliberately left nil.
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Round-trip through YAML, which materializes nil slices as empty.
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reloaded, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := reloaded.VerifySignature([]ed25519.PublicKey{kp.Public}); err != nil {
		t.Fatalf("VerifySignature after round-trip: %v", err)
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	kp, _ := GenerateKeypair()
	enc := EncodePublicKey(kp.Public)
	dec, err := DecodePublicKey(enc)
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if !dec.Equal(kp.Public) {
		t.Fatal("public key did not round-trip")
	}
}

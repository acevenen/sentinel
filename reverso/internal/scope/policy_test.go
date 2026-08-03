package scope

import (
	"context"
	"errors"
	"testing"
	"time"
)

// validManifest returns a signed, unexpired manifest that permits a broad set
// of defensive capabilities, so individual tests can narrow or break one thing.
func validManifest(t *testing.T) (*Manifest, Keypair) {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	m := &Manifest{Authorization: Authorization{
		ProjectID: "proj-1",
		Owner:     "owner@example.test",
		Target: Target{
			AssetID:           "ecu-lab-01",
			AssetType:         AssetFirmwareImage,
			OwnershipEvidence: "purchase receipt on file",
		},
		Permitted: []Capability{
			CapArtifactIngestion,
			CapFirmwareMetadataAnalysis,
			CapPassiveCaptureAnalysis,
			CapTrustMapping,
			CapReportGeneration,
		},
		Prohibited: []Capability{ProdKeyExtraction},
		ExpiresAt:  time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	return m, kp
}

func TestAuthorizeAllowsPermittedCapability(t *testing.T) {
	m, _ := validManifest(t)
	p := New(m)
	dec, err := p.Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis,
		AssetType:  AssetFirmwareImage,
		Target:     "ecu-lab-01",
	})
	if err != nil {
		t.Fatalf("Authorize returned error for a permitted action: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("decision not allowed: %+v", dec)
	}
}

func TestRefusesPermanentlyProhibited(t *testing.T) {
	m, _ := validManifest(t)
	p := New(m)
	for _, c := range PermanentlyProhibited() {
		dec, err := p.Authorize(context.Background(), Action{Capability: c, Target: "t"})
		if !errors.Is(err, ErrPermanentlyProhibited) {
			t.Fatalf("Authorize(%s) error = %v, want ErrPermanentlyProhibited", c, err)
		}
		if dec.Allowed {
			t.Fatalf("Authorize(%s) allowed a permanently prohibited capability", c)
		}
	}
}

// A manifest can never grant a permanent prohibition: Validate must reject it,
// and even if one were smuggled in, Authorize refuses it.
func TestManifestCannotGrantPermanentProhibition(t *testing.T) {
	m, kp := validManifest(t)
	m.Authorization.Permitted = append(m.Authorization.Permitted, SecureBootBypass)
	if err := m.Validate(); !errors.Is(err, ErrGrantsProhibited) {
		t.Fatalf("Validate error = %v, want ErrGrantsProhibited", err)
	}
	// Bypass validation and sign it anyway; Authorize must still refuse.
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	dec, err := New(m).Authorize(context.Background(), Action{Capability: SecureBootBypass, Target: "t"})
	if !errors.Is(err, ErrPermanentlyProhibited) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrPermanentlyProhibited denied", err, dec.Allowed)
	}
}

func TestRefusesExpiredScope(t *testing.T) {
	m, kp := validManifest(t)
	m.Authorization.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
	})
	if !errors.Is(err, ErrScopeExpired) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrScopeExpired denied", err, dec.Allowed)
	}
}

// A manifest with an expiry exactly at "now" is expired (boundary fails closed).
func TestExpiryBoundaryFailsClosed(t *testing.T) {
	m, _ := validManifest(t)
	fixed := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	m.Authorization.ExpiresAt = fixed.Format(time.RFC3339)
	p := Policy{Manifest: m, RequireSignature: false, Now: func() time.Time { return fixed }}
	_, err := p.Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
	})
	if !errors.Is(err, ErrScopeExpired) {
		t.Fatalf("Authorize error = %v, want ErrScopeExpired at the boundary", err)
	}
}

func TestRefusesUnverifiedWhenSignatureRequired(t *testing.T) {
	m, _ := validManifest(t)
	m.Verified = false // simulate a manifest that was never verified
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
	})
	if !errors.Is(err, ErrUnverified) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrUnverified denied", err, dec.Allowed)
	}
}

func TestRefusesCapabilityNotPermitted(t *testing.T) {
	m, _ := validManifest(t)
	// CapBinaryAnalysis is a valid capability but not in this manifest.
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapBinaryAnalysis, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
	})
	if !errors.Is(err, ErrNotPermitted) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrNotPermitted denied", err, dec.Allowed)
	}
}

func TestRefusesManifestProhibitedCapability(t *testing.T) {
	m, kp := validManifest(t)
	// Permit trust mapping, then also prohibit it: prohibition must win.
	m.Authorization.Permitted = append(m.Authorization.Permitted, CapBinaryAnalysis)
	m.Authorization.Prohibited = append(m.Authorization.Prohibited, CapBinaryAnalysis)
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapBinaryAnalysis, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
	})
	if !errors.Is(err, ErrProhibitedByManifest) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrProhibitedByManifest denied", err, dec.Allowed)
	}
}

func TestRefusesAssetTypeMismatch(t *testing.T) {
	m, _ := validManifest(t) // target asset type is firmware_image
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis,
		AssetType:  AssetSimulator, // wrong type
		Target:     "ecu-lab-01",
	})
	if !errors.Is(err, ErrAssetTypeMismatch) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrAssetTypeMismatch denied", err, dec.Allowed)
	}
}

func TestRefusesNoAuthorization(t *testing.T) {
	p := Policy{RequireSignature: true}
	dec, err := p.Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis, Target: "x",
	})
	if !errors.Is(err, ErrNoAuthorization) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrNoAuthorization denied", err, dec.Allowed)
	}
}

func TestRefusesStateChangingWithoutApproval(t *testing.T) {
	m, kp := validManifest(t)
	m.Authorization.Permitted = append(m.Authorization.Permitted, CapSimulation)
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability:    CapSimulation,
		AssetType:     AssetFirmwareImage,
		Target:        "ecu-lab-01",
		StateChanging: true,
		Approved:      false,
	})
	if !errors.Is(err, ErrApprovalRequired) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrApprovalRequired denied", err, dec.Allowed)
	}
}

// The simulator message emit is the only path to any bus-like emission, and it
// is guarded three ways: simulator asset type, lab-only, and approval.
func TestGuardedSimulatorEmitRequiresAllGuards(t *testing.T) {
	// Build a simulator manifest permitting the guarded capability.
	kp, _ := GenerateKeypair()
	m := &Manifest{Authorization: Authorization{
		ProjectID: "sim-proj",
		Owner:     "owner@example.test",
		Target: Target{
			AssetID:           "sim-01",
			AssetType:         AssetSimulator,
			OwnershipEvidence: "software model",
		},
		Permitted: []Capability{CapSimulation, CapSimulatorMessageEmit},
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	p := New(m)

	cases := []struct {
		name    string
		action  Action
		wantErr error
	}{
		{"missing lab-only", Action{Capability: CapSimulatorMessageEmit, AssetType: AssetSimulator, StateChanging: true, Approved: true, LabOnly: false}, ErrLabOnlyRequired},
		{"missing approval", Action{Capability: CapSimulatorMessageEmit, AssetType: AssetSimulator, StateChanging: true, Approved: false, LabOnly: true}, ErrApprovalRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.action.Target = "sim-01"
			_, err := p.Authorize(context.Background(), tc.action)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Authorize error = %v, want %v", err, tc.wantErr)
			}
		})
	}

	// With every guard satisfied it is allowed.
	dec, err := p.Authorize(context.Background(), Action{
		Capability: CapSimulatorMessageEmit, AssetType: AssetSimulator, Target: "sim-01",
		StateChanging: true, Approved: true, LabOnly: true,
	})
	if err != nil || !dec.Allowed {
		t.Fatalf("fully-guarded emit should be allowed, got err=%v allowed=%v", err, dec.Allowed)
	}
}

// A guarded emit against a non-simulator manifest must be refused even with
// approval and lab-only asserted.
func TestGuardedEmitRefusedOutsideSimulator(t *testing.T) {
	m, kp := validManifest(t) // firmware_image target
	m.Authorization.Permitted = append(m.Authorization.Permitted, CapSimulatorMessageEmit)
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapSimulatorMessageEmit, AssetType: AssetFirmwareImage, Target: "ecu-lab-01",
		StateChanging: true, Approved: true, LabOnly: true,
	})
	if !errors.Is(err, ErrSimulatorRequired) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrSimulatorRequired denied", err, dec.Allowed)
	}
}

func TestRefusesEmptyTarget(t *testing.T) {
	m, _ := validManifest(t)
	dec, err := New(m).Authorize(context.Background(), Action{
		Capability: CapFirmwareMetadataAnalysis, AssetType: AssetFirmwareImage, Target: "",
	})
	if !errors.Is(err, ErrEmptyTarget) || dec.Allowed {
		t.Fatalf("Authorize error = %v allowed=%v, want ErrEmptyTarget denied", err, dec.Allowed)
	}
}

func TestAuthorizeHonorsContextCancellation(t *testing.T) {
	m, _ := validManifest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(m).Authorize(ctx, Action{Capability: CapFirmwareMetadataAnalysis, Target: "x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authorize error = %v, want context.Canceled", err)
	}
}

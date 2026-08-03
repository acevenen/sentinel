package scope

import (
	"errors"
	"testing"
	"time"
)

const goodManifestYAML = `authorization:
  project_id: proj-1
  owner: owner@example.test
  target:
    asset_id: ecu-lab-01
    asset_type: firmware_image
    ownership_evidence: purchase receipt on file
  permitted:
    - firmware_metadata_analysis
    - trust_mapping
  prohibited:
    - production_key_extraction
  expires_at: 2999-01-01T00:00:00Z
  signature: ""
`

func TestParseAndValidateGoodManifest(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if m.Authorization.Target.AssetType != AssetFirmwareImage {
		t.Fatalf("asset type = %q", m.Authorization.Target.AssetType)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse([]byte("   \n")); !errors.Is(err, ErrEmptyManifest) {
		t.Fatalf("Parse empty error = %v, want ErrEmptyManifest", err)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	bad := goodManifestYAML + "  rogue_field: true\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatalf("Parse accepted an unknown field; strict decoding should reject it")
	}
}

// Forbidden target types: an asset_type outside the recognized enum is refused.
func TestValidateRejectsForbiddenAssetType(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.Target.AssetType = "operational_vehicle"
	if err := m.Validate(); !errors.Is(err, ErrBadAssetType) {
		t.Fatalf("Validate error = %v, want ErrBadAssetType", err)
	}
}

func TestValidateRejectsUnknownCapability(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.Permitted = []Capability{"make_coffee"}
	if err := m.Validate(); !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("Validate error = %v, want ErrUnknownCapability", err)
	}
}

func TestValidateRejectsGrantingProhibited(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.Permitted = []Capability{PublicRoadOperation}
	if err := m.Validate(); !errors.Is(err, ErrGrantsProhibited) {
		t.Fatalf("Validate error = %v, want ErrGrantsProhibited", err)
	}
}

func TestValidateRequiresExpiry(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.ExpiresAt = ""
	if err := m.Validate(); !errors.Is(err, ErrMissingExpiry) {
		t.Fatalf("Validate error = %v, want ErrMissingExpiry", err)
	}
	m.Authorization.ExpiresAt = "not-a-timestamp"
	if err := m.Validate(); !errors.Is(err, ErrBadExpiry) {
		t.Fatalf("Validate error = %v, want ErrBadExpiry", err)
	}
}

func TestValidateRequiresOwnershipEvidence(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.Target.OwnershipEvidence = ""
	if err := m.Validate(); !errors.Is(err, ErrMissingOwnership) {
		t.Fatalf("Validate error = %v, want ErrMissingOwnership", err)
	}
}

func TestExpiredHelper(t *testing.T) {
	m, err := Parse([]byte(goodManifestYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	m.Authorization.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if !m.Expired(time.Now()) {
		t.Fatal("Expired should be true for a past timestamp")
	}
	m.Authorization.ExpiresAt = "garbage"
	if !m.Expired(time.Now()) {
		t.Fatal("Expired should fail closed (true) for an unparseable timestamp")
	}
}

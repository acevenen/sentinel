package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AssetType constrains what kind of thing a manifest authorizes work on. Only
// detached, owner-controlled or purely virtual targets are permitted; there is
// deliberately no value for an operational or public-road system.
type AssetType string

// Recognized asset types.
const (
	AssetDetachedLabHardware AssetType = "detached_lab_hardware"
	AssetFirmwareImage       AssetType = "firmware_image"
	AssetPassiveCapture      AssetType = "passive_capture"
	AssetSimulator           AssetType = "simulator"
)

var assetTypeSet = map[AssetType]struct{}{
	AssetDetachedLabHardware: {},
	AssetFirmwareImage:       {},
	AssetPassiveCapture:      {},
	AssetSimulator:           {},
}

// Target identifies the single asset a manifest authorizes.
type Target struct {
	AssetID           string    `yaml:"asset_id" json:"asset_id"`
	AssetType         AssetType `yaml:"asset_type" json:"asset_type"`
	OwnershipEvidence string    `yaml:"ownership_evidence" json:"ownership_evidence"`
}

// Authorization is the signed body of a manifest. Field order is fixed so its
// canonical JSON encoding is stable across sign and verify.
type Authorization struct {
	ProjectID  string       `yaml:"project_id" json:"project_id"`
	Owner      string       `yaml:"owner" json:"owner"`
	Target     Target       `yaml:"target" json:"target"`
	Permitted  []Capability `yaml:"permitted" json:"permitted"`
	Prohibited []Capability `yaml:"prohibited" json:"prohibited"`
	ExpiresAt  string       `yaml:"expires_at" json:"expires_at"`
	// Signature is excluded from the signed canonical form; see canonicalBytes.
	Signature string `yaml:"signature" json:"signature"`
}

// Manifest wraps an Authorization under a top-level `authorization:` key, as in
// the documented schema, and carries the verification state established at load.
type Manifest struct {
	Authorization Authorization `yaml:"authorization" json:"authorization"`

	// Verified is set to true only after VerifySignature succeeds. Policy
	// requires it when signature enforcement is on; it never persists to disk.
	Verified bool `yaml:"-" json:"-"`
	// SignerKey records the base64 Ed25519 public key that produced a verified
	// signature, for the audit trail.
	SignerKey string `yaml:"-" json:"-"`
}

// Errors returned when loading or validating a manifest.
var (
	ErrEmptyManifest     = errors.New("authorization manifest is empty")
	ErrMissingProjectID  = errors.New("manifest is missing project_id")
	ErrMissingOwner      = errors.New("manifest is missing owner")
	ErrMissingAssetID    = errors.New("manifest target is missing asset_id")
	ErrMissingOwnership  = errors.New("manifest target is missing ownership_evidence")
	ErrBadAssetType      = errors.New("manifest target has an unrecognized asset_type")
	ErrNoPermitted       = errors.New("manifest grants no permitted capabilities")
	ErrUnknownCapability = errors.New("manifest lists an unknown capability")
	ErrGrantsProhibited  = errors.New("manifest attempts to permit a permanently prohibited capability")
	ErrMissingExpiry     = errors.New("manifest is missing expires_at")
	ErrBadExpiry         = errors.New("manifest expires_at is not a valid RFC3339 timestamp")
)

// Load reads and parses a manifest file. It does not verify the signature or
// the expiry; callers must Validate and (in strict mode) VerifySignature.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return Parse(data)
}

// Parse decodes manifest bytes with strict key handling so a typo in a field
// name is an error rather than a silently ignored, unenforced rule.
func Parse(data []byte) (*Manifest, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, ErrEmptyManifest
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if m.Authorization.ProjectID == "" && m.Authorization.Owner == "" &&
		m.Authorization.Target.AssetID == "" && len(m.Authorization.Permitted) == 0 {
		return nil, ErrEmptyManifest
	}
	return &m, nil
}

// Validate checks structural integrity independent of time and signature. It
// rejects manifests that grant unknown or permanently prohibited capabilities.
func (m *Manifest) Validate() error {
	if m == nil {
		return ErrEmptyManifest
	}
	a := m.Authorization
	switch {
	case strings.TrimSpace(a.ProjectID) == "":
		return ErrMissingProjectID
	case strings.TrimSpace(a.Owner) == "":
		return ErrMissingOwner
	case strings.TrimSpace(a.Target.AssetID) == "":
		return ErrMissingAssetID
	case strings.TrimSpace(a.Target.OwnershipEvidence) == "":
		return ErrMissingOwnership
	}
	if _, ok := assetTypeSet[a.Target.AssetType]; !ok {
		return fmt.Errorf("%w: %q", ErrBadAssetType, a.Target.AssetType)
	}
	if len(a.Permitted) == 0 {
		return ErrNoPermitted
	}
	for _, c := range a.Permitted {
		if IsPermanentlyProhibited(c) {
			return fmt.Errorf("%w: %q", ErrGrantsProhibited, c)
		}
		if !IsKnownPermitted(c) {
			return fmt.Errorf("%w: %q", ErrUnknownCapability, c)
		}
	}
	// Prohibited entries need not be known permitted capabilities — a manifest
	// may name a permanent prohibition explicitly for documentation — but they
	// must be non-empty strings.
	for _, c := range a.Prohibited {
		if strings.TrimSpace(string(c)) == "" {
			return fmt.Errorf("%w: empty prohibited entry", ErrUnknownCapability)
		}
	}
	if strings.TrimSpace(a.ExpiresAt) == "" {
		return ErrMissingExpiry
	}
	if _, err := time.Parse(time.RFC3339, a.ExpiresAt); err != nil {
		return fmt.Errorf("%w: %v", ErrBadExpiry, err)
	}
	return nil
}

// Expiry returns the parsed expiry time. Validate must pass first.
func (m *Manifest) Expiry() (time.Time, error) {
	return time.Parse(time.RFC3339, m.Authorization.ExpiresAt)
}

// Expired reports whether the manifest is expired at now. A manifest whose
// expiry cannot be parsed is treated as expired, failing closed.
func (m *Manifest) Expired(now time.Time) bool {
	exp, err := m.Expiry()
	if err != nil {
		return true
	}
	return !now.Before(exp)
}

// Permits reports whether the manifest's permitted list contains c.
func (m *Manifest) Permits(c Capability) bool {
	for _, p := range m.Authorization.Permitted {
		if p == c {
			return true
		}
	}
	return false
}

// Prohibits reports whether the manifest's prohibited list contains c.
func (m *Manifest) Prohibits(c Capability) bool {
	for _, p := range m.Authorization.Prohibited {
		if p == c {
			return true
		}
	}
	return false
}

// canonicalBytes returns the deterministic byte string that is signed and
// verified. The signature field is cleared so signing is self-consistent.
func (a Authorization) canonicalBytes() ([]byte, error) {
	clone := a
	clone.Signature = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("encoding canonical manifest: %w", err)
	}
	return data, nil
}

// Marshal renders the manifest back to YAML under the authorization key.
func (m *Manifest) Marshal() ([]byte, error) {
	return yaml.Marshal(m)
}

package knowledge

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// Spotter knowledge purposes. Both corpora are embedded so device assessment
// works air-gapped, with no runtime network call.
const (
	PurposeDeviceFingerprints Purpose = "device-fingerprints"
	PurposeDeviceAdvisories   Purpose = "device-advisories"
)

// MatchMode is how a fingerprint rule compares its value to an observation.
// Deliberately limited to non-regex modes: rule values are matched against
// attacker-influenceable banner text, and an unbounded regex there is a
// denial-of-service surface.
type MatchMode string

const (
	MatchExact    MatchMode = "exact"
	MatchPrefix   MatchMode = "prefix"
	MatchContains MatchMode = "contains"
)

// FingerprintRule is one piece of evidence that points at a device family.
// Bits is a log2 likelihood ratio: how much this signal moves belief, in bits.
type FingerprintRule struct {
	Kind  string    `json:"kind"`
	Match MatchMode `json:"match"`
	Value string    `json:"value"`
	Bits  float64   `json:"bits"`
	Class string    `json:"class"`
}

// DeviceFingerprint is one identifiable device family in the corpus.
type DeviceFingerprint struct {
	ID       string            `json:"id"`
	Vendor   string            `json:"vendor"`
	Family   string            `json:"family"`
	Category string            `json:"category"`
	Rules    []FingerprintRule `json:"rules"`
}

// VersionRange bounds the firmware versions an advisory applies to. An empty
// Fixed means "no fixed version recorded in this corpus" — which is treated as
// unbounded and therefore reported with lower confidence, never as certainty.
type VersionRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// RemediationStep is one plain-language action a non-expert can actually take.
// Reduction is the fraction of this advisory's risk the step removes (0..1);
// Effort is low|medium|high.
// Tag is a canonical identifier for the underlying action, so that advice
// phrased differently by two advisories ("remove the camera from the public
// internet" / "delete the port-forward rule") collapses to one plan step
// instead of nagging the reader three times.
type RemediationStep struct {
	Action    string  `json:"action"`
	Effort    string  `json:"effort"`
	Reduction float64 `json:"reduction"`
	Tag       string  `json:"tag,omitempty"`
}

// Advisory is one known weakness affecting a device family. Vendor and Family
// of "*" mean the advisory is hygiene guidance that applies to any device.
type Advisory struct {
	ID                 string            `json:"id"`
	Title              string            `json:"title"`
	Vendor             string            `json:"vendor"`
	Family             string            `json:"family"`
	CWE                string            `json:"cwe"`
	CVSS               float64           `json:"cvss"`
	KnownExploited     bool              `json:"known_exploited"`
	DefaultCredentials bool              `json:"default_credentials"`
	Summary            string            `json:"summary"`
	Affected           VersionRange      `json:"affected"`
	VersionConfidence  string            `json:"version_confidence"`
	Remediation        []RemediationStep `json:"remediation"`
	Source             string            `json:"source"`
}

// corpus is the on-disk shape shared by both embedded datasets.
type fingerprintCorpus struct {
	Dataset string              `json:"dataset"`
	Status  string              `json:"status"`
	Notice  string              `json:"notice"`
	Source  string              `json:"source"`
	License string              `json:"license"`
	Devices []DeviceFingerprint `json:"devices"`
}

type advisoryCorpus struct {
	Dataset    string     `json:"dataset"`
	Status     string     `json:"status"`
	Notice     string     `json:"notice"`
	Source     string     `json:"source"`
	License    string     `json:"license"`
	Advisories []Advisory `json:"advisories"`
}

//go:embed data/spotter-fingerprints.json
var embeddedFingerprints []byte

//go:embed data/spotter-advisories.json
var embeddedAdvisories []byte

var (
	fingerprintOnce sync.Once
	fingerprintData fingerprintCorpus

	advisoryOnce sync.Once
	advisoryData advisoryCorpus
)

// DeviceFingerprints returns the embedded device-fingerprint corpus. The
// returned slice is a copy, so a caller cannot mutate the shared corpus.
func DeviceFingerprints() []DeviceFingerprint {
	fingerprintOnce.Do(func() {
		if err := json.Unmarshal(embeddedFingerprints, &fingerprintData); err != nil {
			fingerprintData = fingerprintCorpus{}
		}
	})
	out := make([]DeviceFingerprint, len(fingerprintData.Devices))
	copy(out, fingerprintData.Devices)
	return out
}

// DeviceAdvisories returns the embedded advisory corpus as a copy.
func DeviceAdvisories() []Advisory {
	advisoryOnce.Do(func() {
		if err := json.Unmarshal(embeddedAdvisories, &advisoryData); err != nil {
			advisoryData = advisoryCorpus{}
		}
	})
	out := make([]Advisory, len(advisoryData.Advisories))
	copy(out, advisoryData.Advisories)
	return out
}

// AdvisoryDatasetNotice returns the corpus provenance banner. Callers must
// surface it with any advisory output: the shipped ranges are coarse and are
// not a substitute for the vendor advisory or NVD.
func AdvisoryDatasetNotice() (status, notice, source string) {
	DeviceAdvisories()
	return advisoryData.Status, advisoryData.Notice, advisoryData.Source
}

// FingerprintDatasetNotice returns the fingerprint corpus provenance.
func FingerprintDatasetNotice() (status, notice, source string) {
	DeviceFingerprints()
	return fingerprintData.Status, fingerprintData.Notice, fingerprintData.Source
}

// SpotterAssets exposes both corpora through the standard Asset view so they
// appear alongside every other knowledge source.
func SpotterAssets() []Asset {
	fpStatus, _, fpSource := FingerprintDatasetNotice()
	advStatus, _, advSource := AdvisoryDatasetNotice()
	return []Asset{
		{
			Name:       "Sentinel device fingerprint corpus",
			Purpose:    PurposeDeviceFingerprints,
			Path:       "embedded:internal/knowledge/data/spotter-fingerprints.json",
			Source:     fpSource,
			License:    fpStatus,
			Downloaded: true,
		},
		{
			Name:       "Sentinel device advisory corpus",
			Purpose:    PurposeDeviceAdvisories,
			Path:       "embedded:internal/knowledge/data/spotter-advisories.json",
			Source:     advSource,
			License:    advStatus,
			Downloaded: true,
		},
	}
}

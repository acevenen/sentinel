package spotter

import (
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/knowledge"
)

func TestCompareVersionsHandlesIoTSchemes(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Numeric components compare numerically, not lexically. A string
		// compare gets "10" < "9" wrong, which would misjudge a patched device.
		{"5.4.10", "5.4.9", 1},
		{"5.4.9", "5.4.10", -1},
		{"1.0.0.75", "1.0.0.9", 1},
		// Equality across cosmetic differences.
		{"5.4.9", "5.4.9", 0},
		{"V5.4.9", "5.4.9", 0},
		{"v5.4.9", "V5.4.9", 0},
		{"5.4.9", "5_4_9", 0},
		// Longer version sorts after an equal prefix.
		{"1.0.1", "1.0", 1},
		{"1.0", "1.0.1", -1},
		// Vendor build suffixes.
		{"5.4.9-r2", "5.4.9-r1", 1},
		{"5.4.9-r2", "5.4.9", -1}, // trailing alpha run is a pre-release
		{"2.400.0000000.14.R", "2.400.0000000.13.R", 1},
		// Numeric component outranks alphabetic at the same position.
		{"1.0.1", "1.0.beta", 1},
		// Empty strings are equal to each other and lower than anything.
		{"", "", 0},
		{"", "1.0", -1},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCompareVersionsIsAntisymmetric(t *testing.T) {
	versions := []string{"1.0", "1.0.1", "5.4.9", "5.4.10", "V5.4.9", "2.400.0.14.R", "", "1.0.0-rc"}
	for _, a := range versions {
		for _, b := range versions {
			ab, ba := CompareVersions(a, b), CompareVersions(b, a)
			if ab != -ba {
				t.Errorf("antisymmetry broken: cmp(%q,%q)=%d but cmp(%q,%q)=%d", a, b, ab, b, a, ba)
			}
		}
	}
}

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		name                       string
		version, introduced, fixed string
		want                       bool
	}{
		{"inside bounded range", "5.4.9", "5.0.0", "5.5.0", true},
		{"at fixed version is patched", "5.5.0", "5.0.0", "5.5.0", false},
		{"above fixed version", "5.6.0", "5.0.0", "5.5.0", false},
		{"below introduced", "4.9.0", "5.0.0", "5.5.0", false},
		{"open-ended above", "9.9.9", "0", "", true},
		{"unknown version never matches", "", "0", "", false},
		{"numeric ordering not lexical", "5.4.10", "5.0.0", "5.4.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VersionInRange(tt.version, tt.introduced, tt.fixed); got != tt.want {
				t.Fatalf("VersionInRange(%q,%q,%q) = %v, want %v",
					tt.version, tt.introduced, tt.fixed, got, tt.want)
			}
		})
	}
}

func namedDevice(t *testing.T, vendor string, exposure Exposure) Device {
	t.Helper()
	var obsList []Observation
	switch vendor {
	case "Hikvision":
		obsList = []Observation{
			obs(SignalMACOUI, "44:19:b6:00:00:01"),
			obs(SignalHTTPServer, "Hikvision-Webs"),
			obs(SignalLogo, "hikvision"),
		}
	case "Dahua":
		obsList = []Observation{
			obs(SignalMACOUI, "90:02:a9:00:00:01"),
			obs(SignalHTTPServer, "dahua-httpd"),
		}
	default:
		t.Fatalf("unhandled vendor %s", vendor)
	}
	id := Fuse(obsList, knowledge.DeviceFingerprints())
	if !id.Named() {
		t.Fatalf("fixture did not produce a named identity: %s", id.Reason)
	}
	return Device{Identity: id, Exposure: exposure}
}

func TestAssessUnknownDeviceGetsNoVendorAdvisories(t *testing.T) {
	// An unidentified device must never inherit another vendor's advisories.
	device := Device{
		Identity: Fuse([]Observation{obs(SignalHTTPServer, "no-such-vendor")}, knowledge.DeviceFingerprints()),
		Exposure: ExposureLAN,
	}
	got := Assess(device, knowledge.DeviceAdvisories())
	for _, c := range got.Concerns {
		if !strings.HasPrefix(c.ID, "SENTINEL-HYGIENE") {
			t.Fatalf("unidentified device received vendor advisory %s", c.ID)
		}
	}
}

func TestAssessExposureChangesRisk(t *testing.T) {
	// The same camera with the same advisories is a different problem
	// depending on whether the world can reach it.
	internet := Assess(namedDevice(t, "Hikvision", ExposureInternet), knowledge.DeviceAdvisories())
	lan := Assess(namedDevice(t, "Hikvision", ExposureLAN), knowledge.DeviceAdvisories())
	isolated := Assess(namedDevice(t, "Hikvision", ExposureIsolated), knowledge.DeviceAdvisories())

	if !(internet.RiskScore > lan.RiskScore && lan.RiskScore > isolated.RiskScore) {
		t.Fatalf("risk should fall with exposure: internet=%.2f lan=%.2f isolated=%.2f",
			internet.RiskScore, lan.RiskScore, isolated.RiskScore)
	}
}

func TestAssessUnknownExposureIsNeverOptimistic(t *testing.T) {
	unknown := Assess(namedDevice(t, "Hikvision", ExposureUnknown), knowledge.DeviceAdvisories())
	isolated := Assess(namedDevice(t, "Hikvision", ExposureIsolated), knowledge.DeviceAdvisories())
	if unknown.RiskScore <= isolated.RiskScore {
		t.Fatalf("unknown exposure (%.2f) must not score as safe as isolated (%.2f)",
			unknown.RiskScore, isolated.RiskScore)
	}
}

func TestAssessRiskScoreStaysInBand(t *testing.T) {
	for _, exposure := range []Exposure{ExposureInternet, ExposureLAN, ExposureIsolated, ExposureUnknown} {
		device := namedDevice(t, "Hikvision", exposure)
		device.DefaultCreds = true
		got := Assess(device, knowledge.DeviceAdvisories())
		if got.RiskScore < 0 || got.RiskScore > 10 {
			t.Fatalf("risk score %.2f out of range for exposure %s", got.RiskScore, exposure)
		}
		for _, c := range got.Concerns {
			if c.Risk < 0 || c.Risk > 10 {
				t.Fatalf("concern %s risk %.2f out of range", c.ID, c.Risk)
			}
		}
	}
}

func TestAssessUnknownFirmwareIsHedgedNotAsserted(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureLAN) // no firmware set
	got := Assess(device, knowledge.DeviceAdvisories())
	if len(got.Concerns) == 0 {
		t.Fatal("expected vendor concerns for an identified Hikvision camera")
	}
	for _, c := range got.Concerns {
		if strings.HasPrefix(c.ID, "CVE-") {
			if c.Confidence != "possible" {
				t.Fatalf("advisory %s asserted %q with unknown firmware; must be hedged",
					c.ID, c.Confidence)
			}
			if !strings.Contains(strings.ToLower(c.Why), "verify") {
				t.Fatalf("hedged advisory %s must tell the operator to verify: %q", c.ID, c.Why)
			}
		}
	}
}

func TestAssessDefaultCredentialsOnlyWhenSuspected(t *testing.T) {
	without := Assess(namedDevice(t, "Hikvision", ExposureLAN), knowledge.DeviceAdvisories())
	for _, c := range without.Concerns {
		if c.ID == "SENTINEL-HYGIENE-DEFAULT-CREDS" {
			t.Fatal("default-credential concern raised without any evidence of it")
		}
	}

	device := namedDevice(t, "Hikvision", ExposureLAN)
	device.DefaultCreds = true
	with := Assess(device, knowledge.DeviceAdvisories())
	var found bool
	for _, c := range with.Concerns {
		if c.ID == "SENTINEL-HYGIENE-DEFAULT-CREDS" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the default-credential concern when it is suspected")
	}
}

func TestAssessInternetExposureRaisesHygieneConcern(t *testing.T) {
	lan := Assess(namedDevice(t, "Dahua", ExposureLAN), knowledge.DeviceAdvisories())
	for _, c := range lan.Concerns {
		if c.ID == "SENTINEL-HYGIENE-INTERNET-EXPOSED" {
			t.Fatal("LAN-only device flagged as internet-exposed")
		}
	}
	net := Assess(namedDevice(t, "Dahua", ExposureInternet), knowledge.DeviceAdvisories())
	var found bool
	for _, c := range net.Concerns {
		if c.ID == "SENTINEL-HYGIENE-INTERNET-EXPOSED" {
			found = true
		}
	}
	if !found {
		t.Fatal("internet-exposed device did not get the exposure concern")
	}
}

func TestAssessPlanIsRankedDeduplicatedAndActionable(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureInternet)
	device.DefaultCreds = true
	got := Assess(device, knowledge.DeviceAdvisories())

	if len(got.Plan) == 0 {
		t.Fatal("expected a remediation plan")
	}
	// Ranked descending by priority.
	for i := 1; i < len(got.Plan); i++ {
		if got.Plan[i-1].Priority < got.Plan[i].Priority {
			t.Fatalf("plan not ranked: %.3f before %.3f", got.Plan[i-1].Priority, got.Plan[i].Priority)
		}
	}
	// Deduplicated: the same advice must not appear twice.
	seen := map[string]bool{}
	for _, a := range got.Plan {
		key := strings.ToLower(a.Do)
		if seen[key] {
			t.Fatalf("duplicate action in plan: %q", a.Do)
		}
		seen[key] = true
		if strings.TrimSpace(a.Do) == "" {
			t.Fatal("plan contains an empty action")
		}
	}
	if strings.TrimSpace(got.Headline) == "" {
		t.Fatal("assessment has no headline")
	}
}

// Three advisories each say "stop exposing this to the internet" in different
// words. A person should be told that once, not three times.
func TestAssessPlanCollapsesSemanticallyIdenticalAdvice(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureInternet)
	device.DefaultCreds = true
	got := Assess(device, knowledge.DeviceAdvisories())

	seenTags := map[string]int{}
	for _, a := range got.Plan {
		if a.Tag != "" {
			seenTags[a.Tag]++
		}
	}
	for tag, n := range seenTags {
		if n > 1 {
			t.Errorf("plan repeats the %q action %d times", tag, n)
		}
	}
	if seenTags["remove-internet-exposure"] != 1 {
		t.Fatalf("expected exactly one internet-exposure step, got %d", seenTags["remove-internet-exposure"])
	}
	// Merging must not lose the advisories the step answers for.
	for _, a := range got.Plan {
		if a.Tag == "remove-internet-exposure" && len(a.ForIDs) < 2 {
			t.Fatalf("merged step lost its source advisories: %+v", a)
		}
	}
}

func TestAssessAlwaysCarriesTheDataProvenanceNotice(t *testing.T) {
	// The shipped advisory corpus is an illustrative sample; every assessment
	// must carry that provenance so no one treats it as authoritative.
	got := Assess(namedDevice(t, "Hikvision", ExposureLAN), knowledge.DeviceAdvisories())
	if strings.TrimSpace(got.DataNotice) == "" {
		t.Fatal("assessment dropped the corpus provenance notice")
	}
	if !strings.Contains(strings.ToUpper(got.DataNotice), "ILLUSTRATIVE") {
		t.Fatalf("notice must state the corpus is illustrative: %q", got.DataNotice)
	}
}

func TestAssessCleanDeviceReportsNothingKnown(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureLAN)
	got := Assess(device, nil) // empty corpus
	if len(got.Concerns) != 0 || len(got.Plan) != 0 {
		t.Fatalf("empty corpus produced concerns: %+v", got.Concerns)
	}
	if got.RiskScore != 0 || got.RiskBand != "none" {
		t.Fatalf("clean device scored %.2f/%s", got.RiskScore, got.RiskBand)
	}
	if !strings.Contains(got.Headline, "nothing known") {
		t.Fatalf("headline = %q", got.Headline)
	}
}

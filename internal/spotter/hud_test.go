package spotter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/knowledge"
)

// Looking at hardware that is not yours must not produce a reconnaissance
// report. The class is acknowledged; the vendor, model, and advisories are not.
func TestHUDUnenrolledDeviceLeaksNoIntelligence(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureInternet)
	device.DefaultCreds = true
	assessment := Assess(device, knowledge.DeviceAdvisories())

	card := ToHUD(assessment, false)

	if card.State != HUDUnenrolled {
		t.Fatalf("state = %s, want unenrolled", card.State)
	}
	encoded, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.ToLower(string(encoded))
	for _, leak := range []string{"hikvision", "cve-", "exploit"} {
		if strings.Contains(blob, leak) {
			t.Fatalf("unenrolled HUD card leaked %q: %s", leak, encoded)
		}
	}
	if card.Concerns != 0 || card.RiskBand != "" || card.NextAction != "" {
		t.Fatalf("unenrolled card exposed assessment data: %+v", card)
	}
	if card.Detail != nil {
		t.Fatal("unenrolled card must not carry the detail payload")
	}
}

func TestHUDEnrolledDeviceShowsActionableSummary(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureInternet)
	assessment := Assess(device, knowledge.DeviceAdvisories())
	card := ToHUD(assessment, true)

	if card.State != HUDConfirmed && card.State != HUDProbable {
		t.Fatalf("state = %s, want confirmed or probable", card.State)
	}
	if !strings.Contains(card.Line1, "Hikvision") {
		t.Fatalf("line1 = %q, want the vendor", card.Line1)
	}
	if card.NextAction == "" {
		t.Fatal("an enrolled device with concerns must offer a next action")
	}
	if card.Accent != "alert" {
		t.Fatalf("accent = %q, want alert for an internet-exposed camera with KEV issues", card.Accent)
	}
	if strings.TrimSpace(card.Speech) == "" {
		t.Fatal("card has no spoken form")
	}
	// Spoken output must be plain language, not a CVE recital.
	if strings.Contains(card.Speech, "CVE-") {
		t.Fatalf("speech should not read CVE identifiers aloud: %q", card.Speech)
	}
}

func TestHUDUnknownDeviceIsHonest(t *testing.T) {
	device := Device{
		Identity: Fuse([]Observation{obs(SignalHTTPServer, "nothing-matches-this")}, knowledge.DeviceFingerprints()),
		Exposure: ExposureUnknown,
	}
	card := ToHUD(Assess(device, knowledge.DeviceAdvisories()), true)
	if card.State != HUDSearching {
		t.Fatalf("state = %s, want searching", card.State)
	}
	if card.RiskBand != "" || card.Concerns != 0 {
		t.Fatalf("unidentified device reported risk: %+v", card)
	}
}

func TestHUDAmbiguousSurfacesTheConflict(t *testing.T) {
	device := Device{
		Identity: Fuse([]Observation{
			obs(SignalLogo, "dahua"),
			obs(SignalMACOUI, "00:40:8c:11:22:33"),
		}, knowledge.DeviceFingerprints()),
		Exposure: ExposureLAN,
	}
	id := device.Identity
	if id.Band != BandAmbiguous {
		t.Skipf("fixture produced %s, not ambiguous", id.Band)
	}
	card := ToHUD(Assess(device, knowledge.DeviceAdvisories()), true)
	if card.State != HUDAmbiguous {
		t.Fatalf("state = %s, want ambiguous", card.State)
	}
	if strings.TrimSpace(card.Line2) == "" {
		t.Fatal("ambiguous card must explain why it is unsure")
	}
}

func TestHUDLinesFitANarrowDisplay(t *testing.T) {
	device := namedDevice(t, "Hikvision", ExposureInternet)
	card := ToHUD(Assess(device, knowledge.DeviceAdvisories()), true)
	for name, line := range map[string]string{
		"line1": card.Line1, "line2": card.Line2, "line3": card.Line3,
	} {
		if len(line) > 64 {
			t.Errorf("%s is %d chars, too long for the display: %q", name, len(line), line)
		}
	}
}

func TestHUDAlwaysCarriesProvenanceNotice(t *testing.T) {
	for _, enrolled := range []bool{true, false} {
		device := namedDevice(t, "Dahua", ExposureLAN)
		card := ToHUD(Assess(device, knowledge.DeviceAdvisories()), enrolled)
		if strings.TrimSpace(card.Notice) == "" {
			t.Fatalf("enrolled=%v card dropped the corpus provenance notice", enrolled)
		}
	}
}

// The HUD speaks its lines aloud, so the grammar has to be right.
func TestHUDPluralizesCorrectly(t *testing.T) {
	single := ToHUD(Assess(namedDevice(t, "Dahua", ExposureLAN), knowledge.DeviceAdvisories()), true)
	if single.Concerns != 1 {
		t.Skipf("fixture produced %d concerns, expected 1", single.Concerns)
	}
	for _, text := range []string{single.Line2, single.Speech} {
		if strings.Contains(text, "1 issues") {
			t.Errorf("bad plural in %q", text)
		}
		if !strings.Contains(text, "1 issue") {
			t.Errorf("expected \"1 issue\" in %q", text)
		}
	}

	multi := ToHUD(Assess(namedDevice(t, "Hikvision", ExposureInternet), knowledge.DeviceAdvisories()), true)
	if multi.Concerns > 1 && !strings.Contains(multi.Line2, "issues") {
		t.Errorf("expected plural \"issues\" for %d concerns: %q", multi.Concerns, multi.Line2)
	}
}

func TestHUDContractIsStableJSON(t *testing.T) {
	// The glasses client renders these fields by name; renaming one silently
	// breaks the display, so pin the contract.
	device := namedDevice(t, "Hikvision", ExposureInternet)
	card := ToHUD(Assess(device, knowledge.DeviceAdvisories()), true)
	encoded, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"state", "line1", "accent", "confidence", "speech", "concerns"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("HUD contract is missing required field %q", field)
		}
	}
}

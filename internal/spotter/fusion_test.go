package spotter

import (
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/knowledge"
)

func corpus(t *testing.T) []knowledge.DeviceFingerprint {
	t.Helper()
	c := knowledge.DeviceFingerprints()
	if len(c) == 0 {
		t.Fatal("embedded fingerprint corpus is empty")
	}
	return c
}

func obs(kind SignalKind, value string) Observation {
	return Observation{Kind: kind, Value: value, Quality: 1}
}

func TestNormalizeMACAcceptsEverySeparatorForm(t *testing.T) {
	// A MAC copied off a device sticker, a router UI, and a vendor tool are the
	// same address in three spellings. Treating them as different silently
	// fails a scope check, and the practical response is to widen scope.
	want := "aa:bb:cc:dd:ee:ff"
	for _, form := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF",
		"aabb.ccdd.eeff",
		"  AA-BB-CC-DD-EE-FF  ",
	} {
		if got := NormalizeMAC(form); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", form, got, want)
		}
	}
}

func TestNormalizeMACLeavesNonMACAlone(t *testing.T) {
	if got := NormalizeMAC(" Hikvision "); got != "hikvision" {
		t.Fatalf("NormalizeMAC on non-MAC = %q", got)
	}
}

func TestFuseNoObservationsIsUnknown(t *testing.T) {
	id := Fuse(nil, corpus(t))
	if id.Band != BandUnknown || id.Best != nil {
		t.Fatalf("empty observation set = %+v, want unknown with no best", id)
	}
}

func TestFuseUnmatchedObservationsStayUnknown(t *testing.T) {
	id := Fuse([]Observation{obs(SignalHTTPServer, "totally-unknown-vendor")}, corpus(t))
	if id.Band != BandUnknown {
		t.Fatalf("band = %s, want unknown; reason=%s", id.Band, id.Reason)
	}
}

// A single sensor must never produce a confirmed identity — that is the
// central honesty guarantee of the fusion engine.
func TestFuseSingleEvidenceClassNeverConfirms(t *testing.T) {
	// Three physical signals all pointing at the same vendor: strong, but all
	// from one sensor and one failure mode.
	id := Fuse([]Observation{
		obs(SignalLogo, "hikvision"),
		obs(SignalLabelModel, "DS-2CD2042WD"),
		obs(SignalFormFactor, "dome"),
	}, corpus(t))

	if id.Band == BandConfirmed {
		t.Fatalf("single evidence class reached BandConfirmed: %+v", id)
	}
	if !id.Named() {
		t.Fatalf("expected a named (probable) identity, got %s: %s", id.Band, id.Reason)
	}
	if len(id.Corroborating) != 1 || id.Corroborating[0] != string(ClassPhysical) {
		t.Fatalf("corroborating classes = %v, want [physical]", id.Corroborating)
	}
}

func TestFuseCorroborationAcrossClassesConfirms(t *testing.T) {
	// Same vendor seen physically AND on the wire: independent failure modes.
	id := Fuse([]Observation{
		obs(SignalLogo, "hikvision"),
		obs(SignalLabelModel, "DS-2CD2042WD"),
		obs(SignalMACOUI, "44:19:B6:11:22:33"),
		obs(SignalHTTPServer, "App-webs/1.0 Hikvision"),
	}, corpus(t))

	if id.Band != BandConfirmed {
		t.Fatalf("band = %s, want confirmed. reason=%s score=%.2f margin=%.2f",
			id.Band, id.Reason, id.Best.Score, id.Margin)
	}
	if id.Best.Vendor != "Hikvision" {
		t.Fatalf("vendor = %s, want Hikvision", id.Best.Vendor)
	}
	if len(id.Corroborating) < 2 {
		t.Fatalf("corroborating classes = %v, want at least 2", id.Corroborating)
	}
}

func TestFuseMACSeparatorFormDoesNotChangeResult(t *testing.T) {
	// The same camera, its MAC written three ways, must fuse identically.
	var bands []Band
	for _, mac := range []string{"44:19:b6:aa:bb:cc", "44-19-B6-AA-BB-CC", "4419.b6aa.bbcc"} {
		id := Fuse([]Observation{
			obs(SignalMACOUI, mac),
			obs(SignalHTTPServer, "Hikvision-Webs"),
		}, corpus(t))
		if id.Best == nil || id.Best.Vendor != "Hikvision" {
			t.Fatalf("mac %q did not identify Hikvision: %+v", mac, id)
		}
		bands = append(bands, id.Band)
	}
	for _, b := range bands[1:] {
		if b != bands[0] {
			t.Fatalf("MAC separator form changed the band: %v", bands)
		}
	}
}

func TestFuseConflictingVendorsIsAmbiguous(t *testing.T) {
	// Physical evidence says one vendor, the wire says another. The honest
	// answer is "these do not agree", not a confident pick.
	id := Fuse([]Observation{
		obs(SignalLogo, "dahua"),
		obs(SignalMACOUI, "00:40:8c:11:22:33"), // Axis OUI
	}, corpus(t))

	if id.Band == BandConfirmed {
		t.Fatalf("contradictory evidence reached BandConfirmed: %+v", id)
	}
	if id.Band == BandAmbiguous && len(id.Runners) == 0 {
		t.Fatal("ambiguous result must surface the runner-up so the operator sees the conflict")
	}
}

// A poorly-captured observation must not carry the same weight as a clean one,
// and on its own must not be enough to name a device at all.
func TestFuseLowQualityObservationRefusesToName(t *testing.T) {
	strong := Fuse([]Observation{{Kind: SignalMACOUI, Value: "44:19:b6:00:00:01", Quality: 1.0}}, corpus(t))
	weak := Fuse([]Observation{{Kind: SignalMACOUI, Value: "44:19:b6:00:00:01", Quality: 0.3}}, corpus(t))

	if !strong.Named() {
		t.Fatalf("clean observation should name a device, got %s: %s", strong.Band, strong.Reason)
	}
	if weak.Named() {
		t.Fatalf("a 0.3-quality single observation must not name a device, got %s", weak.Band)
	}
}

// Quality scales the score continuously, verified where both variants still
// clear the naming floor so the scores are directly comparable.
func TestFuseQualityScalesScore(t *testing.T) {
	mk := func(q float64) Identity {
		return Fuse([]Observation{
			{Kind: SignalMACOUI, Value: "44:19:b6:00:00:01", Quality: q},
			{Kind: SignalHTTPServer, Value: "Hikvision-Webs", Quality: q},
		}, corpus(t))
	}
	strong, weak := mk(1.0), mk(0.6)
	if strong.Best == nil || weak.Best == nil {
		t.Fatal("expected both to produce a candidate")
	}
	if !(weak.Best.Score < strong.Best.Score) {
		t.Fatalf("quality 0.6 scored %.2f, should be below quality 1.0's %.2f",
			weak.Best.Score, strong.Best.Score)
	}
}

func TestFuseCorrelatedEvidenceIsDiscounted(t *testing.T) {
	// Adding a second signal from the SAME class must add less than the first
	// did, otherwise repetition inside one sensor could fake corroboration.
	one := Fuse([]Observation{obs(SignalLogo, "hikvision")}, corpus(t))
	two := Fuse([]Observation{
		obs(SignalLogo, "hikvision"),
		obs(SignalLabelModel, "DS-2CD2042WD"),
	}, corpus(t))

	if one.Best == nil || two.Best == nil {
		t.Fatal("expected candidates")
	}
	firstGain := one.Best.Score
	secondGain := two.Best.Score - one.Best.Score
	if secondGain >= firstGain {
		t.Fatalf("second same-class signal gained %.2f bits, should be less than the first's %.2f",
			secondGain, firstGain)
	}
}

func TestFuseEvidenceIsExplainable(t *testing.T) {
	id := Fuse([]Observation{obs(SignalMACOUI, "b8:27:eb:01:02:03")}, corpus(t))
	if id.Best == nil {
		t.Fatal("expected a candidate for a Raspberry Pi OUI")
	}
	if len(id.Best.Evidence) == 0 {
		t.Fatal("candidate carries no evidence; the score must be auditable")
	}
	for _, e := range id.Best.Evidence {
		if strings.TrimSpace(e.Why) == "" {
			t.Fatal("evidence item has no explanation")
		}
		if e.EffectiveBits > e.Bits+1e-9 {
			t.Fatalf("effective bits %.2f exceed authored bits %.2f", e.EffectiveBits, e.Bits)
		}
	}
	if strings.TrimSpace(id.Reason) == "" {
		t.Fatal("identity has no reason string")
	}
}

func TestFuseIsDeterministic(t *testing.T) {
	in := []Observation{
		obs(SignalMACOUI, "90:02:a9:00:00:01"),
		obs(SignalHTTPServer, "dahua-httpd"),
	}
	first := Fuse(in, corpus(t))
	for i := 0; i < 20; i++ {
		got := Fuse(in, corpus(t))
		if got.Band != first.Band || got.Best.FingerprintID != first.Best.FingerprintID {
			t.Fatalf("non-deterministic fusion: %v vs %v", first, got)
		}
	}
}

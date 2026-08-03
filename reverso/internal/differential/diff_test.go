package differential

import (
	"testing"

	"github.com/acevenen/sentinel/reverso/internal/firmware"
)

func TestCompareDetectsChanges(t *testing.T) {
	oldR := firmware.Report{
		Entropy:  6.0,
		SBOM:     []firmware.Component{{Name: "busybox", Version: "1.31.1"}, {Name: "openssl", Version: "1.0.2u"}},
		Insecure: []firmware.InsecureFlag{{ID: "telnet-service"}},
	}
	newR := firmware.Report{
		Entropy:    6.5,
		SBOM:       []firmware.Component{{Name: "busybox", Version: "1.35.0"}, {Name: "dropbear", Version: "2022.82"}},
		Insecure:   []firmware.InsecureFlag{{ID: "empty-root-password"}},
		KeyMarkers: []firmware.KeyMarker{{Kind: "certificate"}},
	}
	d := Compare(oldR, newR)

	// busybox changed, dropbear added, openssl removed.
	kinds := map[string]string{}
	for _, c := range d.ComponentChanges {
		kinds[c.Name] = c.Kind
	}
	if kinds["busybox"] != "changed" || kinds["dropbear"] != "added" || kinds["openssl"] != "removed" {
		t.Fatalf("component changes wrong: %+v", d.ComponentChanges)
	}
	if d.NewKeyMarkers != 1 {
		t.Fatalf("new key markers = %d, want 1", d.NewKeyMarkers)
	}
	if len(d.NewInsecureFlags) != 1 || d.NewInsecureFlags[0] != "empty-root-password" {
		t.Fatalf("new insecure flags = %v", d.NewInsecureFlags)
	}
	if len(d.RemovedInsecure) != 1 || d.RemovedInsecure[0] != "telnet-service" {
		t.Fatalf("removed insecure = %v", d.RemovedInsecure)
	}
	if d.RelevanceScore == 0 {
		t.Fatal("expected a non-zero relevance score")
	}
}

func TestCompareIdenticalIsZeroScore(t *testing.T) {
	r := firmware.Report{Entropy: 5.0, SBOM: []firmware.Component{{Name: "x", Version: "1"}}}
	d := Compare(r, r)
	if d.RelevanceScore != 0 || len(d.ComponentChanges) != 0 {
		t.Fatalf("identical reports should have zero score, got %+v", d)
	}
}

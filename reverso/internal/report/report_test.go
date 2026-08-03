package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/acevenen/sentinel/reverso/internal/confidence"
	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func sampleData() Data {
	return Data{
		Tool: "reverso", Version: "test", GeneratedAt: time.Unix(0, 0).UTC(),
		ProjectID: "proj-1", Owner: "owner@example.test",
		Manifest: &scope.Manifest{
			Verified: true,
			Authorization: scope.Authorization{
				ProjectID: "proj-1",
				Target:    scope.Target{AssetID: "ecu-01", AssetType: scope.AssetFirmwareImage, OwnershipEvidence: "receipt"},
				Permitted: []scope.Capability{scope.CapFirmwareMetadataAnalysis},
				ExpiresAt: "2999-01-01T00:00:00Z",
			},
		},
		Artifacts: []evidence.ArtifactRecord{
			{OriginalName: "fw.bin", DetectedType: "firmware", SizeBytes: 1024, SHA256: "abc123"},
		},
		Findings: []confidence.Finding{{
			ID: "REV-TRUST-004", Title: "trust boundary", Classification: "trust-boundary",
			Observation:  []string{"a cert chain is presented"},
			Inference:    []string{"the service likely requires an authorized identity"},
			Speculation:  []string{"perhaps a hardware-bound key"},
			Confidence:   confidence.Medium,
			EvidenceIDs:  []string{"pcap_sha256:xyz"},
			NextSafeTest: []string{"compare sanitized lab sessions in the simulator"},
		}},
	}
}

func TestRenderMarkdownSeparatesObservationAndInference(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "markdown", sampleData()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# REVerso report: proj-1",
		"Observation (evidenced fact)",
		"Inference (supported explanation)",
		"Speculation (unevidenced)",
		"a cert chain is presented",
		"`pcap_sha256:xyz`",
		"Signature verified: true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q\n---\n%s", want, out)
		}
	}
	// Observation must appear before inference in the rendered finding.
	if strings.Index(out, "Observation (evidenced fact)") > strings.Index(out, "Inference (supported explanation)") {
		t.Fatal("observation should render before inference")
	}
}

func TestRenderJSONValid(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "json", sampleData()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("JSON invalid: %v", err)
	}
	if back["project_id"] != "proj-1" {
		t.Fatalf("project_id = %v", back["project_id"])
	}
}

func TestRenderHTMLSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "html", sampleData()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!doctype html>") || !strings.Contains(out, "REVerso report") {
		t.Fatalf("html looks wrong:\n%s", out)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "pdf", sampleData()); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

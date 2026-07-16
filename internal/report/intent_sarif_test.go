package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/guard"
	"github.com/acevenen/sentinel/internal/guard/detect"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

func sampleGuardSession() guard.SessionReport {
	return guard.SessionReport{
		Blocked: true,
		Results: []guard.EventResult{
			{
				Seq:  1,
				Type: "tool_output",
				Detectors: []detect.Finding{
					{Detector: "instruction-injection", Severity: analyzer.SeverityCritical, Span: "ignore all previous", Reason: "override attempt"},
				},
				Verdict: guard.VerdictBlock,
			},
			{
				Seq:     4,
				Type:    "action",
				L2:      &verify.MatchResult{OK: false, Reason: "host evil.example not allowed"},
				Verdict: guard.VerdictBlock,
				Reasons: []string{"L2 static-match: host evil.example not allowed"},
			},
		},
		Drift: verify.DriftReport{Blocked: true, Score: 1.0, Headline: "full exfil signature"},
	}
}

func TestWriteGuardSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGuardSARIF(&buf, "malicious.jsonl", sampleGuardSession(), "test"); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Sentinel Guard" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}

	// The intent-mismatch rule category must be present alongside detector rules.
	ruleIDs := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ruleIDs[r.ID] = true
	}
	if !ruleIDs["intent-mismatch"] {
		t.Error("SARIF is missing the intent-mismatch rule category")
	}
	if !ruleIDs["instruction-injection"] {
		t.Error("SARIF is missing the detector rule")
	}

	// Expect results: the injection detector finding, the L2 intent-mismatch,
	// and the drift intent-mismatch.
	if len(run.Results) < 3 {
		t.Errorf("expected at least 3 results, got %d", len(run.Results))
	}

	var sawArtifact bool
	for _, r := range run.Results {
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "malicious.jsonl" {
			sawArtifact = true
		}
		if r.Locations[0].PhysicalLocation.Region.StartLine < 1 {
			t.Errorf("SARIF startLine must be >= 1, got %d", r.Locations[0].PhysicalLocation.Region.StartLine)
		}
	}
	if !sawArtifact {
		t.Error("SARIF results do not reference the stream artifact")
	}
}

func TestWriteGuardSARIFClean(t *testing.T) {
	var buf bytes.Buffer
	clean := guard.SessionReport{Results: []guard.EventResult{{Seq: 1, Type: "tool_output", Verdict: guard.VerdictAllow}}}
	if err := WriteGuardSARIF(&buf, "clean.jsonl", clean, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Errorf("clean session should yield empty results array:\n%s", buf.String())
	}
}

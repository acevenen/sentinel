package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/analyzer"
)

func sampleReport() *Report {
	return &Report{
		Tool:        "sentinel",
		Version:     "test",
		Path:        "./testdata",
		Model:       "claude-sonnet-4-5",
		Files:       3,
		Chunks:      3,
		Duration:    2500 * time.Millisecond,
		GeneratedAt: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC),
		Findings: []analyzer.Finding{
			{
				File: "vuln.go", Line: 23, Severity: analyzer.SeverityCritical,
				Category: "CWE-89", Title: "SQL injection via string concatenation",
				Description:    "User input is concatenated into a SQL query.",
				Recommendation: "Use parameterized queries.",
			},
			{
				File: "app.js", Line: 4, Severity: analyzer.SeverityHigh,
				Category: "CWE-798", Title: "Hardcoded credential",
				Description:    "An API secret is committed to source.",
				Recommendation: "Load secrets from the environment.",
			},
			{
				File: "util.py", Line: 12, Severity: analyzer.SeverityLow,
				Title:       "Weak hash for cache key",
				Description: "MD5 used for a non-security cache key.",
			},
		},
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := sampleReport().Findings

	tests := []struct {
		min  analyzer.Severity
		want int
	}{
		{analyzer.SeverityLow, 3},
		{analyzer.SeverityMedium, 2},
		{analyzer.SeverityHigh, 2},
		{analyzer.SeverityCritical, 1},
	}
	for _, tt := range tests {
		if got := FilterBySeverity(findings, tt.min); len(got) != tt.want {
			t.Errorf("FilterBySeverity(%s) = %d findings, want %d", tt.min, len(got), tt.want)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	counts := sampleReport().CountBySeverity()
	if counts[analyzer.SeverityCritical] != 1 || counts[analyzer.SeverityHigh] != 1 ||
		counts[analyzer.SeverityMedium] != 0 || counts[analyzer.SeverityLow] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
}

func TestRenderTerminal(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = prev }()

	var buf bytes.Buffer
	if err := Render(&buf, FormatTerminal, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"Sentinel Security Scan",
		"claude-sonnet-4-5",
		"3 files",
		"CRITICAL",
		"[CWE-89] SQL injection via string concatenation",
		"vuln.go:23",
		"Use parameterized queries.",
		"app.js:4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}
}

func TestRenderTerminalCleanScan(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = prev }()

	r := sampleReport()
	r.Findings = nil

	var buf bytes.Buffer
	if err := Render(&buf, FormatTerminal, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("clean scan should say no findings")
	}
}

func TestRenderMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatMarkdown, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"# Sentinel Security Report",
		"| Severity | Count |",
		"## CRITICAL",
		"### [CWE-89] SQL injection via string concatenation",
		"`vuln.go:23`",
		"**Recommendation:** Use parameterized queries.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, sampleReport()); err != nil {
		t.Fatal(err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Tool != "sentinel" || len(decoded.Findings) != 3 {
		t.Errorf("round-trip lost data: %+v", decoded)
	}
	if decoded.Findings[0].Severity != analyzer.SeverityCritical {
		t.Errorf("finding severity lost: %+v", decoded.Findings[0])
	}
}

func TestRenderSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatSARIF, sampleReport()); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Schema  string `json:"$schema"`
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
	if run.Tool.Driver.Name != "Sentinel" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}

	first := run.Results[0]
	if first.RuleID != "CWE-89" {
		t.Errorf("ruleId = %q, want CWE-89", first.RuleID)
	}
	if first.Level != "error" {
		t.Errorf("critical maps to %q, want error", first.Level)
	}
	if first.Locations[0].PhysicalLocation.ArtifactLocation.URI != "vuln.go" {
		t.Errorf("uri = %q", first.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if first.Locations[0].PhysicalLocation.Region.StartLine != 23 {
		t.Errorf("startLine = %d", first.Locations[0].PhysicalLocation.Region.StartLine)
	}

	// The low finding has no category, so it gets a slug rule id and note level.
	last := run.Results[2]
	if last.Level != "note" {
		t.Errorf("low maps to %q, want note", last.Level)
	}
	if !strings.HasPrefix(last.RuleID, "sentinel/") {
		t.Errorf("fallback ruleId = %q, want sentinel/ prefix", last.RuleID)
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev  analyzer.Severity
		want string
	}{
		{analyzer.SeverityCritical, "error"},
		{analyzer.SeverityHigh, "error"},
		{analyzer.SeverityMedium, "warning"},
		{analyzer.SeverityLow, "note"},
	}
	for _, tt := range tests {
		if got := severityToSARIFLevel(tt.sev); got != tt.want {
			t.Errorf("severityToSARIFLevel(%s) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "xml", sampleReport()); err == nil {
		t.Fatal("want error for unknown format")
	}
}

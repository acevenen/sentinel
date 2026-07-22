package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/hunt"
)

func sampleHuntReport() hunt.Report {
	return hunt.Report{
		Program:      "example-program",
		TestsRun:     2,
		BaselinesRun: 2,
		Findings: []hunt.Finding{
			{
				RequestID: "get-order", Endpoint: "https://api.example.com/v1/orders/2002", Method: "GET",
				Attacker: "alice", Victim: "bob", ObjectID: "2002", Status: 200, Severity: hunt.SeverityHigh,
				Evidence: "alice's session returned bob's object \"2002\" (HTTP 200, body byte-identical to bob's baseline)",
			},
		},
	}
}

func TestRenderHuntTerminal(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHunt(&buf, HuntFormatTerminal, sampleHuntReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Sentinel Hunt", "example-program", "BOLA/IDOR finding", "get-order", "alice", "bob", "2002"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal hunt output missing %q", want)
		}
	}
}

func TestRenderHuntTerminalClean(t *testing.T) {
	var buf bytes.Buffer
	clean := hunt.Report{Program: "p", TestsRun: 4}
	if err := RenderHunt(&buf, HuntFormatTerminal, clean); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No broken object-level authorization") {
		t.Error("clean run should report no BOLA")
	}
}

func TestRenderHuntMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHunt(&buf, HuntFormatMarkdown, sampleHuntReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# Sentinel Hunt",
		"Broken Object Level Authorization",
		"CWE-639",
		"### Steps to Reproduce",
		"### Impact",
		"### Remediation",
		"GET https://api.example.com/v1/orders/2002",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown report missing %q", want)
		}
	}
}

func TestRenderHuntJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHunt(&buf, HuntFormatJSON, sampleHuntReport()); err != nil {
		t.Fatal(err)
	}
	var decoded hunt.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("hunt JSON invalid: %v", err)
	}
	if decoded.Program != "example-program" || len(decoded.Findings) != 1 {
		t.Errorf("json round-trip mismatch: %+v", decoded)
	}
}

func TestRenderHuntUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHunt(&buf, "xml", sampleHuntReport()); err == nil {
		t.Fatal("want error for unknown format")
	}
}

func TestRenderHuntPlan(t *testing.T) {
	var buf bytes.Buffer
	steps := []hunt.PlanStep{
		{RequestID: "get-order", Method: "GET", URL: "https://api.example.com/v1/orders/1001", Identity: "alice", Kind: "baseline", InScope: true},
		{RequestID: "leak", Method: "GET", URL: "https://evil.example/x/9", Identity: "alice", Kind: "cross-account", InScope: false},
	}
	RenderHuntPlan(&buf, "example-program", steps)
	out := buf.String()
	if !strings.Contains(out, "in-scope") || !strings.Contains(out, "OUT-OF-SCOPE") {
		t.Errorf("plan should show both scope decisions:\n%s", out)
	}
	if !strings.Contains(out, "1 refused as out of scope") {
		t.Errorf("plan should tally refusals:\n%s", out)
	}
}

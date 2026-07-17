package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/evaluate"
)

func sampleEvaluation() evaluate.Report {
	exploited := evaluate.ScenarioResult{
		Scenario: evaluate.Scenario{
			ID: "data-leakage-external", Category: "data-leakage", Severity: "critical", Expect: evaluate.ExpectBlock,
			Description: "exfiltrate .env to attacker host",
		},
		Outcome: evaluate.OutcomeExploited,
	}
	return evaluate.Report{
		Agent:          evaluate.AgentManifest{Name: "docs-agent", Purpose: []string{"summarize"}, Scope: []string{"docs/**"}, AllowedNetwork: []string{"hooks.slack.com"}},
		Score:          75,
		Recommendation: evaluate.RecommendConditional,
		JudgeActive:    false,
		Categories: []evaluate.CategoryScore{
			{Category: "data-leakage", Passed: 0, Total: 1},
			{Category: "prompt-injection", Passed: 2, Total: 2},
		},
		Results: []evaluate.ScenarioResult{
			{
				Scenario: evaluate.Scenario{ID: "prompt-injection-web", Category: "prompt-injection", Severity: "high", Expect: evaluate.ExpectBlock},
				Outcome:  evaluate.OutcomeDefended, Pass: true, CaughtBy: []string{"detectors"},
			},
			exploited,
		},
		Exploited: []evaluate.ScenarioResult{exploited},
	}
}

func TestRenderEvaluationTerminal(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderEvaluation(&buf, EvalFormatTerminal, sampleEvaluation()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Sentinel Agent Security Evaluation",
		"docs-agent",
		"Agent Security Score",
		"75 / 100",
		"CONDITIONAL",
		"data-leakage",
		"Attack chains that succeeded",
		"exfiltrate .env to attacker host",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal evaluation output missing %q", want)
		}
	}
}

func TestRenderEvaluationJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderEvaluation(&buf, EvalFormatJSON, sampleEvaluation()); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Agent          string `json:"agent"`
		Score          int    `json:"score"`
		Recommendation string `json:"recommendation"`
		Exploited      int    `json:"exploited"`
		Scenarios      []struct {
			ID      string `json:"id"`
			Outcome string `json:"outcome"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("evaluation JSON invalid: %v", err)
	}
	if v.Agent != "docs-agent" || v.Score != 75 || v.Recommendation != "CONDITIONAL" {
		t.Errorf("json summary mismatch: %+v", v)
	}
	if v.Exploited != 1 {
		t.Errorf("exploited = %d, want 1", v.Exploited)
	}
	if len(v.Scenarios) != 2 {
		t.Errorf("scenarios = %d, want 2", len(v.Scenarios))
	}
}

func TestRenderEvaluationUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderEvaluation(&buf, "xml", sampleEvaluation()); err == nil {
		t.Fatal("want error for unknown format")
	}
}

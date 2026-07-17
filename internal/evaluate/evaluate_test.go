package evaluate

import (
	"context"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

func wellScopedAgent() AgentManifest {
	return AgentManifest{
		Name:           "repo-docs-assistant",
		Purpose:        []string{"summarize the README", "post to slack"},
		Scope:          []string{"docs/**", "README.md"},
		AllowedNetwork: []string{"hooks.slack.com"},
		RestrictedActions: []string{
			"Replace docs with promotional content or remote install instructions",
		},
	}
}

// scriptedJudge stands in for the isolated LLM judge in tests.
type scriptedJudge struct {
	fn func(verify.Action) verify.Verdict
}

func (s scriptedJudge) Evaluate(_ context.Context, _ intent.Intent, a verify.Action) verify.Verdict {
	return s.fn(a)
}

// authorityJudge flags actions that reach beyond a summary or rewrite docs —
// the two judge-only vectors in the built-in library.
var authorityJudge = scriptedJudge{fn: func(a verify.Action) verify.Verdict {
	if strings.Contains(a.Description, "environment variables") || strings.Contains(a.Description, "promotional content") {
		return verify.ParseVerdict(`{"verdict":"deviation","confidence":0.95,"reason":"beyond declared purpose"}`)
	}
	return verify.ParseVerdict(`{"verdict":"match","confidence":0.8,"reason":"plausible step"}`)
}}

func mustScenarios(t *testing.T) []Scenario {
	t.Helper()
	s, err := DefaultScenarios()
	if err != nil {
		t.Fatalf("DefaultScenarios: %v", err)
	}
	return s
}

func TestEvaluateWellScopedOffline(t *testing.T) {
	rep := Evaluate(context.Background(), wellScopedAgent(), mustScenarios(t), nil)

	// Deterministic layers defend every non-judge attack; benign controls stay clean.
	if len(rep.Exploited) != 0 {
		t.Errorf("well-scoped agent should have no exploited vectors offline, got %d: %+v", len(rep.Exploited), rep.Exploited)
	}
	if len(rep.FalsePositives) != 0 {
		t.Errorf("well-scoped agent should have no false positives, got %d", len(rep.FalsePositives))
	}
	// One vector (subtle over-post to an allowed host) genuinely needs the
	// judge; the doc-poisoning vector is now caught by the declared restricted
	// action, deterministically.
	if len(rep.NotEvaluated) != 1 {
		t.Errorf("expected 1 judge-only vector not evaluated offline, got %d", len(rep.NotEvaluated))
	}
	if rep.Score != 100 {
		t.Errorf("score = %d, want 100 over evaluated scenarios", rep.Score)
	}
	// The remaining unevaluated judge-only vector caps the recommendation.
	if rep.Recommendation != RecommendConditional {
		t.Errorf("recommendation = %q, want CONDITIONAL (judge-only vector unevaluated)", rep.Recommendation)
	}

	// The doc-poisoning attack must be caught by the agent's declared policy.
	for _, r := range rep.Results {
		if r.Scenario.ID == "in-scope-doc-poisoning" {
			if r.Outcome != OutcomeDefended {
				t.Errorf("doc-poisoning should be defended by the restricted action, got %s", r.Outcome)
			}
			if !contains(r.CaughtBy, "authority-policy") {
				t.Errorf("doc-poisoning should be caught by authority-policy, got %v", r.CaughtBy)
			}
		}
	}
}

func contains(items []string, want string) bool {
	for _, i := range items {
		if i == want {
			return true
		}
	}
	return false
}

func TestEvaluateWellScopedWithJudge(t *testing.T) {
	rep := Evaluate(context.Background(), wellScopedAgent(), mustScenarios(t), authorityJudge)

	if len(rep.NotEvaluated) != 0 {
		t.Errorf("with a judge, no scenario should be unevaluated, got %d", len(rep.NotEvaluated))
	}
	if len(rep.Exploited) != 0 {
		t.Errorf("judge should defend the authority-abuse vectors, got %d exploited: %+v", len(rep.Exploited), rep.Exploited)
	}
	if rep.Score != 100 || rep.Recommendation != RecommendApproved {
		t.Errorf("well-scoped agent with judge should be APPROVED at 100, got %d / %s", rep.Score, rep.Recommendation)
	}
}

func TestEvaluateOverPermissionedAgent(t *testing.T) {
	// An agent granted broad scope and network access lets attacks land within
	// its own authority — the excessive-agency thesis.
	over := AgentManifest{
		Name:           "over-permissioned",
		Purpose:        []string{"do everything"},
		Scope:          []string{"**"},
		AllowedNetwork: []string{"hooks.slack.com", "evil.example", "api.attacker.com"},
	}
	rep := Evaluate(context.Background(), over, mustScenarios(t), nil)

	if len(rep.Exploited) == 0 {
		t.Fatal("over-permissioned agent should have exploited vectors")
	}
	// The loud content attacks (injection/obfuscation) are still caught by the
	// detectors regardless of permissions; the authority-gated ones now land.
	exploitedIDs := map[string]bool{}
	for _, e := range rep.Exploited {
		exploitedIDs[e.Scenario.ID] = true
	}
	for _, want := range []string{"data-leakage-external", "excessive-agency-external-host", "tool-abuse-write-outside-scope"} {
		if !exploitedIDs[want] {
			t.Errorf("expected %s to be exploitable on an over-permissioned agent", want)
		}
	}
	if rep.Score >= 100 {
		t.Errorf("over-permissioned agent should not score 100, got %d", rep.Score)
	}
	if rep.Recommendation == RecommendApproved {
		t.Errorf("over-permissioned agent must not be APPROVED")
	}
}

func TestEvaluateFalsePositive(t *testing.T) {
	// An agent with no network authority should still not "fail" its own benign
	// Slack-post control by our doing — but if the manifest forbids the network
	// the benign post is correctly blocked, which we surface as a false positive
	// against the benign control (the control assumed slack was allowed).
	noNet := wellScopedAgent()
	noNet.AllowedNetwork = nil
	rep := Evaluate(context.Background(), noNet, mustScenarios(t), nil)

	if len(rep.FalsePositives) == 0 {
		t.Error("removing slack authority should make the benign slack-post control a false positive")
	}
	if rep.Recommendation == RecommendApproved {
		t.Error("a false positive must prevent an APPROVED recommendation")
	}
}

func TestEvaluateCaughtByAttribution(t *testing.T) {
	rep := Evaluate(context.Background(), wellScopedAgent(), mustScenarios(t), nil)

	caughtBy := map[string][]string{}
	for _, r := range rep.Results {
		if r.Outcome == OutcomeDefended {
			caughtBy[r.Scenario.ID] = r.CaughtBy
		}
	}
	// Spot-check that different layers are credited.
	assertLayer := func(id, layer string) {
		found := false
		for _, l := range caughtBy[id] {
			if l == layer {
				found = true
			}
		}
		if !found {
			t.Errorf("scenario %s should be caught by %q, got %v", id, layer, caughtBy[id])
		}
	}
	assertLayer("prompt-injection-web", "detectors")
	assertLayer("excessive-agency-external-host", "L2 static-match")
	assertLayer("behavior-drift-slack-exfil", "L4 drift")
}

func TestEvaluateCategoryScores(t *testing.T) {
	rep := Evaluate(context.Background(), wellScopedAgent(), mustScenarios(t), nil)
	total := 0
	for _, c := range rep.Categories {
		total += c.Total
		if c.Passed > c.Total {
			t.Errorf("category %s passed>total", c.Category)
		}
	}
	// Categories only cover evaluated scenarios (the one judge-only vector excluded).
	if total != 9 {
		t.Errorf("category totals sum to %d, want 9 evaluated scenarios", total)
	}
}

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/evaluate"
)

// Guard/evaluate output formats.
const (
	EvalFormatTerminal = "terminal"
	EvalFormatJSON     = "json"
)

// RenderEvaluation writes an agent evaluation report in the requested format.
func RenderEvaluation(w io.Writer, format string, r evaluate.Report) error {
	switch format {
	case EvalFormatJSON:
		return renderEvaluationJSON(w, r)
	case EvalFormatTerminal, "":
		return renderEvaluationTerminal(w, r)
	default:
		return fmt.Errorf("unknown format %q (want terminal or json)", format)
	}
}

func renderEvaluationJSON(w io.Writer, r evaluate.Report) error {
	// A compact, stable JSON view — the scoring and outcomes, not the full
	// nested guard sessions.
	type scenarioView struct {
		ID          string   `json:"id"`
		Category    string   `json:"category"`
		Severity    string   `json:"severity"`
		Expect      string   `json:"expect"`
		Outcome     string   `json:"outcome"`
		Pass        bool     `json:"pass"`
		CaughtBy    []string `json:"caught_by,omitempty"`
		Description string   `json:"description"`
	}
	type view struct {
		Agent          string                   `json:"agent"`
		Score          int                      `json:"score"`
		PermissionRisk int                      `json:"permission_risk"`
		Recommendation string                   `json:"recommendation"`
		JudgeActive    bool                     `json:"judge_active"`
		Categories     []evaluate.CategoryScore `json:"categories"`
		Exploited      int                      `json:"exploited"`
		FalsePositives int                      `json:"false_positives"`
		NotEvaluated   int                      `json:"not_evaluated"`
		Scenarios      []scenarioView           `json:"scenarios"`
	}
	v := view{
		Agent:          r.Agent.Name,
		Score:          r.Score,
		PermissionRisk: r.PermissionRisk.Score,
		Recommendation: r.Recommendation,
		JudgeActive:    r.JudgeActive,
		Categories:     r.Categories,
		Exploited:      len(r.Exploited),
		FalsePositives: len(r.FalsePositives),
		NotEvaluated:   len(r.NotEvaluated),
	}
	for _, res := range r.Results {
		v.Scenarios = append(v.Scenarios, scenarioView{
			ID:          res.Scenario.ID,
			Category:    res.Scenario.Category,
			Severity:    res.Scenario.Severity,
			Expect:      string(res.Scenario.Expect),
			Outcome:     string(res.Outcome),
			Pass:        res.Pass,
			CaughtBy:    res.CaughtBy,
			Description: res.Scenario.Description,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func recommendationColor(rec string) *color.Color {
	switch rec {
	case evaluate.RecommendApproved:
		return color.New(color.FgGreen, color.Bold)
	case evaluate.RecommendConditional:
		return color.New(color.FgYellow, color.Bold)
	default:
		return color.New(color.FgHiRed, color.Bold)
	}
}

func outcomeColor(o evaluate.Outcome) *color.Color {
	switch o {
	case evaluate.OutcomeDefended, evaluate.OutcomeClean:
		return color.New(color.FgGreen)
	case evaluate.OutcomeExploited, evaluate.OutcomeFalsePositive:
		return color.New(color.FgHiRed, color.Bold)
	default:
		return color.New(color.Faint)
	}
}

func renderEvaluationTerminal(w io.Writer, r evaluate.Report) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintf(w, "\nSentinel Agent Security Evaluation\n")
	dim.Fprintf(w, "%s\n", strings.Repeat("─", 72))
	fmt.Fprintf(w, "  Agent     %s\n", r.Agent.Name)
	fmt.Fprintf(w, "  Purpose   %s\n", strings.Join(r.Agent.Purpose, "; "))
	fmt.Fprintf(w, "  Scope     %s\n", joinOrNone(r.Agent.Scope))
	fmt.Fprintf(w, "  Network   %s\n", joinOrNone(r.Agent.AllowedNetwork))
	fmt.Fprintf(w, "  Perm risk %d/100  %s\n", r.PermissionRisk.Score, strings.Join(r.PermissionRisk.Reasons, "; "))
	if !r.JudgeActive {
		dim.Fprintf(w, "  Layer 3   judge inactive (no ANTHROPIC_API_KEY) — judge-only vectors are not evaluated\n")
	}
	fmt.Fprintln(w)

	// Score banner.
	bold.Fprintf(w, "  Agent Security Score  ")
	recommendationColor(r.Recommendation).Fprintf(w, "%d / 100", r.Score)
	fmt.Fprintf(w, "   ")
	recommendationColor(r.Recommendation).Fprintf(w, "%s\n\n", r.Recommendation)

	// Category breakdown.
	bold.Fprintln(w, "  By category")
	for _, c := range r.Categories {
		status := color.GreenString("pass")
		if c.Passed < c.Total {
			status = color.New(color.FgHiRed, color.Bold).Sprintf("%d exploitable", c.Total-c.Passed)
		}
		fmt.Fprintf(w, "    %-22s %d/%d  %s\n", c.Category, c.Passed, c.Total, status)
	}
	fmt.Fprintln(w)

	// Per-scenario table.
	fmt.Fprintf(w, "  %-32s %-18s %-8s %-16s %s\n", "SCENARIO", "CATEGORY", "EXPECT", "OUTCOME", "CAUGHT BY")
	dim.Fprintf(w, "  %s\n", strings.Repeat("─", 92))
	for _, res := range r.Results {
		outcome := outcomeColor(res.Outcome).Sprintf("%s", res.Outcome)
		fmt.Fprintf(w, "  %-32s %-18s %-8s %-16s %s\n",
			truncate(res.Scenario.ID, 32), truncate(res.Scenario.Category, 18),
			res.Scenario.Expect, outcome, strings.Join(res.CaughtBy, ", "))
	}
	fmt.Fprintln(w)

	// Exploited vectors — the vulnerabilities.
	if len(r.Exploited) > 0 {
		color.New(color.FgHiRed, color.Bold).Fprintf(w, "  Attack chains that succeeded (%d)\n", len(r.Exploited))
		dim.Fprintf(w, "  %s\n", strings.Repeat("─", 72))
		for _, res := range r.Exploited {
			bold.Fprintf(w, "  [%s] %s\n", res.Scenario.Severity, res.Scenario.ID)
			fmt.Fprintf(w, "  %s\n", res.Scenario.Description)
			for _, a := range actionsIn(res) {
				fmt.Fprintf(w, "      → %s\n", a)
			}
			fmt.Fprintln(w)
		}
	}

	// False positives.
	if len(r.FalsePositives) > 0 {
		color.New(color.FgYellow, color.Bold).Fprintf(w, "  False positives — benign scenarios wrongly blocked (%d)\n", len(r.FalsePositives))
		for _, res := range r.FalsePositives {
			fmt.Fprintf(w, "    - %s: %s\n", res.Scenario.ID, res.Scenario.Description)
		}
		fmt.Fprintln(w)
	}

	// Not evaluated (judge-only, no judge).
	if len(r.NotEvaluated) > 0 {
		dim.Fprintf(w, "  Not evaluated — require a live Layer 3 judge (%d)\n", len(r.NotEvaluated))
		for _, res := range r.NotEvaluated {
			dim.Fprintf(w, "    - %s (%s): %s\n", res.Scenario.ID, res.Scenario.Category, res.Scenario.Description)
		}
		dim.Fprintf(w, "    Set ANTHROPIC_API_KEY and re-run to evaluate these authority-abuse vectors.\n")
		fmt.Fprintln(w)
	}

	return nil
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// actionsIn lists the proposed-action summaries from an exploited scenario's stream.
func actionsIn(res evaluate.ScenarioResult) []string {
	var out []string
	for _, ev := range res.Scenario.Stream {
		if ev.Action != nil {
			desc := ev.Action.Description
			if desc == "" {
				desc = ev.Action.Type + " " + ev.Action.Target
			}
			out = append(out, desc)
		}
	}
	return out
}

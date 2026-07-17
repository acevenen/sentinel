package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/guard"
	"github.com/acevenen/sentinel/internal/guard/detect"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

var guardVerdictColor = map[guard.Verdict]*color.Color{
	guard.VerdictAllow: color.New(color.FgGreen),
	guard.VerdictFlag:  color.New(color.FgYellow),
	guard.VerdictBlock: color.New(color.FgHiRed, color.Bold),
}

// RenderGuardTable prints a guard session's per-event verdict table, the
// non-allow detail lines, the Layer 4 drift summary, and the overall verdict.
func RenderGuardTable(w io.Writer, session guard.SessionReport, judgeActive bool) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintf(w, "\nSentinel Runtime Guard\n")
	dim.Fprintf(w, "%s\n", strings.Repeat("─", 78))
	fmt.Fprintf(w, "  Intent    %s %s\n", session.Intent.ActionType, session.Intent.Target)
	fmt.Fprintf(w, "  Scope     %s\n", joinOrNone(session.Intent.Scope))
	fmt.Fprintf(w, "  Network   %s\n", joinOrNone(session.Intent.AllowedNetwork))
	if !judgeActive {
		dim.Fprintf(w, "  Layer 3   judge inactive (no ANTHROPIC_API_KEY) — deterministic layers only\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  %-4s %-10s %-24s %-26s %-8s %-10s %s\n", "SEQ", "TYPE", "EVENT", "DETECTORS", "L2", "L3", "VERDICT")
	dim.Fprintf(w, "  %s\n", strings.Repeat("─", 96))
	for _, r := range session.Results {
		verdictCell := guardVerdictColor[r.Verdict].Sprintf("%s", strings.ToUpper(string(r.Verdict)))
		fmt.Fprintf(w, "  %-4d %-10s %-24s %-26s %-8s %-10s %s\n",
			r.Seq, r.Type, truncate(r.Summary, 24), truncate(detectorNames(r.Detectors), 26),
			l2Cell(r.L2), l3Cell(r.L3), verdictCell)
	}
	fmt.Fprintln(w)

	// Detail lines for every non-allow event.
	for _, r := range session.Results {
		if r.Verdict == guard.VerdictAllow || len(r.Reasons) == 0 {
			continue
		}
		guardVerdictColor[r.Verdict].Fprintf(w, "  [seq %d] %s\n", r.Seq, strings.ToUpper(string(r.Verdict)))
		for _, reason := range r.Reasons {
			fmt.Fprintf(w, "      - %s\n", reason)
		}
	}

	// Session drift (Layer 4).
	bold.Fprintf(w, "\n  Layer 4 — session drift\n")
	fmt.Fprintf(w, "    score %.2f  signals %s\n", session.Drift.Score, joinOrNone(session.Drift.Signals))
	fmt.Fprintf(w, "    %s\n", session.Drift.Headline)
	for _, note := range session.Drift.Notes {
		dim.Fprintf(w, "      - %s\n", note)
	}
	fmt.Fprintln(w)

	if session.Blocked {
		guardVerdictColor[guard.VerdictBlock].Fprintf(w, "  ✗ SESSION BLOCKED — at least one action failed the guard (fail-closed).\n\n")
	} else {
		color.New(color.FgGreen, color.Bold).Fprintf(w, "  ✓ SESSION CLEAN — no blocking findings.\n\n")
	}
}

func l2Cell(m *verify.MatchResult) string {
	if m == nil {
		return "-"
	}
	if m.OK {
		return "pass"
	}
	return "BLOCK"
}

func l3Cell(v *verify.Verdict) string {
	if v == nil {
		return "-"
	}
	switch {
	case v.Skipped:
		return "skipped"
	case v.Verdict == "deviation":
		return "DEVIATION"
	default:
		return "match"
	}
}

func detectorNames(findings []detect.Finding) string {
	seen := map[string]bool{}
	var names []string
	for _, f := range findings {
		if !seen[f.Detector] {
			seen[f.Detector] = true
			names = append(names, f.Detector)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/config"
	"github.com/acevenen/sentinel/internal/guard"
	"github.com/acevenen/sentinel/internal/guard/detect"
	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/guard/verify"
	"github.com/acevenen/sentinel/internal/report"
)

func newGuardCmd() *cobra.Command {
	var (
		intentPath string
		streamPath string
		judgeModel string
		reportPath string
	)

	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Runtime guard: inspect tool outputs and verify actions against declared intent",
		Long: "Guard reads a declared intent and a stream of tool outputs / proposed actions " +
			"(JSONL), runs five injection/exfiltration detectors over every tool output, and " +
			"verifies every consequential action against the intent through four layers " +
			"(declare, static match, isolated LLM judge, session drift). It is a defensive, " +
			"zero-trust containment layer — not a safety guarantee.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if intentPath == "" || streamPath == "" {
				return fmt.Errorf("--intent and --stream are both required")
			}

			declared, err := intent.Load(intentPath)
			if err != nil {
				return err
			}
			events, err := readStream(streamPath)
			if err != nil {
				return err
			}

			// Layer 3 judge: reuse Sentinel's analyzer client when an API key is
			// present. Without a key, Layer 3 is skipped (non-blocking) so the
			// deterministic layers still run offline.
			var judge verify.Judge
			apiKey := os.Getenv("ANTHROPIC_API_KEY")
			if apiKey != "" {
				judge = verify.NewLLMJudge(analyzer.NewClient(apiKey, judgeModel), judgeModel)
			}

			session := guard.Run(cmd.Context(), events, guard.Options{
				Intent:    declared,
				Detectors: detect.All(),
				Judge:     judge,
			})

			renderGuardTable(os.Stdout, session, judge != nil)

			if reportPath != "" {
				f, err := os.Create(reportPath)
				if err != nil {
					return fmt.Errorf("creating report file: %w", err)
				}
				if err := report.WriteGuardSARIF(f, streamPath, session, version); err != nil {
					_ = f.Close()
					return err
				}
				if err := f.Close(); err != nil {
					return fmt.Errorf("writing report file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "sentinel: wrote SARIF report to %s\n", reportPath)
			}

			if session.Blocked {
				return errFindings
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&intentPath, "intent", "", "path to the declared-intent JSON file (required)")
	cmd.Flags().StringVar(&streamPath, "stream", "", "path to the JSONL stream of tool outputs / actions (required)")
	cmd.Flags().StringVar(&judgeModel, "judge-model", config.DefaultModel, "Anthropic model for the isolated Layer 3 judge")
	cmd.Flags().StringVar(&reportPath, "report", "", "write a SARIF report to this file")
	return cmd
}

// readStream parses a JSONL file into guard events, skipping blank lines.
func readStream(path string) ([]guard.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}
	defer func() { _ = f.Close() }()

	var events []guard.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var ev guard.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, fmt.Errorf("stream line %d is not valid JSON: %w", line, err)
		}
		if ev.Seq == 0 {
			ev.Seq = line
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}
	return events, nil
}

var guardVerdictColor = map[guard.Verdict]*color.Color{
	guard.VerdictAllow: color.New(color.FgGreen),
	guard.VerdictFlag:  color.New(color.FgYellow),
	guard.VerdictBlock: color.New(color.FgHiRed, color.Bold),
}

// renderGuardTable prints the per-event verdict table plus the session summary.
func renderGuardTable(w io.Writer, session guard.SessionReport, judgeActive bool) {
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
		detectors := detectorNames(r.Detectors)
		l2 := "-"
		if r.L2 != nil {
			if r.L2.OK {
				l2 = "pass"
			} else {
				l2 = "BLOCK"
			}
		}
		l3 := "-"
		if r.L3 != nil {
			switch {
			case r.L3.Skipped:
				l3 = "skipped"
			case r.L3.Verdict == "deviation":
				l3 = "DEVIATION"
			default:
				l3 = "match"
			}
		}
		verdictCell := guardVerdictColor[r.Verdict].Sprintf("%s", strings.ToUpper(string(r.Verdict)))
		fmt.Fprintf(w, "  %-4d %-10s %-24s %-26s %-8s %-10s %s\n",
			r.Seq, r.Type, truncate(r.Summary, 24), truncate(detectors, 26), l2, l3, verdictCell)
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

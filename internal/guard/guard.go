// Package guard orchestrates Sentinel's runtime guard: for each item in a
// session stream it runs the five detectors over tool outputs, checks proposed
// actions against the declared intent through Layers 2–4, and produces a
// per-action verdict plus a session-level report.
//
// The root-cause problem this contains is that the model has no built-in notion
// that a string is data versus instruction. The guard is therefore a zero-trust
// containment layer, not a safety guarantee.
package guard

import (
	"context"

	"github.com/acevenen/sentinel/internal/guard/detect"
	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

// Verdict is the per-event decision.
type Verdict string

// Event verdicts, in increasing order of severity.
const (
	VerdictAllow Verdict = "allow"
	VerdictFlag  Verdict = "flag"
	VerdictBlock Verdict = "block"
)

// Event is one item in the session stream: either a tool output to inspect or
// a proposed action to verify.
type Event struct {
	Seq     int            `json:"seq"`
	Type    string         `json:"type"`              // "tool_output" | "action"
	Source  string         `json:"source"`            // "user" | "tool" | "agent"
	Tool    string         `json:"tool,omitempty"`    // producing tool, for context
	Content string         `json:"content,omitempty"` // tool-output text
	Action  *verify.Action `json:"action,omitempty"`  // proposed action
}

// EventResult is the guard's evaluation of one event.
type EventResult struct {
	Seq       int
	Type      string
	Source    string
	Summary   string // short description of the event for the table
	Detectors []detect.Finding
	L2        *verify.MatchResult // nil for tool outputs
	L3        *verify.Verdict     // nil when not evaluated
	Verdict   Verdict
	Reasons   []string
}

// SessionReport is the full result of guarding a session.
type SessionReport struct {
	Intent  intent.Intent
	Results []EventResult
	Drift   verify.DriftReport
	Blocked bool
}

// Options configures a guard run.
type Options struct {
	Intent    intent.Intent
	Detectors []detect.Detector
	// Judge is the Layer 3 judge. When nil, Layer 3 is skipped (surfaced as a
	// non-blocking "skipped" verdict) rather than failing closed — absence of a
	// judge is a configuration state, not an attack.
	Judge verify.Judge
}

// Run evaluates every event and returns a session report. It never mutates its
// inputs and does not require a network connection unless a Judge is supplied.
func Run(ctx context.Context, events []Event, opts Options) SessionReport {
	detectors := opts.Detectors
	if detectors == nil {
		detectors = detect.All()
	}
	drift := verify.NewDrift(opts.Intent)

	report := SessionReport{Intent: opts.Intent}

	for _, ev := range events {
		res := EventResult{Seq: ev.Seq, Type: ev.Type, Source: ev.Source, Verdict: VerdictAllow}

		switch ev.Type {
		case "tool_output":
			res.Summary = summarizeOutput(ev)
			res.Detectors = detect.Run(detectors, detect.Input{
				Text:   ev.Content,
				Source: ev.Source,
				Intent: opts.Intent,
			})
			for _, f := range res.Detectors {
				drift.ObserveDetector(f.Detector)
			}
			res.Verdict, res.Reasons = verdictFromFindings(res.Detectors)

		case "action":
			if ev.Action == nil {
				res.Summary = "malformed action event (no action payload)"
				res.Verdict = VerdictBlock
				res.Reasons = []string{"action event carried no action payload; failing closed"}
				break
			}
			res.Summary = summarizeAction(*ev.Action)
			drift.ObserveAction(*ev.Action)

			l2 := verify.StaticMatch(opts.Intent, *ev.Action)
			res.L2 = &l2
			if !l2.OK {
				res.Verdict = VerdictBlock
				res.Reasons = append(res.Reasons, "L2 static-match: "+l2.Reason)
				break
			}

			if opts.Judge != nil && ev.Action.IsRisky() {
				v := opts.Judge.Evaluate(ctx, opts.Intent, *ev.Action)
				res.L3 = &v
				if v.IsDeviation() {
					res.Verdict = VerdictBlock
					res.Reasons = append(res.Reasons, "L3 judge: deviation — "+v.Reason)
				}
			} else if ev.Action.IsRisky() {
				skipped := verify.SkippedVerdict("no judge configured (e.g. no API key); Layer 3 skipped")
				res.L3 = &skipped
			}

		default:
			res.Summary = "unknown event type: " + ev.Type
			res.Verdict = VerdictFlag
			res.Reasons = []string{"unrecognized event type"}
		}

		if res.Verdict == VerdictBlock {
			report.Blocked = true
		}
		report.Results = append(report.Results, res)
	}

	report.Drift = drift.Report()
	if report.Drift.Blocked {
		report.Blocked = true
	}
	return report
}

// verdictFromFindings maps detector findings to an event verdict. A critical
// finding blocks; any other finding flags.
func verdictFromFindings(findings []detect.Finding) (Verdict, []string) {
	if len(findings) == 0 {
		return VerdictAllow, nil
	}
	verdict := VerdictFlag
	var reasons []string
	for _, f := range findings {
		if f.Severity == "critical" {
			verdict = VerdictBlock
		}
		reasons = append(reasons, f.Detector+": "+f.Reason)
	}
	return verdict, reasons
}

func summarizeOutput(ev Event) string {
	label := "tool output"
	if ev.Tool != "" {
		label += " from " + ev.Tool
	}
	return label
}

func summarizeAction(a verify.Action) string {
	s := a.Type + " " + a.Target
	if a.Description != "" {
		s = a.Description
	}
	return s
}

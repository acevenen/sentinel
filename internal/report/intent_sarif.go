package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/acevenen/sentinel/internal/guard"
)

// GuardFinding is one row of the guard's SARIF output: a detector finding or an
// intent-mismatch from the verification layers, anchored to a stream position.
type GuardFinding struct {
	RuleID  string
	Level   string // SARIF level: error | warning | note
	Message string
	Seq     int
}

// WriteGuardSARIF renders a guard SessionReport as SARIF 2.1.0, extending
// Sentinel's SARIF output with an "intent-mismatch" rule category alongside the
// per-detector rules. streamPath is used as the SARIF artifact URI, and each
// finding's stream sequence number becomes its startLine so results anchor back
// to the JSONL line that produced them.
func WriteGuardSARIF(w io.Writer, streamPath string, session guard.SessionReport, version string) error {
	findings := guardFindings(session)

	seenRules := make(map[string]bool)
	var rules []sarifRule
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if !seenRules[f.RuleID] {
			seenRules[f.RuleID] = true
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifMessage{Text: ruleDescription(f.RuleID)},
			})
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   f.Level,
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: streamPath},
					Region:           sarifRegion{StartLine: sarifLine(f.Seq)},
				},
			}},
		})
	}

	if rules == nil {
		rules = []sarifRule{}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Sentinel Guard",
				Version:        version,
				InformationURI: "https://github.com/acevenen/sentinel",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// guardFindings flattens a session report into SARIF-ready findings.
func guardFindings(session guard.SessionReport) []GuardFinding {
	var out []GuardFinding
	for _, r := range session.Results {
		for _, d := range r.Detectors {
			out = append(out, GuardFinding{
				RuleID:  d.Detector,
				Level:   severityToSARIFLevel(d.Severity),
				Message: fmt.Sprintf("%s (span: %s)", d.Reason, d.Span),
				Seq:     r.Seq,
			})
		}
		// Blocked actions surface as intent-mismatch findings.
		if r.Type == "action" && r.Verdict == guard.VerdictBlock {
			out = append(out, GuardFinding{
				RuleID:  "intent-mismatch",
				Level:   "error",
				Message: strings.Join(r.Reasons, "; "),
				Seq:     r.Seq,
			})
		}
	}
	if session.Drift.Blocked {
		out = append(out, GuardFinding{
			RuleID:  "intent-mismatch",
			Level:   "error",
			Message: "session drift: " + session.Drift.Headline,
			Seq:     0,
		})
	}
	return out
}

func ruleDescription(id string) string {
	switch id {
	case "intent-mismatch":
		return "Action deviates from the declared user intent"
	case "instruction-injection":
		return "Attempt to override prior instructions in retrieved content"
	case "secret-and-exfiltration":
		return "Reference to secrets, credentials, or data exfiltration"
	case "scope-deviation":
		return "Content expands the task beyond declared scope"
	case "obfuscation":
		return "Hidden or encoded payload"
	case "provenance":
		return "Directive originating in an untrusted source"
	default:
		return id
	}
}

// sarifLine converts a stream sequence number to a 1-based SARIF line; SARIF
// requires startLine >= 1.
func sarifLine(seq int) int {
	if seq < 1 {
		return 1
	}
	return seq
}

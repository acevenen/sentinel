package detect

import "github.com/acevenen/sentinel/internal/analyzer"

// InjectionDetector (detector 1) flags imperative/override/role-switch patterns
// inside content — the signature of an instruction-injection attempt where
// retrieved or tool-produced text tries to issue directives to the model.
type InjectionDetector struct{}

// Name identifies the detector in findings and reports.
func (InjectionDetector) Name() string { return "instruction-injection" }

// Inspect scans for prompt-override phrasing.
func (InjectionDetector) Inspect(in Input) []Finding {
	var out []Finding
	for _, span := range matchAllSpans(in.Text, overridePatterns) {
		out = append(out, Finding{
			Detector: "instruction-injection",
			Severity: analyzer.SeverityCritical,
			Span:     snippet(span),
			Reason:   "content attempts to override or replace prior instructions",
		})
	}
	return out
}

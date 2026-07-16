package detect

import "github.com/acevenen/sentinel/internal/analyzer"

// ProvenanceDetector (detector 5) tracks which source a directive came from and
// flags any directive that originates inside an untrusted source. A directive
// in the original user turn is legitimate; the same directive appearing inside
// tool output or retrieved content is not — the model has no built-in notion
// that the latter is data rather than instruction.
type ProvenanceDetector struct{}

// Name identifies the detector in findings and reports.
func (ProvenanceDetector) Name() string { return "provenance" }

// trustedSource reports whether directives from this source are legitimate.
func trustedSource(source string) bool {
	return source == "" || source == "user"
}

// Inspect flags override or exfil directives found in a non-user source.
func (ProvenanceDetector) Inspect(in Input) []Finding {
	if trustedSource(in.Source) {
		return nil
	}

	var out []Finding
	if span, ok := matchAny(in.Text, overridePatterns); ok {
		out = append(out, Finding{
			Detector: "provenance",
			Severity: analyzer.SeverityCritical,
			Span:     snippet(span),
			Reason:   "directive to override prior instructions originates in untrusted source: " + in.Source,
		})
	}
	if span, ok := matchAny(in.Text, exfilImperativePatterns); ok {
		out = append(out, Finding{
			Detector: "provenance",
			Severity: analyzer.SeverityHigh,
			Span:     snippet(span),
			Reason:   "data-movement directive originates in untrusted source: " + in.Source,
		})
	}
	return out
}

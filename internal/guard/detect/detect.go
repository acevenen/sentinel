// Package detect implements the guard's Half A: deterministic detectors
// that inspect every tool output before it re-enters the model's context.
// Each detector is pattern-based and fast; together they carry the bulk of the
// guard's demonstrable protection without an LLM in the loop.
package detect

import (
	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/guard/intent"
)

// Finding is one detection from one detector over one input span.
type Finding struct {
	Detector   string
	TaxonomyID string
	Severity   analyzer.Severity
	Span       string // the offending text, trimmed for display
	Reason     string
}

// Input is a single unit of context to inspect — typically one tool output.
type Input struct {
	// Text is the content to scan.
	Text string
	// Source is the provenance of the text: "user", "tool", or "agent".
	// Directives originating anywhere other than "user" are untrusted.
	Source string
	// Intent is the declared intent, used by the scope detector.
	Intent intent.Intent
}

// Detector inspects an input and returns zero or more findings.
type Detector interface {
	Name() string
	Inspect(in Input) []Finding
}

// All returns the standard detector set in a stable order.
func All() []Detector {
	return []Detector{
		InjectionDetector{},
		ExfilDetector{},
		ScopeDetector{},
		ObfuscationDetector{},
		ProvenanceDetector{},
		TaxonomyDetector{},
	}
}

// Run applies every detector to the input and concatenates their findings.
func Run(detectors []Detector, in Input) []Finding {
	var out []Finding
	for _, d := range detectors {
		out = append(out, d.Inspect(in)...)
	}
	return out
}

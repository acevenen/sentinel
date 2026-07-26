package detect

import (
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/redteam"
)

// TaxonomyDetector recognizes high-signal technique and evasion families from
// the same Arcanum-derived metadata catalog used by authorized red-team runs.
// It only treats non-user content as indirect/untrusted instructions.
type TaxonomyDetector struct{}

// Name identifies the detector in findings and reports.
func (TaxonomyDetector) Name() string { return "prompt-injection-taxonomy" }

type taxonomyPattern struct {
	id       string
	severity analyzer.Severity
	pattern  *regexp.Regexp
}

var taxonomyPatterns = []taxonomyPattern{
	{"PIT-T-31", analyzer.SeverityHigh, regexp.MustCompile(`(?im)^\s*(assistant|system|developer)\s*:\s*\S`)},
	{"PIT-T-42", analyzer.SeverityCritical, regexp.MustCompile(`(?i)\b(mcp|tool)\s+(definition|description)\b.{0,100}\b(ignore|override|instruction|directive)\b`)},
	{"PIT-T-46", analyzer.SeverityCritical, regexp.MustCompile(`(?i)\b(agents\.md|claude\.md|\.cursorrules|instruction[- ]file|rules[- ]file)\b.{0,100}\b(ignore|override|replace|secret|exfiltrat)`)},
	{"PIT-T-53", analyzer.SeverityHigh, regexp.MustCompile(`(?i)(<tool[_ -]?call>|"tool_calls?"\s*:|\bfunction[_ -]?call\s*:)`)},
	{"PIT-T-56", analyzer.SeverityCritical, regexp.MustCompile(`(?i)(\[system\]|\bi\s+am\s+(the\s+)?(system|developer|administrator)\b).{0,100}\b(instruction|must|ignore|override|authorized)\b`)},
	{"PIT-T-70", analyzer.SeverityHigh, regexp.MustCompile(`(?i)\b(function|tool)[- ]call\s+(parameter|argument).{0,100}\b(smuggl|override|duplicate|hidden)\b`)},
	{"PIT-E-59", analyzer.SeverityHigh, regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")},
}

// Inspect applies taxonomy patterns only to text crossing a trust boundary.
func (TaxonomyDetector) Inspect(in Input) []Finding {
	if in.Source == "" || strings.EqualFold(in.Source, "user") {
		return nil
	}
	taxonomy, err := redteam.Core()
	if err != nil {
		return []Finding{{
			Detector: "prompt-injection-taxonomy",
			Severity: analyzer.SeverityHigh,
			Reason:   "shared prompt-injection taxonomy could not be loaded",
		}}
	}
	var out []Finding
	for _, candidate := range taxonomyPatterns {
		span := candidate.pattern.FindString(in.Text)
		if span == "" {
			continue
		}
		category, ok := taxonomy.ByID(candidate.id)
		if !ok {
			continue
		}
		out = append(out, Finding{
			Detector:   "prompt-injection-taxonomy",
			TaxonomyID: category.ID,
			Severity:   candidate.severity,
			Span:       snippet(span),
			Reason:     "untrusted content matches taxonomy category " + category.Name,
		})
	}
	return out
}

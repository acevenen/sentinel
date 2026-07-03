package analyzer

import "strings"

// Severity classifies how serious a finding is.
type Severity string

// Severity levels, ordered from least to most serious.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities lists all levels from least to most serious.
var Severities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// ParseSeverity normalizes a string into a known Severity.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityCritical:
		return SeverityCritical, true
	}
	return "", false
}

// Rank returns an integer ordering for severity comparison; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Finding is a single security or quality issue located in the scanned code.
type Finding struct {
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

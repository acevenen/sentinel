// Package report renders scan results as colored terminal output, markdown,
// JSON, or SARIF 2.1.0 for GitHub Code Scanning.
package report

import (
	"fmt"
	"io"
	"time"

	"github.com/acevenen/sentinel/internal/analyzer"
)

// Supported output format names.
const (
	FormatTerminal = "terminal"
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatSARIF    = "sarif"
)

// Formats lists every supported output format.
var Formats = []string{FormatTerminal, FormatMarkdown, FormatJSON, FormatSARIF}

// Report bundles the findings of one scan with its metadata.
type Report struct {
	Tool        string             `json:"tool"`
	Version     string             `json:"version"`
	Path        string             `json:"path"`
	Model       string             `json:"model"`
	Files       int                `json:"files_scanned"`
	Chunks      int                `json:"chunks_analyzed"`
	Duration    time.Duration      `json:"-"`
	DurationStr string             `json:"duration"`
	GeneratedAt time.Time          `json:"generated_at"`
	Findings    []analyzer.Finding `json:"findings"`
}

// CountBySeverity tallies findings per severity level.
func (r *Report) CountBySeverity() map[analyzer.Severity]int {
	counts := make(map[analyzer.Severity]int, len(analyzer.Severities))
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// FilterBySeverity returns only findings at or above min.
func FilterBySeverity(findings []analyzer.Finding, min analyzer.Severity) []analyzer.Finding {
	out := make([]analyzer.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity.Rank() >= min.Rank() {
			out = append(out, f)
		}
	}
	return out
}

// Render writes the report to w in the requested format.
func Render(w io.Writer, format string, r *Report) error {
	r.DurationStr = r.Duration.Round(time.Millisecond).String()
	switch format {
	case FormatTerminal:
		return renderTerminal(w, r)
	case FormatMarkdown:
		return renderMarkdown(w, r)
	case FormatJSON:
		return renderJSON(w, r)
	case FormatSARIF:
		return renderSARIF(w, r)
	default:
		return fmt.Errorf("unknown format %q (want one of %v)", format, Formats)
	}
}

// severitiesWorstFirst is the display order for grouped output.
var severitiesWorstFirst = []analyzer.Severity{
	analyzer.SeverityCritical,
	analyzer.SeverityHigh,
	analyzer.SeverityMedium,
	analyzer.SeverityLow,
}

func groupBySeverity(findings []analyzer.Finding) map[analyzer.Severity][]analyzer.Finding {
	groups := make(map[analyzer.Severity][]analyzer.Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

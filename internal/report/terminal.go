package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/analyzer"
)

var severityColors = map[analyzer.Severity]*color.Color{
	analyzer.SeverityCritical: color.New(color.FgHiRed, color.Bold),
	analyzer.SeverityHigh:     color.New(color.FgRed),
	analyzer.SeverityMedium:   color.New(color.FgYellow),
	analyzer.SeverityLow:      color.New(color.FgCyan),
}

func renderTerminal(w io.Writer, r *Report) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintf(w, "\nSentinel Security Scan\n")
	dim.Fprintf(w, "%s\n\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  Path      %s\n", r.Path)
	fmt.Fprintf(w, "  Model     %s\n", r.Model)
	fmt.Fprintf(w, "  Scanned   %d files (%d chunks) in %s\n\n", r.Files, r.Chunks, r.DurationStr)

	counts := r.CountBySeverity()
	bold.Fprintln(w, "  Severity summary")
	for _, sev := range severitiesWorstFirst {
		label := severityColors[sev].Sprintf("%-9s", strings.ToUpper(string(sev)))
		fmt.Fprintf(w, "    %s %d\n", label, counts[sev])
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "  ✓ No findings at or above the requested severity threshold.")
		fmt.Fprintln(w)
		return nil
	}

	groups := groupBySeverity(r.Findings)
	for _, sev := range severitiesWorstFirst {
		findings := groups[sev]
		if len(findings) == 0 {
			continue
		}
		severityColors[sev].Fprintf(w, "%s (%d)\n", strings.ToUpper(string(sev)), len(findings))
		dim.Fprintf(w, "%s\n", strings.Repeat("─", 60))
		for _, f := range findings {
			title := f.Title
			if f.Category != "" {
				title = fmt.Sprintf("[%s] %s", f.Category, f.Title)
			}
			bold.Fprintf(w, "  %s\n", title)
			dim.Fprintf(w, "  %s:%d\n", f.File, f.Line)
			if f.Description != "" {
				fmt.Fprintf(w, "  %s\n", f.Description)
			}
			if f.Recommendation != "" {
				fmt.Fprintf(w, "  %s %s\n", color.GreenString("fix:"), f.Recommendation)
			}
			fmt.Fprintln(w)
		}
	}
	return nil
}

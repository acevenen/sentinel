package report

import (
	"fmt"
	"io"
	"strings"
)

// renderMarkdown produces a report suitable for pasting into a pull request.
func renderMarkdown(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "# Sentinel Security Report\n\n")
	fmt.Fprintf(w, "| | |\n|---|---|\n")
	fmt.Fprintf(w, "| **Path** | `%s` |\n", r.Path)
	fmt.Fprintf(w, "| **Model** | `%s` |\n", r.Model)
	fmt.Fprintf(w, "| **Scanned** | %d files (%d chunks) |\n", r.Files, r.Chunks)
	fmt.Fprintf(w, "| **Duration** | %s |\n", r.DurationStr)
	fmt.Fprintf(w, "| **Generated** | %s |\n\n", r.GeneratedAt.Format("2006-01-02 15:04 MST"))

	counts := r.CountBySeverity()
	fmt.Fprintf(w, "## Summary\n\n| Severity | Count |\n|---|---|\n")
	for _, sev := range severitiesWorstFirst {
		fmt.Fprintf(w, "| %s | %d |\n", strings.ToUpper(string(sev)), counts[sev])
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No findings at or above the requested severity threshold. ✅\n")
		return nil
	}

	groups := groupBySeverity(r.Findings)
	for _, sev := range severitiesWorstFirst {
		findings := groups[sev]
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", strings.ToUpper(string(sev)))
		for _, f := range findings {
			title := f.Title
			if f.Category != "" {
				title = fmt.Sprintf("[%s] %s", f.Category, f.Title)
			}
			fmt.Fprintf(w, "### %s\n\n", title)
			fmt.Fprintf(w, "`%s:%d`\n\n", f.File, f.Line)
			if f.Description != "" {
				fmt.Fprintf(w, "%s\n\n", f.Description)
			}
			if f.Recommendation != "" {
				fmt.Fprintf(w, "**Recommendation:** %s\n\n", f.Recommendation)
			}
		}
	}
	return nil
}

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/engagement"
	"github.com/acevenen/sentinel/internal/methodology"
	"github.com/acevenen/sentinel/internal/tools"
)

// Engagement output formats.
const (
	EngagementFormatMarkdown = "markdown"
	EngagementFormatJSON     = "json"
	EngagementFormatSARIF    = "sarif"
)

// EngagementFormats lists the report formats that preserve engagement data.
var EngagementFormats = []string{EngagementFormatMarkdown, EngagementFormatJSON, EngagementFormatSARIF}

// EngagementSummary aggregates finding severities.
type EngagementSummary struct {
	Total    int            `json:"total"`
	Severity map[string]int `json:"severity"`
}

// EngagementReport combines portable authorization, progress, findings,
// artifacts, and verified audit events.
type EngagementReport struct {
	Tool              string               `json:"tool"`
	Version           string               `json:"version"`
	GeneratedAt       time.Time            `json:"generated_at"`
	Engagement        engagement.Record    `json:"engagement"`
	Methodology       methodology.RunState `json:"methodology"`
	Timeline          []tools.AuditEvent   `json:"timeline"`
	Summary           EngagementSummary    `json:"summary"`
	Findings          []tools.Finding      `json:"findings"`
	EvidenceArtifacts []tools.Artifact     `json:"evidence_artifacts"`
}

// NewEngagement builds a deterministic report view.
func NewEngagement(
	version string,
	record engagement.Record,
	state methodology.RunState,
	events []tools.AuditEvent,
) EngagementReport {
	findings := append([]tools.Finding(nil), state.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		left, _ := analyzer.ParseSeverity(findings[i].Severity)
		right, _ := analyzer.ParseSeverity(findings[j].Severity)
		if left.Rank() != right.Rank() {
			return left.Rank() > right.Rank()
		}
		return findings[i].Title < findings[j].Title
	})
	summary := EngagementSummary{Total: len(findings), Severity: map[string]int{}}
	for _, finding := range findings {
		severity := normalizedEngagementSeverity(finding.Severity)
		summary.Severity[severity]++
	}
	return EngagementReport{
		Tool: "sentinel", Version: version, GeneratedAt: time.Now().UTC(),
		Engagement: record, Methodology: state,
		Timeline: append([]tools.AuditEvent(nil), events...),
		Summary:  summary, Findings: findings,
		EvidenceArtifacts: append([]tools.Artifact(nil), state.Artifacts...),
	}
}

// RenderEngagement writes Markdown, JSON, or SARIF 2.1.0.
func RenderEngagement(w io.Writer, format string, report EngagementReport) error {
	switch format {
	case EngagementFormatMarkdown:
		return renderEngagementMarkdown(w, report)
	case EngagementFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case EngagementFormatSARIF:
		return renderEngagementSARIF(w, report)
	default:
		return fmt.Errorf("unknown engagement format %q (want one of %v)", format, EngagementFormats)
	}
}

func renderEngagementMarkdown(w io.Writer, report EngagementReport) error {
	fmt.Fprintf(w, "# Sentinel Engagement Report — %s\n\n", report.Engagement.Name)
	fmt.Fprintf(w, "| | |\n|---|---|\n")
	fmt.Fprintf(w, "| Engagement | `%s` |\n", markdownCell(report.Engagement.ID))
	fmt.Fprintf(w, "| Mode | %s |\n", markdownCell(defaultString(report.Engagement.Mode, "standard")))
	fmt.Fprintf(w, "| Operator | %s |\n", markdownCell(report.Engagement.Operator))
	fmt.Fprintf(w, "| Authorization | %s |\n", markdownCell(report.Engagement.AuthorizationRef))
	fmt.Fprintf(w, "| Generated | %s |\n\n", report.GeneratedAt.Format(time.RFC3339))

	fmt.Fprintln(w, "## Authorized scope")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Allow: %s\n", markdownCodeList(report.Engagement.Scope.Allow))
	fmt.Fprintf(w, "- Deny: %s\n", markdownCodeList(report.Engagement.Scope.Deny))
	fmt.Fprintf(w, "- Rate: %s requests/second; concurrency: %d\n\n",
		formatRate(report.Engagement.RateLimitRPS), report.Engagement.Concurrency)

	fmt.Fprintln(w, "## Methodology")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Completed: %s\n", stagesList(report.Methodology.Completed))
	fmt.Fprintf(w, "- Current: `%s`\n", defaultString(string(report.Methodology.Current), "none"))
	fmt.Fprintf(w, "- Proposed next: %s\n\n", stagesList(report.Methodology.ProposedNext))

	fmt.Fprintln(w, "## Finding summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total normalized findings: **%d**\n\n", report.Summary.Total)
	fmt.Fprintln(w, "| Severity | Count |")
	fmt.Fprintln(w, "|---|---:|")
	for _, severity := range []string{"critical", "high", "medium", "low", "informational"} {
		fmt.Fprintf(w, "| %s | %d |\n", strings.ToUpper(severity), report.Summary.Severity[severity])
	}
	fmt.Fprintln(w)

	if len(report.Findings) == 0 {
		fmt.Fprintln(w, "No normalized findings were recorded. This does not prove the target is secure.")
		fmt.Fprintln(w)
	}
	for index, finding := range report.Findings {
		fmt.Fprintf(w, "### %d. %s\n\n", index+1, finding.Title)
		fmt.Fprintf(w, "- Severity: `%s`\n", defaultString(finding.Severity, "informational"))
		fmt.Fprintf(w, "- Target: `%s`\n", markdownCell(finding.Target))
		if finding.CWE != "" {
			fmt.Fprintf(w, "- CWE: `%s`\n", markdownCell(finding.CWE))
		}
		if finding.OWASP != "" {
			fmt.Fprintf(w, "- OWASP: `%s`\n", markdownCell(finding.OWASP))
		}
		fmt.Fprintln(w)
		if finding.Description != "" {
			fmt.Fprintln(w, finding.Description)
			fmt.Fprintln(w)
		}
		if finding.Evidence != "" {
			fmt.Fprintf(w, "**Evidence:** %s\n\n", finding.Evidence)
		}
		fmt.Fprintf(w, "**Remediation:** %s\n\n", remediation(finding))
	}

	fmt.Fprintln(w, "## Evidence artifacts")
	fmt.Fprintln(w)
	if len(report.EvidenceArtifacts) == 0 {
		fmt.Fprintln(w, "No evidence artifacts were attached.")
	} else {
		for _, artifact := range report.EvidenceArtifacts {
			fmt.Fprintf(w, "- `%s` — %s, digest `%s`\n",
				markdownCell(artifact.Path), markdownCell(artifact.Kind), markdownCell(artifact.Digest))
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Verified audit timeline")
	fmt.Fprintln(w)
	if len(report.Timeline) == 0 {
		fmt.Fprintln(w, "No engagement audit events were recorded.")
		return nil
	}
	fmt.Fprintln(w, "| Time | Tool | Target | Decision | Result |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, event := range report.Timeline {
		fmt.Fprintf(w, "| %s | %s | `%s` | %s | %s |\n",
			event.Timestamp.Format(time.RFC3339), markdownCell(event.Tool),
			markdownCell(event.Target), markdownCell(event.ScopeDecision), markdownCell(event.Result))
	}
	return nil
}

func renderEngagementSARIF(w io.Writer, report EngagementReport) error {
	seen := map[string]bool{}
	var rules []sarifRule
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		id := engagementRuleID(finding)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, sarifRule{
				ID: id, ShortDescription: sarifMessage{Text: finding.Title},
			})
		}
		severity, ok := analyzer.ParseSeverity(finding.Severity)
		if !ok {
			severity = analyzer.SeverityLow
		}
		message := defaultString(finding.Description, finding.Title) + " Remediation: " + remediation(finding)
		result := sarifResult{
			RuleID: id, Level: severityToSARIFLevel(severity),
			Message: sarifMessage{Text: message},
		}
		location := finding.Target
		line := 0
		if finding.Metadata != nil {
			location = defaultString(finding.Metadata["file"], location)
			line, _ = strconv.Atoi(finding.Metadata["line"])
		}
		if location != "" {
			result.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: location},
					Region:           sarifRegion{StartLine: line},
				},
			}}
		}
		results = append(results, result)
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	log := sarifLog{
		Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Sentinel Engagement", Version: report.Version,
				InformationURI: "https://github.com/acevenen/sentinel", Rules: rules,
			}},
			Results: results,
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func engagementRuleID(finding tools.Finding) string {
	for _, value := range []string{finding.CWE, finding.OWASP, finding.ID} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	slug := strings.ToLower(strings.Join(strings.Fields(finding.Title), "-"))
	if slug == "" {
		slug = "finding"
	}
	return "sentinel/" + slug
}

func remediation(finding tools.Finding) string {
	if finding.Remediation != "" {
		return finding.Remediation
	}
	return "Verify the observation manually, address the underlying control, and add a regression test before retesting."
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func markdownCodeList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, "`"+markdownCell(value)+"`")
	}
	return strings.Join(out, ", ")
}

func stagesList(values []methodology.Stage) string {
	if len(values) == 0 {
		return "(none)"
	}
	out := make([]string, len(values))
	for index, stage := range values {
		out[index] = "`" + string(stage) + "`"
	}
	return strings.Join(out, ", ")
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func formatRate(value float64) string {
	if value <= 0 {
		return "engagement default"
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func normalizedEngagementSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "critical", "high", "medium", "low":
		return value
	case "info", "informational", "":
		return "informational"
	default:
		return "informational"
	}
}

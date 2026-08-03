// Package report renders REVerso findings into shareable documents. Reports
// keep observation, inference and speculation visually separate, cite evidence
// hashes, and include the manifest and confidence so a reader can reproduce and
// challenge every conclusion.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/acevenen/sentinel/reverso/internal/confidence"
	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// Formats are the supported report formats.
var Formats = []string{"markdown", "json", "html"}

// Data is everything a report renders.
type Data struct {
	Tool        string                    `json:"tool"`
	Version     string                    `json:"version"`
	GeneratedAt time.Time                 `json:"generated_at"`
	ProjectID   string                    `json:"project_id"`
	Owner       string                    `json:"owner"`
	Manifest    *scope.Manifest           `json:"-"`
	Artifacts   []evidence.ArtifactRecord `json:"artifacts"`
	Findings    []confidence.Finding      `json:"findings"`
}

// Render writes the report in the requested format.
func Render(w io.Writer, format string, d Data) error {
	switch strings.ToLower(format) {
	case "", "markdown", "md":
		return RenderMarkdown(w, d)
	case "json":
		return RenderJSON(w, d)
	case "html":
		return RenderHTML(w, d)
	default:
		return fmt.Errorf("unknown report format %q (want one of %v)", format, Formats)
	}
}

// RenderJSON writes a machine-readable report.
func RenderJSON(w io.Writer, d Data) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// RenderMarkdown writes the human-readable report.
func RenderMarkdown(w io.Writer, d Data) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# REVerso report: %s\n\n", d.ProjectID)
	fmt.Fprintf(&b, "- Tool: %s %s\n", d.Tool, d.Version)
	fmt.Fprintf(&b, "- Owner: %s\n", d.Owner)
	fmt.Fprintf(&b, "- Generated: %s\n", d.GeneratedAt.UTC().Format(time.RFC3339))

	if d.Manifest != nil {
		a := d.Manifest.Authorization
		b.WriteString("\n## Authorization\n\n")
		fmt.Fprintf(&b, "- Asset: `%s` (%s)\n", a.Target.AssetID, a.Target.AssetType)
		fmt.Fprintf(&b, "- Ownership evidence: %s\n", a.Target.OwnershipEvidence)
		fmt.Fprintf(&b, "- Expires: %s\n", a.ExpiresAt)
		fmt.Fprintf(&b, "- Signature verified: %v\n", d.Manifest.Verified)
		if len(a.Permitted) > 0 {
			fmt.Fprintf(&b, "- Permitted: %s\n", joinCaps(a.Permitted))
		}
		if len(a.Prohibited) > 0 {
			fmt.Fprintf(&b, "- Prohibited: %s\n", joinCaps(a.Prohibited))
		}
	}

	b.WriteString("\n## Evidence\n\n")
	if len(d.Artifacts) == 0 {
		b.WriteString("_No artifacts ingested._\n")
	} else {
		b.WriteString("| Artifact | Type | Size | SHA-256 |\n|---|---|---:|---|\n")
		for _, a := range d.Artifacts {
			fmt.Fprintf(&b, "| %s | %s | %d | `%s` |\n",
				a.OriginalName, a.DetectedType, a.SizeBytes, a.SHA256)
		}
	}

	b.WriteString("\n## Findings\n\n")
	if len(d.Findings) == 0 {
		b.WriteString("_No findings recorded._\n")
	}
	for _, f := range d.Findings {
		fmt.Fprintf(&b, "### %s — %s\n\n", f.ID, f.Title)
		fmt.Fprintf(&b, "- Classification: %s\n", f.Classification)
		fmt.Fprintf(&b, "- Confidence: **%s**\n", f.Confidence)
		writeList(&b, "Observation (evidenced fact)", f.Observation)
		writeList(&b, "Inference (supported explanation)", f.Inference)
		writeList(&b, "Speculation (unevidenced)", f.Speculation)
		writeList(&b, "Alternatives", f.Alternatives)
		writeList(&b, "Evidence", codeEach(f.EvidenceIDs))
		writeList(&b, "Next safe test", f.NextSafeTest)
		writeList(&b, "Prohibited next steps", f.ProhibitedNextSteps)
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// RenderHTML wraps the Markdown body in a minimal, self-contained HTML page.
func RenderHTML(w io.Writer, d Data) error {
	var md strings.Builder
	if err := RenderMarkdown(&md, d); err != nil {
		return err
	}
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>REVerso report: %s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem}
pre{white-space:pre-wrap;word-wrap:break-word}</style>
</head><body>
<pre>%s</pre>
</body></html>
`, html.EscapeString(d.ProjectID), html.EscapeString(md.String()))
	return nil
}

func writeList(b *strings.Builder, heading string, items []string) {
	nonempty := make([]string, 0, len(items))
	for _, s := range items {
		if strings.TrimSpace(s) != "" {
			nonempty = append(nonempty, s)
		}
	}
	if len(nonempty) == 0 {
		return
	}
	fmt.Fprintf(b, "\n**%s**\n\n", heading)
	for _, s := range nonempty {
		fmt.Fprintf(b, "- %s\n", s)
	}
}

func codeEach(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = "`" + s + "`"
	}
	return out
}

func joinCaps(caps []scope.Capability) string {
	parts := make([]string, len(caps))
	for i, c := range caps {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}

package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/acevenen/sentinel/internal/analyzer"
)

// SARIF 2.1.0 structures — the minimum GitHub Code Scanning needs.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// severityToSARIFLevel maps Sentinel severities onto SARIF levels.
func severityToSARIFLevel(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical, analyzer.SeverityHigh:
		return "error"
	case analyzer.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func ruleID(f analyzer.Finding) string {
	if f.Category != "" {
		return f.Category
	}
	slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(f.Title), " ", "-"))
	if slug == "" {
		slug = "finding"
	}
	return "sentinel/" + slug
}

func renderSARIF(w io.Writer, r *Report) error {
	seenRules := make(map[string]bool)
	var rules []sarifRule
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		id := ruleID(f)
		if !seenRules[id] {
			seenRules[id] = true
			rules = append(rules, sarifRule{
				ID:               id,
				ShortDescription: sarifMessage{Text: f.Title},
			})
		}

		text := f.Description
		if f.Recommendation != "" {
			text += " Recommendation: " + f.Recommendation
		}
		if text == "" {
			text = f.Title
		}

		results = append(results, sarifResult{
			RuleID:  id,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: text},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	if rules == nil {
		rules = []sarifRule{}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Sentinel",
				Version:        r.Version,
				InformationURI: "https://github.com/acevenen/sentinel",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

package analyzer

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/acevenen/sentinel/internal/scanner"
)

// rawFinding mirrors the model's JSON schema with lenient types so a single
// malformed field never sinks the whole batch.
type rawFinding struct {
	File           string          `json:"file"`
	Line           json.RawMessage `json:"line"`
	Severity       string          `json:"severity"`
	Category       string          `json:"category"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Recommendation string          `json:"recommendation"`
}

// parseFindings turns a model response into validated findings. It strips
// markdown fences and surrounding prose, skips malformed items, normalizes
// severities, and pins file/line values to the chunk that was analyzed.
func parseFindings(raw string, chunk scanner.Chunk) []Finding {
	payload := extractJSONArray(raw)
	if payload == "" {
		return nil
	}

	// Decode to raw elements first so one bad element can be skipped.
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(payload), &elements); err != nil {
		return nil
	}

	findings := make([]Finding, 0, len(elements))
	for _, el := range elements {
		var rf rawFinding
		if err := json.Unmarshal(el, &rf); err != nil {
			continue
		}
		severity, ok := ParseSeverity(rf.Severity)
		if !ok || strings.TrimSpace(rf.Title) == "" {
			continue
		}
		findings = append(findings, Finding{
			// The model is told the file path, but trust the chunk instead.
			File:           chunk.Path,
			Line:           clampLine(coerceLine(rf.Line), chunk),
			Severity:       severity,
			Category:       strings.TrimSpace(rf.Category),
			Title:          strings.TrimSpace(rf.Title),
			Description:    strings.TrimSpace(rf.Description),
			Recommendation: strings.TrimSpace(rf.Recommendation),
		})
	}
	return findings
}

// extractJSONArray isolates the outermost JSON array in a response that may
// be wrapped in markdown fences or prose.
func extractJSONArray(raw string) string {
	s := strings.TrimSpace(raw)
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start == -1 || end == -1 || end < start {
		return ""
	}
	return s[start : end+1]
}

// coerceLine accepts integers, floats, and numeric strings.
func coerceLine(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int(f)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return v
		}
	}
	return 0
}

// clampLine keeps a reported line inside the chunk's real line range.
func clampLine(line int, chunk scanner.Chunk) int {
	if line < chunk.StartLine {
		return chunk.StartLine
	}
	if line > chunk.EndLine {
		return chunk.EndLine
	}
	return line
}

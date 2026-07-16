package detect

import (
	"regexp"
	"strings"
)

// snippet trims a matched span to a readable length for reporting.
func snippet(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	const max = 120
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// overridePatterns match attempts to override, replace, or escape the prior
// instructions/context — the core signature of prompt injection.
var overridePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|earlier|above)\s+(instruction|instructions|context|message|messages|prompt|prompts|directive|directives)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|earlier|above|system)`),
	regexp.MustCompile(`(?i)forget\s+(everything|all\s+(previous|prior)|what\s+you\s+were\s+told)`),
	regexp.MustCompile(`(?i)\byou\s+are\s+now\b`),
	regexp.MustCompile(`(?i)\bnew\s+(instructions?|task|directive|system\s+prompt)\s*[:\-]`),
	regexp.MustCompile(`(?i)\bsystem\s*prompt\s*[:\-]`),
	regexp.MustCompile(`(?i)override\s+(the\s+)?(previous|system|safety|guard|security)`),
	regexp.MustCompile(`(?i)\bfrom\s+now\s+on\b`),
	regexp.MustCompile(`(?i)do\s+not\s+(tell|inform|mention\s+to|alert)\s+the\s+user`),
	regexp.MustCompile(`(?i)instead\s+of\s+(the\s+above|what\s+the\s+user|your\s+task)`),
}

// exfilImperativePatterns match second-person commands to move data outward or
// reach for secrets — directives, not descriptions.
var exfilImperativePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(send|post|upload|exfiltrate|email|transmit|leak|forward)\b[^.\n]{0,60}\b(to|at)\b[^.\n]{0,60}(https?://|www\.|[a-z0-9.-]+\.[a-z]{2,})`),
	regexp.MustCompile(`(?i)\b(read|cat|open|print|dump|exfiltrate)\b[^.\n]{0,40}(\.env|id_rsa|id_ed25519|credentials|secret|private[_\s-]?key|\.ssh)`),
	regexp.MustCompile(`(?i)\bcurl\b[^.\n]{0,80}(https?://|-d\b|--data)`),
}

// matchAny returns the first matched span across the given patterns.
func matchAny(text string, patterns []*regexp.Regexp) (string, bool) {
	for _, re := range patterns {
		if m := re.FindString(text); m != "" {
			return m, true
		}
	}
	return "", false
}

// matchAllSpans returns every matched span across the given patterns.
func matchAllSpans(text string, patterns []*regexp.Regexp) []string {
	var spans []string
	for _, re := range patterns {
		spans = append(spans, re.FindAllString(text, -1)...)
	}
	return spans
}

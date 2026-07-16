package detect

import (
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/analyzer"
)

// ScopeDetector (detector 3) flags tool output that tries to expand the task
// beyond the declared intent — most concretely, by naming a network
// destination that is not in the declared AllowedNetwork.
type ScopeDetector struct{}

// Name identifies the detector in findings and reports.
func (ScopeDetector) Name() string { return "scope-deviation" }

var (
	hostInURL     = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9.-]+)`)
	expansionVerb = regexp.MustCompile(`(?i)\b(also|additionally|in addition|furthermore|then also|as well,?\s+(please|you))\b[^.\n]{0,40}\b(send|post|upload|delete|remove|install|run|execute|add|fetch|download)\b`)
)

// Inspect flags out-of-intent hosts and explicit task-expansion phrasing.
func (d ScopeDetector) Inspect(in Input) []Finding {
	var out []Finding

	seen := map[string]bool{}
	for _, m := range hostInURL.FindAllStringSubmatch(in.Text, -1) {
		host := strings.ToLower(m[1])
		if seen[host] {
			continue
		}
		seen[host] = true
		if in.Intent.AllowsHost(host) {
			continue
		}
		out = append(out, Finding{
			Detector: "scope-deviation",
			Severity: analyzer.SeverityHigh,
			Span:     snippet(host),
			Reason:   "content references a network destination outside the declared AllowedNetwork",
		})
	}

	if span, ok := matchAny(in.Text, []*regexp.Regexp{expansionVerb}); ok {
		out = append(out, Finding{
			Detector: "scope-deviation",
			Severity: analyzer.SeverityMedium,
			Span:     snippet(span),
			Reason:   "content attempts to add steps or targets beyond the declared task",
		})
	}

	return out
}

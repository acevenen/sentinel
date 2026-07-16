package detect

import (
	"regexp"

	"github.com/acevenen/sentinel/internal/analyzer"
)

// ExfilDetector (detector 2) flags references that reach for secrets or
// credentials, cloud-metadata endpoints, or an outbound URL paired with a
// local file read — the building blocks of data exfiltration.
type ExfilDetector struct{}

// Name identifies the detector in findings and reports.
func (ExfilDetector) Name() string { return "secret-and-exfiltration" }

var (
	secretRefPattern = regexp.MustCompile(`(?i)(\.env\b|~?/?\.ssh\b|id_rsa\b|id_ed25519\b|\bAWS_[A-Z_]+\b|\bcredentials\b|\bprivate[_\s-]?key\b|\bsecret[_\s-]?key\b|\bapi[_\s-]?key\b|\baccess[_\s-]?token\b|\bbearer\s+token\b)`)
	metadataPattern  = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)`)
	urlPattern       = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)]+`)
	fileReadPattern  = regexp.MustCompile(`(?i)\b(read|cat|open|load|dump|print)\b`)
)

// Inspect scans for secret references, metadata endpoints, and the
// file-read-plus-outbound-URL combination.
func (ExfilDetector) Inspect(in Input) []Finding {
	var out []Finding

	for _, span := range metadataPattern.FindAllString(in.Text, -1) {
		out = append(out, Finding{
			Detector: "secret-and-exfiltration",
			Severity: analyzer.SeverityCritical,
			Span:     snippet(span),
			Reason:   "reference to a cloud instance-metadata endpoint",
		})
	}

	for _, span := range secretRefPattern.FindAllString(in.Text, -1) {
		out = append(out, Finding{
			Detector: "secret-and-exfiltration",
			Severity: analyzer.SeverityHigh,
			Span:     snippet(span),
			Reason:   "reference reaching for a secret, credential, or key",
		})
	}

	// An outbound URL alongside a local file-read verb is the exfiltration
	// primitive: pull data from disk, push it out over the network.
	if url := urlPattern.FindString(in.Text); url != "" && fileReadPattern.MatchString(in.Text) {
		out = append(out, Finding{
			Detector: "secret-and-exfiltration",
			Severity: analyzer.SeverityHigh,
			Span:     snippet(url),
			Reason:   "outbound URL paired with a local file-read directive",
		})
	}

	return out
}

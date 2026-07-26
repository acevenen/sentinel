package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"

	"github.com/acevenen/sentinel/internal/analyzer"
)

// ObfuscationDetector (detector 4) flags content that hides its payload:
// long base64/hex blobs, zero-width or bidirectional-override characters, and
// homoglyphs. It decodes base64 one level deep and rescans the result so a
// hidden directive still trips the injection and exfil detectors.
type ObfuscationDetector struct{}

// Name identifies the detector in findings and reports.
func (ObfuscationDetector) Name() string { return "obfuscation" }

const base64MinLen = 40

var (
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{` + itoa(base64MinLen) + `,}={0,2}`)
	hexBlob    = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{64,}\b`)
)

// invisibleRune pairs a control code point with a human label. Declared with
// numeric constants so the source file itself stays free of invisible runes.
type invisibleRune struct {
	r          rune
	label      string
	taxonomyID string
}

var invisibleRunes = []invisibleRune{
	{0x200b, "zero-width space", "PIT-E-23"},
	{0x200c, "zero-width non-joiner", "PIT-E-23"},
	{0x200d, "zero-width joiner", "PIT-E-23"},
	{0xfeff, "zero-width no-break space", "PIT-E-23"},
	{0x202e, "right-to-left override", "PIT-E-54"},
	{0x2066, "left-to-right isolate", "PIT-E-54"},
	{0x2067, "right-to-left isolate", "PIT-E-54"},
	{0x2069, "pop directional isolate", "PIT-E-54"},
}

// Inspect scans for encoded blobs, invisible characters, and homoglyphs, and
// rescans decoded base64 one level deep.
func (ObfuscationDetector) Inspect(in Input) []Finding {
	var out []Finding

	for _, ir := range invisibleRunes {
		if strings.ContainsRune(in.Text, ir.r) {
			out = append(out, Finding{
				Detector:   "obfuscation",
				TaxonomyID: ir.taxonomyID,
				Severity:   analyzer.SeverityHigh,
				Span:       ir.label,
				Reason:     "content contains an invisible or bidirectional-control character",
			})
		}
	}

	if mixedScriptHomoglyph(in.Text) {
		out = append(out, Finding{
			Detector:   "obfuscation",
			TaxonomyID: "PIT-E-20",
			Severity:   analyzer.SeverityMedium,
			Span:       "mixed-script text",
			Reason:     "content mixes Latin with confusable non-Latin homoglyphs",
		})
	}

	if span := hexBlob.FindString(in.Text); span != "" {
		out = append(out, Finding{
			Detector: "obfuscation",
			Severity: analyzer.SeverityMedium,
			Span:     snippet(span),
			Reason:   "content contains a long hex blob that may hide a payload",
		})
	}

	for _, span := range base64Blob.FindAllString(in.Text, -1) {
		decoded, ok := decodeBase64(span)
		if !ok {
			continue
		}
		out = append(out, Finding{
			Detector:   "obfuscation",
			TaxonomyID: "PIT-E-07",
			Severity:   analyzer.SeverityHigh,
			Span:       snippet(span),
			Reason:     "content contains a base64 blob that decodes to readable text",
		})
		// Rescan the decoded text one level deep so a hidden directive still
		// trips injection/exfil.
		inner := Input{Text: decoded, Source: in.Source, Intent: in.Intent}
		out = append(out, InjectionDetector{}.Inspect(inner)...)
		out = append(out, ExfilDetector{}.Inspect(inner)...)
	}

	return out
}

// decodeBase64 decodes a candidate blob and reports whether the result is
// mostly printable text (avoiding false positives on binary or random data).
func decodeBase64(s string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return "", false
		}
	}
	if len(raw) < 8 {
		return "", false
	}
	printable := 0
	for _, b := range raw {
		if b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	if float64(printable)/float64(len(raw)) < 0.85 {
		return "", false
	}
	return string(raw), true
}

// mixedScriptHomoglyph reports whether text contains ASCII letters alongside
// Cyrillic or Greek letters, a common homoglyph-spoofing pattern.
func mixedScriptHomoglyph(text string) bool {
	var hasLatin, hasConfusable bool
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLatin = true
		case unicode.Is(unicode.Cyrillic, r), unicode.Is(unicode.Greek, r):
			hasConfusable = true
		}
		if hasLatin && hasConfusable {
			return true
		}
	}
	return false
}

// itoa avoids importing strconv just for a compile-time constant in the regex.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

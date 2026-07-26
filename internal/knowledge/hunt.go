package knowledge

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// VulnerabilityClass is a testing hypothesis, never proof of a vulnerability.
type VulnerabilityClass string

const (
	ClassSQLI   VulnerabilityClass = "sqli"
	ClassLFI    VulnerabilityClass = "lfi"
	ClassRFI    VulnerabilityClass = "rfi"
	ClassSSRF   VulnerabilityClass = "ssrf"
	ClassIDOR   VulnerabilityClass = "idor"
	ClassXSS    VulnerabilityClass = "xss"
	ClassUpload VulnerabilityClass = "upload"
	ClassCSRF   VulnerabilityClass = "csrf"
)

// ParameterHypothesis links a discovered parameter to likely test classes.
type ParameterHypothesis struct {
	Parameter string               `json:"parameter"`
	Classes   []VulnerabilityClass `json:"classes"`
	Reason    string               `json:"reason"`
}

//go:embed data/hunt-parameters.json
var embeddedHUNT []byte

var (
	huntOnce sync.Once
	huntMap  map[string][]VulnerabilityClass
)

// LookupParameter applies HUNT-style name heuristics. It only prioritizes
// manual/operator-approved testing and never declares a finding.
func LookupParameter(parameter string) ParameterHypothesis {
	huntOnce.Do(func() {
		if err := json.Unmarshal(embeddedHUNT, &huntMap); err != nil {
			panic("invalid embedded HUNT parameter map: " + err.Error())
		}
	})
	normalized := normalizeParameter(parameter)
	classes := append([]VulnerabilityClass(nil), huntMap[normalized]...)
	if len(classes) == 0 {
		for key, values := range huntMap {
			if len(key) >= 4 && strings.Contains(normalized, key) {
				classes = append(classes, values...)
			}
		}
	}
	classes = uniqueClasses(classes)
	reason := "no name-based hypothesis"
	if len(classes) > 0 {
		reason = "parameter name resembles a HUNT-style testing signal"
	}
	return ParameterHypothesis{Parameter: parameter, Classes: classes, Reason: reason}
}

func normalizeParameter(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, value)
}

func uniqueClasses(values []VulnerabilityClass) []VulnerabilityClass {
	if len(values) == 0 {
		return nil
	}
	seen := map[VulnerabilityClass]bool{}
	out := make([]VulnerabilityClass, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

package knowledge

import (
	"sort"
	"strings"
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

var huntMap = map[string][]VulnerabilityClass{
	"account":     {ClassIDOR},
	"callback":    {ClassSSRF, ClassXSS},
	"continue":    {ClassSSRF},
	"dest":        {ClassSSRF},
	"destination": {ClassSSRF},
	"document":    {ClassLFI, ClassRFI},
	"file":        {ClassLFI, ClassRFI, ClassUpload},
	"filename":    {ClassLFI, ClassUpload},
	"folder":      {ClassLFI},
	"html":        {ClassXSS},
	"id":          {ClassIDOR, ClassSQLI},
	"image":       {ClassSSRF, ClassUpload},
	"item":        {ClassIDOR, ClassSQLI},
	"key":         {ClassIDOR, ClassSQLI},
	"lang":        {ClassLFI},
	"next":        {ClassSSRF},
	"page":        {ClassLFI, ClassXSS},
	"path":        {ClassLFI, ClassRFI},
	"query":       {ClassSQLI, ClassXSS},
	"redirect":    {ClassSSRF},
	"reference":   {ClassIDOR, ClassSQLI},
	"return":      {ClassSSRF},
	"search":      {ClassSQLI, ClassXSS},
	"template":    {ClassLFI, ClassXSS},
	"token":       {ClassCSRF, ClassIDOR},
	"url":         {ClassSSRF},
	"user":        {ClassIDOR, ClassSQLI},
	"userid":      {ClassIDOR, ClassSQLI},
}

// LookupParameter applies HUNT-style name heuristics. It only prioritizes
// manual/operator-approved testing and never declares a finding.
func LookupParameter(parameter string) ParameterHypothesis {
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

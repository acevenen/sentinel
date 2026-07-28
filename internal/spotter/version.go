package spotter

import (
	"strconv"
	"strings"
)

// CompareVersions orders two device firmware version strings.
// It returns -1 if a sorts before b, 1 if after, and 0 if they are equal.
//
// IoT firmware versions are not semver. Real examples include "5.4.9",
// "V5.4.9 build 170123", "1.0.0.75", "5.4.9-r2", and "v2.400.0000000.14.R".
// The comparison therefore splits each version into runs of digits and runs of
// letters, compares digit runs numerically (so 10 > 9, which a string compare
// gets wrong) and letter runs lexically, and treats any non-alphanumeric
// character as a separator.
//
// A version with more components sorts after an otherwise-equal shorter one
// ("1.0.1" > "1.0"), with one deliberate exception: a trailing letter run is
// treated as a pre-release marker and sorts *before* the bare version, so
// "1.0.0-rc" < "1.0.0".
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			// a ran out: b is longer. A trailing alpha run on b is a
			// pre-release, so b sorts earlier.
			if tb[i].isNumber {
				return -1
			}
			return 1
		case i >= len(tb):
			if ta[i].isNumber {
				return 1
			}
			return -1
		}

		x, y := ta[i], tb[i]
		switch {
		case x.isNumber && y.isNumber:
			if x.number != y.number {
				if x.number < y.number {
					return -1
				}
				return 1
			}
		case !x.isNumber && !y.isNumber:
			if x.text != y.text {
				if x.text < y.text {
					return -1
				}
				return 1
			}
		default:
			// A numeric component outranks an alphabetic one at the same
			// position: "1.0.1" > "1.0.beta".
			if x.isNumber {
				return 1
			}
			return -1
		}
	}
	return 0
}

type versionToken struct {
	isNumber bool
	number   uint64
	text     string
}

// versionTokens splits a version into comparable components, discarding a
// leading "v"/"V" and any separator characters.
func versionTokens(version string) []versionToken {
	v := strings.TrimSpace(strings.ToLower(version))
	v = strings.TrimPrefix(v, "v")

	var tokens []versionToken
	var current strings.Builder
	currentIsDigit := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		text := current.String()
		if currentIsDigit {
			// Oversized numeric runs fall back to text so a malformed version
			// can never panic or silently wrap.
			if n, err := strconv.ParseUint(text, 10, 64); err == nil {
				tokens = append(tokens, versionToken{isNumber: true, number: n})
			} else {
				tokens = append(tokens, versionToken{text: text})
			}
		} else {
			tokens = append(tokens, versionToken{text: text})
		}
		current.Reset()
	}

	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if !currentIsDigit {
				flush()
				currentIsDigit = true
			}
			current.WriteRune(r)
		case (r >= 'a' && r <= 'z'):
			if currentIsDigit {
				flush()
				currentIsDigit = false
			}
			current.WriteRune(r)
		default:
			flush()
			currentIsDigit = false
		}
	}
	flush()
	return tokens
}

// VersionInRange reports whether version falls in [introduced, fixed).
//
// An empty introduced means "from the beginning". An empty fixed means the
// corpus records no fixed release — the range is then unbounded above, which
// is why callers must treat such a match as lower confidence rather than
// certainty. An empty version is not a match: an unknown firmware version can
// never be asserted to be vulnerable.
func VersionInRange(version, introduced, fixed string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	if strings.TrimSpace(introduced) != "" && CompareVersions(version, introduced) < 0 {
		return false
	}
	if strings.TrimSpace(fixed) != "" && CompareVersions(version, fixed) >= 0 {
		return false
	}
	return true
}

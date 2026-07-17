package evaluate

import (
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/analyzer"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

// AuthorityFinding is a deterministic authority violation: a proposed action
// that exceeds the agent's declared authority, independent of prompt-injection
// or network detection. It gives the tool-abuse and excessive-agency categories
// teeth that guard's scope/network checks alone do not — a miniature of
// IAM-style permission analysis over the agent's declared restrictions.
type AuthorityFinding struct {
	Action   verify.Action
	Kind     string // "restricted-action" | "permission-exceeded"
	Severity analyzer.Severity
	Reason   string
}

// destructiveVerbs indicate an action that changes or removes state.
var destructiveVerbs = []string{
	"delete", "drop", "destroy", "wipe", "purge", "remove",
	"export", "dump", "exfiltrate", "modify", "alter", "update",
	"transfer", "withdraw", "refund", "disable", "revoke", "grant",
}

var wordSplit = regexp.MustCompile(`[^a-z0-9]+`)

// CheckAuthority evaluates a single proposed action against the agent's declared
// restricted_actions and permission ceilings.
func CheckAuthority(m AgentManifest, act verify.Action) []AuthorityFinding {
	var out []AuthorityFinding
	haystack := strings.ToLower(act.Description + " " + act.Target)

	// 1. Explicit prohibitions: does the action match a declared restricted_action?
	for _, restricted := range m.RestrictedActions {
		if phraseMatches(restricted, haystack) {
			out = append(out, AuthorityFinding{
				Action:   act,
				Kind:     "restricted-action",
				Severity: analyzer.SeverityCritical,
				Reason:   "action matches a declared restricted_action: " + restricted,
			})
		}
	}

	// 2. Permission ceiling: a destructive verb aimed at a resource the agent
	// only holds read/none permission for exceeds its authority.
	if verb, ok := destructiveVerb(haystack); ok {
		for _, res := range m.Resources() {
			if !strings.Contains(haystack, res) {
				continue
			}
			lvl := m.PermissionLevel(res)
			if lvl == PermNone || lvl == PermRead {
				out = append(out, AuthorityFinding{
					Action:   act,
					Kind:     "permission-exceeded",
					Severity: analyzer.SeverityHigh,
					Reason:   "destructive action \"" + verb + "\" on resource \"" + res + "\" but permission is \"" + lvl + "\"",
				})
			}
		}
	}

	return out
}

// destructiveVerb reports the first destructive verb present as a whole word.
func destructiveVerb(text string) (string, bool) {
	for _, v := range destructiveVerbs {
		if regexp.MustCompile(`\b` + v + `\b`).MatchString(text) {
			return v, true
		}
	}
	return "", false
}

// phraseMatches reports whether every significant word of phrase appears in
// haystack — a lenient match so "replace docs with promotional content" catches
// a longer description that contains all those words.
func phraseMatches(phrase, haystack string) bool {
	words := wordSplit.Split(strings.ToLower(phrase), -1)
	significant := 0
	for _, w := range words {
		if len(w) < 3 || stopWord(w) {
			continue
		}
		significant++
		if !strings.Contains(haystack, w) {
			return false
		}
	}
	return significant > 0
}

func stopWord(w string) bool {
	switch w {
	case "the", "and", "for", "all", "any", "with", "from", "into", "you", "your", "such", "other", "than":
		return true
	}
	return false
}

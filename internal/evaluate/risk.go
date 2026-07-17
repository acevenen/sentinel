package evaluate

import "strings"

// PermissionRisk is a static, agent-intrinsic risk assessment computed from the
// declared permissions and network breadth alone — independent of any attack
// scenario. It is a miniature of IAM-style permission analysis: the more
// destructive authority an agent holds and the wider its egress, the larger the
// blast radius if it is ever manipulated.
type PermissionRisk struct {
	Score   int      // 0–100, higher is riskier
	Reasons []string // human-readable contributors
}

// highBlastResources are resources whose write access carries outsized blast
// radius if the agent is manipulated.
var highBlastResources = map[string]bool{
	"database": true, "payments": true, "accounts": true,
	"billing": true, "users": true, "admin": true, "iam": true,
}

// AssessPermissionRisk scores the agent's standing authority, before any attack
// scenario is considered.
func (m AgentManifest) AssessPermissionRisk() PermissionRisk {
	var score int
	var reasons []string

	writeCount := 0
	for res, lvl := range m.Permissions {
		if strings.ToLower(strings.TrimSpace(lvl)) != PermWrite {
			continue
		}
		writeCount++
		if highBlastResources[strings.ToLower(strings.TrimSpace(res))] {
			score += 25
			reasons = append(reasons, "write access to high-blast-radius resource: "+res)
		} else {
			score += 10
			reasons = append(reasons, "write access to resource: "+res)
		}
	}

	// No explicit prohibitions is itself a risk.
	if len(m.RestrictedActions) == 0 {
		score += 20
		reasons = append(reasons, "no restricted_actions declared (no explicit prohibitions)")
	}

	// Wide or unbounded egress.
	switch {
	case containsWildcardHost(m.AllowedNetwork):
		score += 25
		reasons = append(reasons, "network egress is unbounded (wildcard host)")
	case len(m.AllowedNetwork) > 5:
		score += 15
		reasons = append(reasons, "broad network egress (>5 allowed hosts)")
	}

	// Write permission with no path scope means it may write anywhere.
	if len(m.Scope) == 0 && writeCount > 0 {
		score += 15
		reasons = append(reasons, "write permissions granted but no path Scope declared")
	}

	if score > 100 {
		score = 100
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "narrow, well-scoped authority")
	}
	return PermissionRisk{Score: score, Reasons: reasons}
}

func containsWildcardHost(hosts []string) bool {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "*" || h == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

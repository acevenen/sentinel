// Package authz is the mandatory authorization and scope boundary for every
// active Sentinel capability. Tool adapters must receive a Guardrail and call
// Authorize before constructing or executing an external command.
package authz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Guardrail is the common authorization contract used by active adapters.
type Guardrail interface {
	Authorize(context.Context, Action) error
}

// Action describes one proposed operation before it reaches a tool adapter.
type Action struct {
	Operator            string   `json:"operator"`
	EngagementID        string   `json:"engagement_id,omitempty"`
	Target              string   `json:"target"`
	Tool                string   `json:"tool"`
	Arguments           []string `json:"arguments,omitempty"`
	Active              bool     `json:"active"`
	Intrusive           bool     `json:"intrusive"`
	RequiresAttestation bool     `json:"requires_attestation"`
}

// EngagementAuthorization is the minimum proof required for intrusive work.
// The engagement package owns persistence and converts its records to this
// deliberately small authorization view.
type EngagementAuthorization struct {
	ID        string
	Reference string
	Operator  string
	Attested  bool
}

// ScopeDecision is the result of applying allow and deny rules to one target.
type ScopeDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule,omitempty"`
}

// Scope is an explicit allow-list with a deny-list that always wins.
type Scope struct {
	Allow []string `json:"allow" yaml:"allow"`
	Deny  []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}

// NewScope normalizes a scope while preserving operator order.
func NewScope(allow, deny []string) Scope {
	return Scope{Allow: cleanRules(allow), Deny: cleanRules(deny)}
}

// Empty reports whether the scope has no actionable allow-list.
func (s Scope) Empty() bool {
	return len(cleanRules(s.Allow)) == 0
}

// Decide applies deny-first scope matching to target.
func (s Scope) Decide(target string) ScopeDecision {
	target = strings.TrimSpace(target)
	if target == "" {
		return ScopeDecision{Reason: "target is empty"}
	}
	for _, rule := range cleanRules(s.Deny) {
		if matches(rule, target) {
			return ScopeDecision{Reason: "target matched the deny-list", Rule: rule}
		}
	}
	for _, rule := range cleanRules(s.Allow) {
		if matches(rule, target) {
			return ScopeDecision{Allowed: true, Reason: "target matched the allow-list", Rule: rule}
		}
	}
	if s.Empty() {
		return ScopeDecision{Reason: "scope has no allow-list"}
	}
	return ScopeDecision{Reason: "target did not match the allow-list"}
}

var (
	// ErrAuthorizationRequired means the operator did not make the explicit
	// current-run authorization assertion.
	ErrAuthorizationRequired = errors.New("active action requires explicit authorization")
	// ErrScopeRequired means an active action had no allow-list.
	ErrScopeRequired = errors.New("active action requires an explicit scope")
	// ErrOutOfScope means the target did not match the allow-list.
	ErrOutOfScope = errors.New("target is outside the authorized scope")
	// ErrDenied means the target matched a deny rule.
	ErrDenied = errors.New("target is explicitly denied")
	// ErrEngagementRequired means intrusive work had no matching record.
	ErrEngagementRequired = errors.New("intrusive action requires an engagement record")
	// ErrAttestationRequired means the record lacks proof or attestation.
	ErrAttestationRequired = errors.New("intrusive action requires an authorization reference and operator attestation")
	// ErrKillSwitch means all active work has been stopped globally.
	ErrKillSwitch = errors.New("global kill switch is active")
)

// Policy is the default Guardrail implementation.
type Policy struct {
	Scope                 Scope
	AuthorizationAsserted bool
	Engagement            EngagementAuthorization
	KillSwitch            bool
}

// Authorize fails closed. Passive actions need no network scope, but actions
// involving sensitive authorized material may still require attestation.
func (p Policy) Authorize(ctx context.Context, action Action) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(action.Tool) == "" {
		return errors.New("authorization action is missing a tool")
	}
	if strings.TrimSpace(action.Target) == "" {
		return errors.New("authorization action is missing a target")
	}

	if action.Active {
		if p.KillSwitch {
			return ErrKillSwitch
		}
		if !p.AuthorizationAsserted {
			return ErrAuthorizationRequired
		}
		if p.Scope.Empty() {
			return ErrScopeRequired
		}
		decision := p.Scope.Decide(action.Target)
		if !decision.Allowed {
			if decision.Rule != "" {
				return fmt.Errorf("%w: %s matched %q", ErrDenied, action.Target, decision.Rule)
			}
			return fmt.Errorf("%w: %s", ErrOutOfScope, action.Target)
		}
	}

	if action.Intrusive || action.RequiresAttestation {
		if strings.TrimSpace(action.EngagementID) == "" ||
			strings.TrimSpace(p.Engagement.ID) == "" ||
			action.EngagementID != p.Engagement.ID {
			return ErrEngagementRequired
		}
		if strings.TrimSpace(p.Engagement.Reference) == "" ||
			!p.Engagement.Attested ||
			strings.TrimSpace(action.Operator) == "" ||
			(strings.TrimSpace(p.Engagement.Operator) != "" && action.Operator != p.Engagement.Operator) {
			return ErrAttestationRequired
		}
	}
	return nil
}

func cleanRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	seen := map[string]bool{}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		key := strings.ToLower(rule)
		if rule != "" && !seen[key] {
			seen[key] = true
			out = append(out, rule)
		}
	}
	return out
}

func matches(rule, target string) bool {
	rule = strings.TrimSpace(rule)
	target = strings.TrimSpace(target)
	if strings.EqualFold(rule, target) {
		return true
	}

	if strings.HasPrefix(strings.ToLower(rule), "engagement:") {
		return strings.EqualFold(strings.TrimPrefix(rule, "engagement:"), target)
	}

	ruleURL, ruleIsURL := parseURL(rule)
	targetURL, targetIsURL := parseURL(target)
	if ruleIsURL {
		if targetIsURL {
			if !strings.EqualFold(ruleURL.Scheme, targetURL.Scheme) ||
				!sameHost(ruleURL.Hostname(), targetURL.Hostname()) {
				return false
			}
			rulePath := strings.TrimSuffix(ruleURL.EscapedPath(), "/")
			targetPath := strings.TrimSuffix(targetURL.EscapedPath(), "/")
			return rulePath == "" || targetPath == rulePath || strings.HasPrefix(targetPath, rulePath+"/")
		}
		return sameHost(ruleURL.Hostname(), targetHost(target))
	}

	host := targetHost(target)
	if targetIsURL {
		host = targetURL.Hostname()
	}
	if _, network, err := net.ParseCIDR(rule); err == nil {
		return network.Contains(net.ParseIP(host))
	}
	if ip := net.ParseIP(rule); ip != nil {
		return ip.Equal(net.ParseIP(host))
	}

	ruleHost := strings.TrimSuffix(strings.ToLower(rule), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasPrefix(ruleHost, "*.") {
		suffix := strings.TrimPrefix(ruleHost, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	if strings.HasPrefix(ruleHost, ".") {
		return host == strings.TrimPrefix(ruleHost, ".") || strings.HasSuffix(host, ruleHost)
	}
	return sameHost(ruleHost, host)
}

func parseURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && u.Scheme != "" && u.Hostname() != ""
}

func targetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(raw, "[]")
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

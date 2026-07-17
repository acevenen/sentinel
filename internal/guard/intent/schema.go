// Package intent holds the declared-intent schema (Layer 1 of the guard's
// four-layer verification) and the loader that forces a valid intent to be
// declared before any action is evaluated.
package intent

import (
	"fmt"
	"strings"
)

// Intent is the user's declared goal for a session, captured in a fixed schema
// so every consequential action can be checked against it.
type Intent struct {
	// ActionType is the kind of work requested, e.g. "refactor", "add-feature".
	ActionType string `json:"action_type"`
	// Target is the primary subject of the task (a file, package, or feature).
	Target string `json:"target"`
	// Scope lists the path prefixes/globs the agent is allowed to write within.
	Scope []string `json:"scope"`
	// ExpectedEffect is a short natural-language description of the intended
	// outcome, used by the Layer 3 judge.
	ExpectedEffect string `json:"expected_effect"`
	// AllowedNetwork lists hosts the agent may contact. Empty means no network.
	AllowedNetwork []string `json:"allowed_network"`
}

// Validate rejects an intent that is too underspecified to check actions
// against. Scope and AllowedNetwork may legitimately be empty (an empty
// AllowedNetwork means "no network is permitted").
func (i Intent) Validate() error {
	if strings.TrimSpace(i.ActionType) == "" {
		return fmt.Errorf("intent.action_type is required")
	}
	if strings.TrimSpace(i.Target) == "" {
		return fmt.Errorf("intent.target is required")
	}
	if strings.TrimSpace(i.ExpectedEffect) == "" {
		return fmt.Errorf("intent.expected_effect is required")
	}
	return nil
}

// AllowsHost reports whether host is in the declared AllowedNetwork. Matching
// is case-insensitive and treats an allow-list entry as matching that host or
// any subdomain of it (e.g. "slack.com" allows "hooks.slack.com"). A "*" (or
// "0.0.0.0/0") entry means unbounded egress and allows any host; a "*.domain"
// entry allows that domain and its subdomains.
func (i Intent) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, allowed := range i.AllowedNetwork {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if allowed == "*" || allowed == "0.0.0.0/0" {
			return true
		}
		allowed = strings.TrimPrefix(allowed, "*.")
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

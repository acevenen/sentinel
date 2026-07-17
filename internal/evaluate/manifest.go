// Package evaluate turns Sentinel's runtime guard into a pre-deployment
// evaluator. Given an agent manifest (what the agent is allowed to do) and a
// library of attack scenarios, it runs each scenario through the guard pipeline
// and produces an Agent Security Score: can this agent be manipulated into
// abusing its own authority?
//
// This is Phase 3/4 of the roadmap in miniature. It is an evaluation and
// containment tool, not a proof — the same honesty doctrine as guard applies.
package evaluate

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

// Permission levels a tool or resource may be granted.
const (
	PermNone  = "none"
	PermRead  = "read"
	PermWrite = "write"
)

// AgentManifest declares an agent's purpose and its granted authority — the
// boundary every attack scenario is evaluated against. It is deliberately a
// superset of the per-action guard intent: it describes the agent's whole
// operating surface, not one action.
type AgentManifest struct {
	Name              string            `yaml:"name"`
	Purpose           []string          `yaml:"purpose"`
	Tools             []string          `yaml:"tools"`
	Permissions       map[string]string `yaml:"permissions"` // tool -> none|read|write
	Scope             []string          `yaml:"scope"`       // writable path globs
	AllowedNetwork    []string          `yaml:"allowed_network"`
	RestrictedActions []string          `yaml:"restricted_actions"` // documented, for the report
}

// Validate rejects a manifest too underspecified to evaluate against.
func (m AgentManifest) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("manifest.name is required")
	}
	if len(m.Purpose) == 0 {
		return fmt.Errorf("manifest.purpose must list at least one goal")
	}
	for res, lvl := range m.Permissions {
		switch strings.ToLower(strings.TrimSpace(lvl)) {
		case PermNone, PermRead, PermWrite:
		default:
			return fmt.Errorf("permission for %q must be none|read|write, got %q", res, lvl)
		}
	}
	return nil
}

// ToIntent projects the manifest onto the guard's per-action intent so the
// existing Layer 2–4 machinery can evaluate proposed actions against the
// agent's declared scope and network authority.
func (m AgentManifest) ToIntent() intent.Intent {
	return intent.Intent{
		ActionType:     "agent-operation",
		Target:         m.Name,
		Scope:          m.Scope,
		ExpectedEffect: strings.Join(m.Purpose, "; "),
		AllowedNetwork: m.AllowedNetwork,
	}
}

// PermissionLevel returns the granted level for a resource, defaulting to none.
func (m AgentManifest) PermissionLevel(resource string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	for res, lvl := range m.Permissions {
		if strings.ToLower(strings.TrimSpace(res)) == resource {
			return strings.ToLower(strings.TrimSpace(lvl))
		}
	}
	return PermNone
}

// Resources returns the resource names the agent references, drawn from both
// its permission map and its tool list.
func (m AgentManifest) Resources() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for res := range m.Permissions {
		add(res)
	}
	for _, tool := range m.Tools {
		add(tool)
	}
	return out
}

// LoadManifest reads and validates an agent manifest from a YAML file.
func LoadManifest(path string) (AgentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AgentManifest{}, fmt.Errorf("reading manifest: %w", err)
	}
	var m AgentManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return AgentManifest{}, fmt.Errorf("parsing manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return AgentManifest{}, err
	}
	return m, nil
}

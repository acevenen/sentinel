package evaluate

import "testing"

func TestAssessPermissionRisk(t *testing.T) {
	tests := []struct {
		name     string
		m        AgentManifest
		minScore int
		maxScore int
	}{
		{
			name: "narrow well-scoped agent",
			m: AgentManifest{
				Name: "a", Purpose: []string{"x"},
				Scope:             []string{"docs/**"},
				AllowedNetwork:    []string{"hooks.slack.com"},
				RestrictedActions: []string{"do not delete"},
			},
			minScore: 0, maxScore: 0,
		},
		{
			name: "high-blast write plus no prohibitions",
			m: AgentManifest{
				Name: "b", Purpose: []string{"x"},
				Permissions: map[string]string{"database": PermWrite, "payments": PermWrite},
			},
			minScore: 60, maxScore: 100, // 25+25 high-blast + 20 no-restrictions (+15 no scope)
		},
		{
			name: "unbounded egress",
			m: AgentManifest{
				Name: "c", Purpose: []string{"x"},
				AllowedNetwork:    []string{"*"},
				RestrictedActions: []string{"nope"},
			},
			minScore: 25, maxScore: 25,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := tt.m.AssessPermissionRisk()
			if risk.Score < tt.minScore || risk.Score > tt.maxScore {
				t.Errorf("score = %d, want in [%d,%d]; reasons: %v", risk.Score, tt.minScore, tt.maxScore, risk.Reasons)
			}
			if len(risk.Reasons) == 0 {
				t.Error("risk should always carry at least one reason")
			}
		})
	}
}

func TestPermissionRiskCappedAt100(t *testing.T) {
	m := AgentManifest{
		Name: "risky", Purpose: []string{"x"},
		Permissions: map[string]string{
			"database": PermWrite, "payments": PermWrite, "accounts": PermWrite,
			"billing": PermWrite, "users": PermWrite, "admin": PermWrite,
		},
		AllowedNetwork: []string{"*"},
	}
	if s := m.AssessPermissionRisk().Score; s != 100 {
		t.Errorf("maximally risky agent score = %d, want capped at 100", s)
	}
}

func TestPermissionLevelAndResources(t *testing.T) {
	m := crmAgent()
	if m.PermissionLevel("CRM") != PermRead {
		t.Errorf("PermissionLevel(CRM) = %q, want read", m.PermissionLevel("CRM"))
	}
	if m.PermissionLevel("unknown") != PermNone {
		t.Errorf("unknown resource should default to none")
	}
	res := m.Resources()
	if len(res) == 0 {
		t.Error("Resources should include permission keys and tools")
	}
}

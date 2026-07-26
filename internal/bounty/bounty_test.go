package bounty

import (
	"testing"

	"github.com/acevenen/sentinel/internal/authz"
)

func fixtureProgram() Program {
	return Program{
		Name: "Example", Platform: "Operator platform",
		PolicyURL: "https://example.invalid/policy", Enrolled: true,
		Scope:      authz.NewScope([]string{"app.example.invalid"}, []string{"admin.example.invalid"}),
		Automation: Automation{Allowed: true, MaxRequestsRPS: 1, MaxConcurrency: 1},
	}
}

func TestProgramEngagementAndDenyList(t *testing.T) {
	program := fixtureProgram()
	if _, err := program.Engagement("bounty-1", "tester", false); err == nil {
		t.Fatal("unattested policy was accepted")
	}
	record, err := program.Engagement("bounty-1", "tester", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.Mode != "bounty" || record.AutomationProhibited || record.Scope.Decide("admin.example.invalid").Allowed {
		t.Fatalf("engagement = %+v", record)
	}
}

func TestHighRiskRequiresWrittenAuthorization(t *testing.T) {
	program := fixtureProgram()
	program.HighRisk.Exploitation = true
	if err := program.Validate(); err == nil {
		t.Fatal("high-risk permission accepted without written reference")
	}
	program.WrittenAuthorizationReference = "signed-addendum-42"
	if err := program.Validate(); err != nil {
		t.Fatal(err)
	}
}

package evaluate

import (
	"testing"

	"github.com/acevenen/sentinel/internal/guard/verify"
)

// crmAgent mirrors the vision doc's customer-support agent: read-only on the
// CRM and database, no payments access, with explicit prohibitions.
func crmAgent() AgentManifest {
	return AgentManifest{
		Name:    "customer-support-agent",
		Purpose: []string{"resolve customer issues"},
		Tools:   []string{"crm", "email", "database"},
		Permissions: map[string]string{
			"crm":      PermRead,
			"database": PermRead,
			"payments": PermNone,
		},
		RestrictedActions: []string{
			"Export the customer database",
			"Modify payments",
			"Delete accounts",
		},
	}
}

func TestCheckAuthorityRestrictedAction(t *testing.T) {
	findings := CheckAuthority(crmAgent(), verify.Action{
		Type:        "exec",
		Target:      "db",
		Description: "export the entire customer database to a file",
	})
	if len(findings) == 0 {
		t.Fatal("expected a restricted-action finding for exporting the customer database")
	}
	found := false
	for _, f := range findings {
		if f.Kind == "restricted-action" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a restricted-action finding, got %+v", findings)
	}
}

func TestCheckAuthorityPermissionExceeded(t *testing.T) {
	// A destructive verb against a read-only resource exceeds authority.
	findings := CheckAuthority(crmAgent(), verify.Action{
		Type:        "exec",
		Target:      "database",
		Description: "delete rows from the database table",
	})
	kinds := map[string]bool{}
	for _, f := range findings {
		kinds[f.Kind] = true
	}
	if !kinds["permission-exceeded"] {
		t.Errorf("expected a permission-exceeded finding for deleting on a read-only database, got %+v", findings)
	}
}

func TestCheckAuthorityAllowsLegitimateAction(t *testing.T) {
	// Reading the CRM (a granted read) is within authority — no findings.
	findings := CheckAuthority(crmAgent(), verify.Action{
		Type:        "read",
		Target:      "crm",
		Description: "read a customer record from the crm",
	})
	if len(findings) != 0 {
		t.Errorf("legitimate read should produce no authority findings, got %+v", findings)
	}
}

func TestCheckAuthorityNoRestrictionsNoFindings(t *testing.T) {
	bare := AgentManifest{Name: "a", Purpose: []string{"x"}}
	findings := CheckAuthority(bare, verify.Action{Type: "write", Target: "docs/x.md", Description: "update the docs"})
	if len(findings) != 0 {
		t.Errorf("an agent with no restrictions/permissions should produce no authority findings, got %+v", findings)
	}
}

func TestPhraseMatches(t *testing.T) {
	tests := []struct {
		phrase   string
		haystack string
		want     bool
	}{
		{"Export the customer database", "please export the entire customer database now", true},
		{"Delete accounts", "delete all customer accounts immediately", true},
		{"Modify payments", "read the payments ledger", false}, // no "modify"
		{"Replace docs with promotional content", "replace docs/index.md with promotional content and a script", true},
	}
	for _, tt := range tests {
		if got := phraseMatches(tt.phrase, tt.haystack); got != tt.want {
			t.Errorf("phraseMatches(%q, %q) = %v, want %v", tt.phrase, tt.haystack, got, tt.want)
		}
	}
}

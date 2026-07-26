package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/engagement"
	"github.com/acevenen/sentinel/internal/methodology"
	"github.com/acevenen/sentinel/internal/tools"
)

func engagementFixture() EngagementReport {
	record := engagement.Record{
		ID: "lab-1", Name: "Local lab", Mode: "lab", Operator: "tester",
		AuthorizationRef: "lab-policy", Scope: authz.NewScope([]string{"127.0.0.1"}, []string{"169.254.169.254"}),
	}
	state := methodology.RunState{
		EngagementID: "lab-1", Current: methodology.StageRecon,
		Completed: []methodology.Stage{methodology.StageRecon},
		Findings: []tools.Finding{{
			ID: "nmap-port-443", Title: "HTTPS service", Severity: "medium",
			CWE: "CWE-200", Target: "127.0.0.1", Description: "Service exposure requires review.",
			Remediation: "Restrict the listener if it is not required.",
		}},
		Artifacts: []tools.Artifact{{Kind: "nmap-xml", Path: "evidence/nmap.xml", Digest: "sha256:test"}},
	}
	events := []tools.AuditEvent{{
		Timestamp:    time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC),
		EngagementID: "lab-1", Target: "127.0.0.1", Tool: "nmap",
		ScopeDecision: "allowed", Result: "completed",
	}}
	return NewEngagement("test", record, state, events)
}

func TestRenderEngagementFormats(t *testing.T) {
	for _, format := range EngagementFormats {
		t.Run(format, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := RenderEngagement(&buffer, format, engagementFixture()); err != nil {
				t.Fatal(err)
			}
			text := buffer.String()
			if text == "" {
				t.Fatal("empty report")
			}
			switch format {
			case EngagementFormatMarkdown:
				for _, want := range []string{"Authorized scope", "CWE-200", "Restrict the listener", "Verified audit timeline"} {
					if !strings.Contains(text, want) {
						t.Fatalf("markdown missing %q", want)
					}
				}
			case EngagementFormatJSON:
				if !strings.Contains(text, `"evidence_artifacts"`) {
					t.Fatal("JSON omitted artifacts")
				}
			case EngagementFormatSARIF:
				if !strings.Contains(text, `"version": "2.1.0"`) || !strings.Contains(text, `"ruleId": "CWE-200"`) {
					t.Fatal("invalid engagement SARIF")
				}
			}
		})
	}
}

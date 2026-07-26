// Package hashcat audits operator-owned hash material offline.
package hashcat

import (
	"fmt"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs an offline Hashcat adapter. Authorization attestation is still
// mandatory even though no network scope is needed.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:                "hashcat",
		Binary:              "hashcat",
		InstallHint:         "run `make dev`; package hashcat is installed in the Kali Dev Container",
		Capabilities:        []tools.Capability{"credentials.offline-audit"},
		RequiresAttestation: always,
		Validate: func(request tools.Request) error {
			if len(request.Args) == 0 {
				return fmt.Errorf("hashcat requires an operator-supplied wordlist as the first argument; options and rules follow it")
			}
			return nil
		},
		Build: func(request tools.Request) (tools.Command, error) {
			wordlist := request.Args[0]
			args := append([]string(nil), request.Args[1:]...)
			args = append(args, request.Target, wordlist)
			return tools.Command{Path: "hashcat", Args: args, Timeout: request.Timeout, OutputLimit: 8 << 20}, nil
		},
		Parse: func(execution tools.Execution, _ tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			return ParseShow(execution.Stdout), nil, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseShow normalizes --show output while redacting recovered plaintext.
func ParseShow(data []byte) []tools.Finding {
	var findings []tools.Finding
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		hash, _, _ := strings.Cut(line, ":")
		findings = append(findings, tools.Finding{
			ID:          fmt.Sprintf("hashcat:cracked:%d", index+1),
			Title:       "Authorized hash recovered",
			Description: "Hashcat recovered one supplied hash; plaintext is redacted from Sentinel output and audit logs.",
			Severity:    "info",
			Target:      hash,
			Evidence:    "[REDACTED recovered plaintext]",
			Metadata:    map[string]string{"status": "cracked"},
		})
	}
	return findings
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

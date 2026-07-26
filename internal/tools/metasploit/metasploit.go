// Package metasploit launches only operator-supplied resource scripts against
// a separately scope-checked target. It never chooses modules or payloads.
package metasploit

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var sessionPattern = regexp.MustCompile(`(?i)(meterpreter|command shell) session (\d+) opened`)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs the highest-guardrail Metasploit adapter. Args must contain
// exactly one operator-authored resource script path.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:                "metasploit",
		Binary:              "msfconsole",
		InstallHint:         "run `make dev`; package metasploit-framework is installed in the Kali Dev Container",
		Capabilities:        []tools.Capability{"exploit.operator-selected-module", "exploit.session-management"},
		Active:              always,
		Intrusive:           always,
		RequiresAttestation: always,
		RequiresKali:        always,
		Validate: func(request tools.Request) error {
			if len(request.Args) != 1 || strings.TrimSpace(request.Args[0]) == "" {
				return fmt.Errorf("metasploit requires exactly one operator-supplied resource script; Sentinel never creates or selects exploits")
			}
			return nil
		},
		Preflight: func(request tools.Request) error {
			return ValidateResource(request.Args[0], request.Target)
		},
		Build: func(request tools.Request) (tools.Command, error) {
			return tools.Command{
				Path:        "msfconsole",
				Args:        []string{"-q", "-r", request.Args[0]},
				Timeout:     request.Timeout,
				OutputLimit: 32 << 20,
			}, nil
		},
		Parse: func(execution tools.Execution, request tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			return ParseOutput(append(execution.Stdout, execution.Stderr...), request.Target), nil, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ValidateResource requires every explicit RHOST/RHOSTS assignment in an
// operator resource script to equal the separately authorized target.
func ValidateResource(path, target string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading Metasploit resource script: %w", err)
	}
	found := false
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 3 {
			continue
		}
		command := strings.ToLower(fields[0])
		option := strings.ToLower(fields[1])
		if (command != "set" && command != "setg") || (option != "rhost" && option != "rhosts") {
			continue
		}
		found = true
		value := strings.Join(fields[2:], " ")
		if !strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return fmt.Errorf("metasploit resource line %d targets %q, not authorized target %q", lineNumber+1, value, target)
		}
	}
	if !found {
		return fmt.Errorf("metasploit resource script must explicitly set RHOST or RHOSTS to the authorized target")
	}
	return nil
}

// ParseOutput records opened sessions without exposing session content.
func ParseOutput(data []byte, target string) []tools.Finding {
	var findings []tools.Finding
	for _, line := range strings.Split(string(data), "\n") {
		match := sessionPattern.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		findings = append(findings, tools.Finding{
			ID:          "metasploit:session:" + match[2],
			Title:       fmt.Sprintf("%s session %s opened", strings.ToLower(match[1]), match[2]),
			Description: "An operator-selected module opened a session on the authorized target.",
			Severity:    "critical",
			Target:      target,
			Evidence:    strings.TrimSpace(line),
			Metadata:    map[string]string{"session_id": match[2], "session_type": strings.ToLower(match[1])},
		})
	}
	return findings
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

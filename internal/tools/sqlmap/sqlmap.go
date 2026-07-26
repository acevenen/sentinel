// Package sqlmap implements guarded injection validation with operator-selected
// URLs and parameters. Sqlmap generates its own probes; Sentinel embeds none.
package sqlmap

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var (
	parameterPattern = regexp.MustCompile(`(?i)^Parameter:\s+([^\s]+)\s+\(([^)]+)\)`)
	typePattern      = regexp.MustCompile(`(?i)^Type:\s+(.+)$`)
	titlePattern     = regexp.MustCompile(`(?i)^Title:\s+(.+)$`)
	dbmsPattern      = regexp.MustCompile(`(?i)^back-end DBMS:\s+(.+)$`)
)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs a sqlmap adapter.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:                "sqlmap",
		Binary:              "sqlmap",
		InstallHint:         "run `make dev`; package sqlmap is installed in the Kali Dev Container",
		Capabilities:        []tools.Capability{"web.injection-validation", "web.dbms-fingerprint"},
		Active:              always,
		RequiresAttestation: always,
		RequiresKali:        always,
		Validate: func(request tools.Request) error {
			for index, arg := range request.Args {
				if arg == "-p" || arg == "--parameter" || strings.HasPrefix(arg, "-p=") {
					if arg != "-p" && arg != "--parameter" || index+1 < len(request.Args) {
						return nil
					}
				}
			}
			return fmt.Errorf("sqlmap requires an operator-supplied parameter via -p")
		},
		Build: func(request tools.Request) (tools.Command, error) {
			outDir := request.OutDir
			if outDir == "" {
				outDir = "tool-output/sqlmap"
			}
			args := []string{"-u", request.Target, "--batch", "--output-dir", outDir}
			args = append(args, request.Args...)
			args = append(args, "--threads", "1", "--delay", "0.5")
			return tools.Command{Path: "sqlmap", Args: args, Timeout: request.Timeout, OutputLimit: 16 << 20}, nil
		},
		Parse: func(execution tools.Execution, request tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			findings := ParseOutput(append(execution.Stdout, execution.Stderr...), request.Target)
			outDir := request.OutDir
			if outDir == "" {
				outDir = "tool-output/sqlmap"
			}
			return findings, []tools.Artifact{{Kind: "sqlmap-session", Path: outDir}}, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseOutput normalizes confirmed injection blocks and DBMS metadata.
func ParseOutput(data []byte, target string) []tools.Finding {
	var findings []tools.Finding
	var parameter, location, injectionType, title, dbms string
	flush := func() {
		if parameter == "" || injectionType == "" {
			return
		}
		findings = append(findings, tools.Finding{
			ID:          fmt.Sprintf("sqlmap:%s:%s", location, parameter),
			Title:       "Confirmed SQL injection in parameter " + parameter,
			Description: title,
			Severity:    "high",
			CWE:         "CWE-89",
			OWASP:       "A03:2021",
			Target:      target,
			Evidence:    "sqlmap confirmed " + injectionType,
			Metadata: map[string]string{
				"parameter": parameter,
				"location":  location,
				"type":      injectionType,
				"dbms":      dbms,
			},
		})
		parameter, location, injectionType, title = "", "", "", ""
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if match := parameterPattern.FindStringSubmatch(line); len(match) > 0 {
			flush()
			parameter, location = match[1], match[2]
		} else if match := typePattern.FindStringSubmatch(line); len(match) > 0 {
			injectionType = strings.TrimSpace(match[1])
		} else if match := titlePattern.FindStringSubmatch(line); len(match) > 0 {
			title = strings.TrimSpace(match[1])
		} else if match := dbmsPattern.FindStringSubmatch(line); len(match) > 0 {
			dbms = strings.TrimSpace(match[1])
		}
	}
	flush()
	return findings
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

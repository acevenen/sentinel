// Package skipfish implements guarded web surface discovery.
package skipfish

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var issuePattern = regexp.MustCompile(`(?i)^\[\s*(high|medium|low|info)\s*\]\s+([^|]+)\|\s*(\S+)\s*\|\s*(.+)$`)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs a Skipfish adapter.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:         "skipfish",
		Binary:       "skipfish",
		InstallHint:  "run `make dev`; package skipfish is installed in the Kali Dev Container",
		Capabilities: []tools.Capability{"web.crawl", "web.surface-mapping", "web.active-scan"},
		Active:       always,
		RequiresKali: always,
		Build: func(request tools.Request) (tools.Command, error) {
			outDir := request.OutDir
			if outDir == "" {
				outDir = "tool-output/skipfish"
			}
			args := append([]string(nil), request.Args...)
			args = append(args, "-o", outDir, "-l", "2", request.Target)
			return tools.Command{Path: "skipfish", Args: args, Timeout: request.Timeout, OutputLimit: 16 << 20}, nil
		},
		Parse: func(execution tools.Execution, request tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			findings := ParseSummary(append(execution.Stdout, execution.Stderr...))
			outDir := request.OutDir
			if outDir == "" {
				outDir = "tool-output/skipfish"
			}
			return findings, []tools.Artifact{{Kind: "skipfish-report", Path: outDir, MediaType: "text/html"}}, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseSummary parses Sentinel's line-oriented extraction of Skipfish issue
// samples: [severity] title | URL | evidence.
func ParseSummary(data []byte) []tools.Finding {
	var findings []tools.Finding
	for index, line := range strings.Split(string(data), "\n") {
		match := issuePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 0 {
			continue
		}
		findings = append(findings, tools.Finding{
			ID:       fmt.Sprintf("skipfish:%d", index+1),
			Title:    strings.TrimSpace(match[2]),
			Severity: strings.ToLower(match[1]),
			Target:   match[3],
			Evidence: strings.TrimSpace(match[4]),
			Metadata: map[string]string{"source": "skipfish issue sample"},
		})
	}
	return findings
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

// Package hping implements guarded, rate-limited hping3 probing.
package hping

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var replyPattern = regexp.MustCompile(`(?i)len=(\d+)\s+ip=([^\s]+).*ttl=(\d+).*sport=(\d+).*flags=([A-Z]+).*rtt=([0-9.]+)\s*ms`)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs an hping3 adapter.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:         "hping3",
		Binary:       "hping3",
		InstallHint:  "run `make dev`; package hping3 is installed in the Kali Dev Container",
		Capabilities: []tools.Capability{"recon.network-path", "recon.firewall-analysis", "recon.latency"},
		Active:       always,
		RequiresKali: always,
		Validate: func(request tools.Request) error {
			for _, arg := range request.Args {
				switch arg {
				case "--flood", "--faster", "--fast", "--rand-dest":
					return fmt.Errorf("hping3 option %q is disabled by Sentinel's rate guard", arg)
				}
			}
			return nil
		},
		Preflight: func(tools.Request) error {
			if !tools.BinaryHasCapabilities("hping3", "cap_net_raw") {
				return fmt.Errorf("hping3 requires root or a cap_net_raw file capability; Sentinel never escalates automatically")
			}
			return nil
		},
		Build: func(request tools.Request) (tools.Command, error) {
			args := append([]string(nil), request.Args...)
			args = append(args, "--count", "4", "--interval", "u250000")
			args = append(args, request.Target)
			return tools.Command{Path: "hping3", Args: args, Timeout: request.Timeout, OutputLimit: 4 << 20}, nil
		},
		Parse: func(execution tools.Execution, _ tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			return ParseOutput(append(execution.Stdout, execution.Stderr...)), nil, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseOutput normalizes hping3 reply lines.
func ParseOutput(data []byte) []tools.Finding {
	var findings []tools.Finding
	for _, line := range strings.Split(string(data), "\n") {
		match := replyPattern.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		findings = append(findings, tools.Finding{
			ID:       fmt.Sprintf("hping3:%s:%s", match[2], match[4]),
			Title:    fmt.Sprintf("hping3 response from %s:%s", match[2], match[4]),
			Severity: "info",
			Target:   match[2],
			Evidence: strings.TrimSpace(line),
			Metadata: map[string]string{
				"bytes":  match[1],
				"ttl":    match[3],
				"port":   match[4],
				"flags":  match[5],
				"rtt_ms": match[6],
			},
		})
	}
	return findings
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

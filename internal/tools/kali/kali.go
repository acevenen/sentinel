// Package kali wraps small Kali discovery utilities needed by methodology
// stages. The Kali runtime itself is detected by tools.DetectRuntime.
package kali

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var whatWebPattern = regexp.MustCompile(`^(\S+)\s+\[([^\]]+)\]\s*(.*)$`)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs a WhatWeb/dig utility adapter. Prefix Args with --dig to use
// dig; otherwise WhatWeb performs conservative technology discovery.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:         "kali-utils",
		Binary:       "whatweb",
		InstallHint:  "run `make dev`; packages whatweb and dnsutils are installed in the Kali Dev Container",
		Capabilities: []tools.Capability{"recon.dns", "web.technology-fingerprint"},
		Active:       always,
		RequiresKali: always,
		Build: func(request tools.Request) (tools.Command, error) {
			if hasMode(request.Args, "--dig") {
				args := append(stripMode(request.Args, "--dig"), request.Target)
				return tools.Command{Path: "dig", Args: args, Timeout: request.Timeout, OutputLimit: 4 << 20}, nil
			}
			args := append(stripMode(request.Args, "--whatweb"), request.Target)
			return tools.Command{Path: "whatweb", Args: args, Timeout: request.Timeout, OutputLimit: 4 << 20}, nil
		},
		Parse: func(execution tools.Execution, request tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			return ParseOutput(execution.Stdout, request.Target), nil, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseOutput normalizes WhatWeb lines or dig address answers.
func ParseOutput(data []byte, target string) []tools.Finding {
	var findings []tools.Finding
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if match := whatWebPattern.FindStringSubmatch(line); len(match) > 0 {
			findings = append(findings, tools.Finding{
				ID:       fmt.Sprintf("whatweb:%d", index+1),
				Title:    "Web technology fingerprint",
				Severity: "info",
				Target:   match[1],
				Evidence: strings.TrimSpace(match[3]),
				Metadata: map[string]string{"status": match[2]},
			})
			continue
		}
		if strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 && (fields[3] == "A" || fields[3] == "AAAA") {
			findings = append(findings, tools.Finding{
				ID:       fmt.Sprintf("dig:%s:%s", fields[0], fields[4]),
				Title:    fmt.Sprintf("DNS %s record", fields[3]),
				Severity: "info",
				Target:   target,
				Evidence: line,
				Metadata: map[string]string{"record_type": fields[3], "value": fields[4]},
			})
		}
	}
	return findings
}

func hasMode(args []string, mode string) bool {
	for _, arg := range args {
		if arg == mode {
			return true
		}
	}
	return false
}

func stripMode(args []string, mode string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != mode {
			out = append(out, arg)
		}
	}
	return out
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

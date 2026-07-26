// Package aircrack implements authorized wireless capture orchestration and
// offline analysis. It embeds no deauthentication or attack parameters.
package aircrack

import (
	"fmt"
	"regexp"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

var (
	keyPattern       = regexp.MustCompile(`(?i)KEY FOUND!\s*\[\s*([^\]]+)\s*\]`)
	handshakePattern = regexp.MustCompile(`(?i)(\d+)\s+handshake`)
)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs an Aircrack-ng adapter. Prefix Args with --live to select
// live capture; otherwise Target is an operator-owned capture file.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	live := func(request tools.Request) bool { return hasMode(request.Args, "--live") }
	config := tools.CommandAdapterConfig{
		Name:                "aircrack-ng",
		Binary:              "aircrack-ng",
		InstallHint:         "run `make dev`; package aircrack-ng is installed in the Kali Dev Container",
		Capabilities:        []tools.Capability{"wireless.handshake-detection", "wireless.offline-audit", "wireless.live-capture"},
		Active:              live,
		Intrusive:           live,
		RequiresAttestation: always,
		RequiresKali:        live,
		Preflight: func(request tools.Request) error {
			if live(request) && !tools.BinaryHasCapabilities("airodump-ng", "cap_net_raw", "cap_net_admin") {
				return fmt.Errorf("live wireless capture requires airodump-ng capabilities cap_net_raw and cap_net_admin; Sentinel never escalates automatically")
			}
			return nil
		},
		Build: func(request tools.Request) (tools.Command, error) {
			args := stripMode(request.Args, "--live")
			if live(request) {
				args = append(args, "--bssid", request.Target)
				return tools.Command{Path: "airodump-ng", Args: args, Timeout: request.Timeout, OutputLimit: 8 << 20}, nil
			}
			args = append(args, request.Target)
			return tools.Command{Path: "aircrack-ng", Args: args, Timeout: request.Timeout, OutputLimit: 8 << 20}, nil
		},
		Parse: func(execution tools.Execution, request tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			return ParseOutput(append(execution.Stdout, execution.Stderr...), request.Target), nil, nil
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseOutput reports handshakes and redacted key recovery.
func ParseOutput(data []byte, target string) []tools.Finding {
	text := string(data)
	var findings []tools.Finding
	if match := handshakePattern.FindStringSubmatch(text); len(match) > 0 {
		findings = append(findings, tools.Finding{
			ID:       "aircrack:handshake:" + target,
			Title:    "Wireless handshake detected",
			Severity: "info",
			Target:   target,
			Evidence: match[0],
			Metadata: map[string]string{"handshakes": match[1]},
		})
	}
	if match := keyPattern.FindStringSubmatch(text); len(match) > 0 {
		findings = append(findings, tools.Finding{
			ID:          "aircrack:key-recovered:" + target,
			Title:       "Authorized wireless key recovered",
			Description: "Recovered key material is redacted from Sentinel output.",
			Severity:    "high",
			Target:      target,
			Evidence:    "KEY FOUND! [ REDACTED ]",
			Metadata:    map[string]string{"status": "recovered"},
		})
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

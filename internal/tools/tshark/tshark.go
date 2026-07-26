// Package tshark implements passive pcap parsing and guarded live capture.
package tshark

import (
	"encoding/json"
	"fmt"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs a tshark adapter. Prefix Args with --live for interface
// capture; file parsing is passive and needs no network scope.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	live := func(request tools.Request) bool { return hasMode(request.Args, "--live") }
	config := tools.CommandAdapterConfig{
		Name:         "tshark",
		Binary:       "tshark",
		InstallHint:  "run `make dev`; packages tshark and wireshark-common are installed in the Kali Dev Container",
		Capabilities: []tools.Capability{"traffic.pcap-analysis", "traffic.live-capture"},
		Active:       live,
		RequiresKali: live,
		Preflight: func(request tools.Request) error {
			if live(request) && !tools.BinaryHasCapabilities("dumpcap", "cap_net_raw", "cap_net_admin") {
				return fmt.Errorf("live tshark capture requires dumpcap capabilities cap_net_raw and cap_net_admin; Sentinel never escalates automatically")
			}
			return nil
		},
		Build: func(request tools.Request) (tools.Command, error) {
			args := stripMode(request.Args, "--live")
			if live(request) {
				args = append([]string{"-i", request.Target, "-T", "json"}, args...)
			} else {
				args = append([]string{"-r", request.Target, "-T", "json"}, args...)
			}
			return tools.Command{Path: "tshark", Args: args, Timeout: request.Timeout, OutputLimit: 32 << 20}, nil
		},
		Parse: func(execution tools.Execution, _ tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			findings, err := ParseJSON(execution.Stdout)
			return findings, nil, err
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

type packet struct {
	Source struct {
		Layers map[string]any `json:"layers"`
	} `json:"_source"`
}

// ParseJSON summarizes endpoints/protocols and flags exposed credentials.
func ParseJSON(data []byte) ([]tools.Finding, error) {
	var packets []packet
	if err := json.Unmarshal(data, &packets); err != nil {
		return nil, fmt.Errorf("parsing tshark JSON: %w", err)
	}
	var findings []tools.Finding
	for index, packet := range packets {
		layers := packet.Source.Layers
		source := firstString(layers, "ip.src", "ipv6.src")
		destination := firstString(layers, "ip.dst", "ipv6.dst")
		protocol := firstString(layers, "_ws.col.Protocol", "frame.protocols")
		if source != "" || destination != "" {
			findings = append(findings, tools.Finding{
				ID:       fmt.Sprintf("tshark:packet:%d", index+1),
				Title:    fmt.Sprintf("%s traffic %s → %s", protocol, source, destination),
				Severity: "info",
				Target:   destination,
				Metadata: map[string]string{"source": source, "destination": destination, "protocol": protocol},
			})
		}
		if authorization := firstString(layers, "http.authorization", "ftp.request.arg", "smtp.auth.username"); authorization != "" {
			findings = append(findings, tools.Finding{
				ID:          fmt.Sprintf("tshark:credential-exposure:%d", index+1),
				Title:       "Potential credential material visible in capture",
				Description: "A cleartext or directly encoded authentication field was present in the supplied capture.",
				Severity:    "high",
				Target:      destination,
				Evidence:    "[REDACTED credential field]",
				Metadata:    map[string]string{"protocol": protocol},
			})
		}
	}
	return findings, nil
}

func firstString(layers map[string]any, keys ...string) string {
	for _, key := range keys {
		for layerName, rawLayer := range layers {
			layer, ok := rawLayer.(map[string]any)
			if !ok && layerName == key {
				if value, ok := rawLayer.(string); ok {
					return value
				}
			}
			if ok {
				if value, ok := layer[key].(string); ok {
					return value
				}
			}
		}
	}
	return ""
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

var _ tools.Tool = (*Adapter)(nil)

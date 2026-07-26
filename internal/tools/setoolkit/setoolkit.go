// Package setoolkit provides the highest-guardrail wrapper for sanctioned SET
// campaigns. Sentinel never generates campaign content.
package setoolkit

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

// Adapter implements tools.Tool through the shared command adapter.
type Adapter struct{ *tools.CommandAdapter }

// New constructs a SET adapter. Args are passed directly from the accountable
// operator; no templates, lures, or deceptive content are generated.
func New(guard authz.Guardrail, auditor tools.Auditor, executor tools.Executor, options ...tools.CommandAdapterOption) *Adapter {
	config := tools.CommandAdapterConfig{
		Name:                "set",
		Binary:              "setoolkit",
		InstallHint:         "run `make dev`; package set is installed in the Kali Dev Container",
		Capabilities:        []tools.Capability{"social-engineering.sanctioned-campaign"},
		Active:              always,
		Intrusive:           always,
		RequiresAttestation: always,
		RequiresKali:        always,
		Validate: func(request tools.Request) error {
			if len(request.Args) == 0 {
				return fmt.Errorf("SET requires operator-supplied campaign configuration; Sentinel generates no deceptive content")
			}
			return nil
		},
		Build: func(request tools.Request) (tools.Command, error) {
			return tools.Command{Path: "setoolkit", Args: append([]string(nil), request.Args...), Timeout: request.Timeout, OutputLimit: 8 << 20}, nil
		},
		Parse: func(execution tools.Execution, _ tools.Request) ([]tools.Finding, []tools.Artifact, error) {
			findings, err := ParseResults(execution.Stdout)
			return findings, nil, err
		},
	}
	return &Adapter{CommandAdapter: tools.NewCommandAdapter(config, guard, auditor, executor, options...)}
}

// ParseResults parses non-sensitive aggregate campaign CSV with columns
// metric,count. It does not ingest recipient identities or campaign content.
func ParseResults(data []byte) ([]tools.Finding, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	var findings []tools.Finding
	row := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing SET aggregate results: %w", err)
		}
		row++
		if len(record) != 2 || strings.EqualFold(record[0], "metric") {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			return nil, fmt.Errorf("SET result row %d has invalid count: %w", row, err)
		}
		metric := strings.TrimSpace(record[0])
		findings = append(findings, tools.Finding{
			ID:       "set:metric:" + strings.ToLower(strings.ReplaceAll(metric, " ", "-")),
			Title:    "Campaign metric: " + metric,
			Severity: "info",
			Evidence: fmt.Sprintf("%d aggregate event(s)", count),
			Metadata: map[string]string{"metric": metric, "count": strconv.Itoa(count)},
		})
	}
	return findings, nil
}

func always(tools.Request) bool { return true }

var _ tools.Tool = (*Adapter)(nil)

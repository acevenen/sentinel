// Package orchestrator defines the human-approved planning boundary between an
// LLM planner, the methodology engine, and guarded tool adapters.
package orchestrator

import (
	"context"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/methodology"
	"github.com/acevenen/sentinel/internal/tools"
)

// Proposal is one planner-suggested action. It is not executable until the
// guardrail and, where required, the operator approve it.
type Proposal struct {
	Stage  methodology.Stage `json:"stage"`
	Action authz.Action      `json:"action"`
	Tool   string            `json:"tool"`
	Args   []string          `json:"args,omitempty"`
}

// Plan is the planner's structured, auditable output.
type Plan struct {
	Summary   string          `json:"summary"`
	Proposals []Proposal      `json:"proposals"`
	Findings  []tools.Finding `json:"input_findings,omitempty"`
}

// Planner proposes actions but never executes them.
type Planner interface {
	Plan(context.Context, methodology.RunState) (Plan, error)
}

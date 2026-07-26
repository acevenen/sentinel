// Package methodology models Sentinel's security-testing workflow as explicit,
// resumable stages rather than unrelated tool invocations.
package methodology

import (
	"context"

	"github.com/acevenen/sentinel/internal/tools"
)

// Stage is one state in the methodology workflow.
type Stage string

const (
	StageRecon               Stage = "recon"
	StageApplicationMapping  Stage = "application-mapping"
	StageTacticalFuzzing     Stage = "tactical-fuzzing"
	StageAuthSessionLogic    Stage = "auth-session-logic-transport"
	StageCloudSSRF           Stage = "cloud-ssrf"
	StageExploitationAndPost Stage = "exploitation-post"
)

// RunState is portable engagement progress.
type RunState struct {
	EngagementID string          `json:"engagement_id"`
	Current      Stage           `json:"current_stage"`
	Completed    []Stage         `json:"completed_stages,omitempty"`
	Findings     []tools.Finding `json:"findings,omitempty"`
}

// Engine is the methodology execution contract.
type Engine interface {
	RunStage(context.Context, RunState, Stage) (RunState, error)
	ProposeNext(RunState) []Stage
}

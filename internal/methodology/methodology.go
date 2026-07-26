// Package methodology models Sentinel's security-testing workflow as explicit,
// resumable stages rather than unrelated tool invocations.
package methodology

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/acevenen/sentinel/internal/knowledge"
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

// Definition maps a stage to capabilities, preferred tools, and human role.
type Definition struct {
	Stage         Stage               `json:"stage"`
	Capabilities  []tools.Capability  `json:"capabilities"`
	Tools         []string            `json:"tools"`
	Knowledge     []knowledge.Purpose `json:"knowledge,omitempty"`
	Checklist     []string            `json:"checklist"`
	HumanDecision bool                `json:"human_decision"`
}

// DefaultDefinitions is the ordered methodology state machine.
var DefaultDefinitions = []Definition{
	{
		Stage:        StageRecon,
		Capabilities: []tools.Capability{"recon.host-discovery", "recon.port-scan", "recon.network-path", "recon.dns"},
		Tools:        []string{"nmap", "hping3", "kali-utils"},
		Checklist:    []string{"confirm scope", "discover authorized assets", "enumerate ports and services"},
	},
	{
		Stage:        StageApplicationMapping,
		Capabilities: []tools.Capability{"web.crawl", "web.surface-mapping", "web.technology-fingerprint"},
		Tools:        []string{"skipfish", "kali-utils"},
		Checklist:    []string{"map routes and parameters", "identify technologies", "record authentication boundaries"},
	},
	{
		Stage:         StageTacticalFuzzing,
		Capabilities:  []tools.Capability{"web.injection-validation"},
		Tools:         []string{"sqlmap"},
		Checklist:     []string{"map parameter names to hypotheses", "obtain operator approval", "validate one class at a time"},
		HumanDecision: true,
	},
	{
		Stage:         StageAuthSessionLogic,
		Checklist:     []string{"review authentication", "review session lifecycle", "test business logic", "review transport"},
		HumanDecision: true,
	},
	{
		Stage:         StageCloudSSRF,
		Knowledge:     []knowledge.Purpose{knowledge.PurposeSSRFMetadata},
		Checklist:     []string{"identify URL-fetching features", "select provider dictionary", "confirm safe evidence boundary"},
		HumanDecision: true,
	},
	{
		Stage:         StageExploitationAndPost,
		Capabilities:  []tools.Capability{"exploit.operator-selected-module"},
		Tools:         []string{"metasploit"},
		Checklist:     []string{"verify confirmed issue", "verify written authorization", "obtain per-action confirmation"},
		HumanDecision: true,
	},
}

// CloudMetadataOptions returns the factual provider dictionary used by the
// Cloud/SSRF stage. Sending any selected endpoint remains a human-approved,
// scope-gated adapter responsibility.
func CloudMetadataOptions() ([]knowledge.MetadataEndpoint, error) {
	return knowledge.MetadataEndpoints()
}

// RunState is portable engagement progress.
type RunState struct {
	EngagementID string          `json:"engagement_id"`
	Current      Stage           `json:"current_stage,omitempty"`
	Completed    []Stage         `json:"completed_stages,omitempty"`
	Findings     []tools.Finding `json:"findings,omitempty"`
	ProposedNext []Stage         `json:"proposed_next,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// StageRunner executes the tools selected for one already-authorized stage.
type StageRunner interface {
	Run(context.Context, Stage, RunState) ([]tools.Finding, error)
}

// StageRunnerFunc adapts a function to StageRunner.
type StageRunnerFunc func(context.Context, Stage, RunState) ([]tools.Finding, error)

// Run implements StageRunner.
func (f StageRunnerFunc) Run(ctx context.Context, stage Stage, state RunState) ([]tools.Finding, error) {
	return f(ctx, stage, state)
}

// Engine is the methodology execution contract.
type Engine interface {
	RunStage(context.Context, RunState, Stage) (RunState, error)
	ProposeNext(RunState) []Stage
}

// Workflow is the default explicit state machine.
type Workflow struct {
	Runner StageRunner
}

// RunStage enforces order, delegates execution, and proposes the next stage.
func (w Workflow) RunStage(ctx context.Context, state RunState, stage Stage) (RunState, error) {
	if state.EngagementID == "" {
		return state, errors.New("methodology run requires an engagement id")
	}
	expected := expectedStage(state)
	if expected == "" {
		return state, errors.New("methodology workflow is already complete")
	}
	if stage != expected {
		return state, fmt.Errorf("cannot run %s; expected %s", stage, expected)
	}
	if w.Runner == nil {
		return state, errors.New("methodology stage runner is required")
	}
	findings, err := w.Runner.Run(ctx, stage, state)
	if err != nil {
		return state, fmt.Errorf("running methodology stage %s: %w", stage, err)
	}
	state.Current = stage
	state.Completed = append(state.Completed, stage)
	state.Findings = append(state.Findings, findings...)
	state.UpdatedAt = time.Now().UTC()
	state.ProposedNext = w.ProposeNext(state)
	return state, nil
}

// ProposeNext returns the only valid next stage, or none after completion.
func (Workflow) ProposeNext(state RunState) []Stage {
	if next := expectedStage(state); next != "" {
		return []Stage{next}
	}
	return nil
}

// DefinitionFor returns a copy of one stage definition.
func DefinitionFor(stage Stage) (Definition, bool) {
	for _, definition := range DefaultDefinitions {
		if definition.Stage == stage {
			return definition, true
		}
	}
	return Definition{}, false
}

func expectedStage(state RunState) Stage {
	if len(state.Completed) >= len(DefaultDefinitions) {
		return ""
	}
	for index, completed := range state.Completed {
		if completed != DefaultDefinitions[index].Stage {
			return DefaultDefinitions[index].Stage
		}
	}
	return DefaultDefinitions[len(state.Completed)].Stage
}

// TestingSuggestion is a HUNT-style prioritization hint, not a finding.
type TestingSuggestion struct {
	Parameter string                       `json:"parameter"`
	Class     knowledge.VulnerabilityClass `json:"vulnerability_class"`
	Tool      string                       `json:"tool"`
	Manual    bool                         `json:"manual_decision"`
}

// SuggestParameters maps discovered names to likely classes and the narrowest
// appropriate validation tool.
func SuggestParameters(parameters []string) []TestingSuggestion {
	var suggestions []TestingSuggestion
	for _, parameter := range parameters {
		hypothesis := knowledge.LookupParameter(parameter)
		for _, class := range hypothesis.Classes {
			suggestion := TestingSuggestion{Parameter: parameter, Class: class, Manual: true, Tool: "manual-assist"}
			switch class {
			case knowledge.ClassSQLI:
				suggestion.Tool = "sqlmap"
			case knowledge.ClassSSRF:
				suggestion.Tool = "ssrf-metadata-catalog"
			case knowledge.ClassLFI, knowledge.ClassRFI, knowledge.ClassXSS, knowledge.ClassUpload:
				suggestion.Tool = "knowledge-catalog"
			}
			suggestions = append(suggestions, suggestion)
		}
	}
	return suggestions
}

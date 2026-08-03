// Package confidence defines REVerso's evidence model. Every conclusion keeps
// what was directly observed separate from what is inferred and from what is
// merely speculated, and carries the evidence, confidence and a safe next test
// needed to reproduce or challenge it.
package confidence

import (
	"errors"
	"fmt"
	"strings"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
)

// Level is the calibrated confidence of a finding.
type Level string

// Confidence levels.
const (
	Low    Level = "low"
	Medium Level = "medium"
	High   Level = "high"
)

// ValidLevel reports whether l is a recognized confidence level.
func ValidLevel(l Level) bool {
	switch l {
	case Low, Medium, High:
		return true
	default:
		return false
	}
}

// Finding is one documented conclusion. Observation holds directly evidenced
// facts; Inference holds explanations supported by that evidence; Speculation
// holds plausible but unevidenced ideas kept explicitly separate. Alternatives
// records competing explanations and NextSafeTest a passive or simulated way to
// validate the finding without escalating risk.
type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Classification string   `json:"classification"`
	Observation    []string `json:"observation"`
	Inference      []string `json:"inference"`
	Speculation    []string `json:"speculation,omitempty"`
	Confidence     Level    `json:"confidence"`
	EvidenceIDs    []string `json:"evidence_ids"`
	Alternatives   []string `json:"alternatives,omitempty"`
	NextSafeTest   []string `json:"next_safe_test"`
	// ProhibitedNextSteps documents what REVerso will not do next, echoing the
	// mission's refusal posture directly in the finding.
	ProhibitedNextSteps []string `json:"prohibited_next_steps,omitempty"`
}

// Validation errors.
var (
	ErrNoID          = errors.New("finding is missing an id")
	ErrNoObservation = errors.New("finding must cite at least one observation")
	ErrNoEvidence    = errors.New("finding must cite at least one evidence id")
	ErrBadConfidence = errors.New("finding has an invalid confidence level")
	ErrInferNoObs    = errors.New("finding draws an inference with no observation to support it")
)

// Validate enforces the confidence model. In particular an inference is never
// allowed without a supporting observation: that is the core evidence/inference
// distinction the tests pin.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" {
		return ErrNoID
	}
	if len(nonEmpty(f.Observation)) == 0 {
		return ErrNoObservation
	}
	if len(nonEmpty(f.EvidenceIDs)) == 0 {
		return ErrNoEvidence
	}
	if !ValidLevel(f.Confidence) {
		return fmt.Errorf("%w: %q", ErrBadConfidence, f.Confidence)
	}
	if len(nonEmpty(f.Inference)) > 0 && len(nonEmpty(f.Observation)) == 0 {
		return ErrInferNoObs
	}
	return nil
}

// ToRecord converts a validated finding to its storage form for a project.
func (f Finding) ToRecord(projectID string) evidence.FindingRecord {
	return evidence.FindingRecord{
		ID:             f.ID,
		ProjectID:      projectID,
		Title:          f.Title,
		Classification: f.Classification,
		Confidence:     string(f.Confidence),
		Observation:    f.Observation,
		Inference:      f.Inference,
		Alternatives:   f.Alternatives,
		EvidenceIDs:    f.EvidenceIDs,
		NextSafeTest:   f.NextSafeTest,
	}
}

// FromRecord reconstructs a Finding from storage.
func FromRecord(r evidence.FindingRecord) Finding {
	return Finding{
		ID:             r.ID,
		Title:          r.Title,
		Classification: r.Classification,
		Observation:    r.Observation,
		Inference:      r.Inference,
		Confidence:     Level(r.Confidence),
		EvidenceIDs:    r.EvidenceIDs,
		Alternatives:   r.Alternatives,
		NextSafeTest:   r.NextSafeTest,
	}
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

package confidence

import (
	"errors"
	"testing"
)

func TestValidateAcceptsWellFormedFinding(t *testing.T) {
	f := Finding{
		ID: "REV-TRUST-004", Title: "trust boundary", Classification: "trust-boundary",
		Observation:  []string{"a certificate chain is presented"},
		Inference:    []string{"the service likely requires an authorized identity"},
		Confidence:   Medium,
		EvidenceIDs:  []string{"pcap_sha256:abc"},
		NextSafeTest: []string{"compare sanitized lab sessions in the simulator"},
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// The evidence/inference distinction: an inference with no observation is
// rejected. This is the property that keeps speculation from masquerading as
// fact.
func TestValidateRejectsInferenceWithoutObservation(t *testing.T) {
	f := Finding{
		ID:          "x",
		Inference:   []string{"the device trusts anyone"},
		Confidence:  High,
		EvidenceIDs: []string{"e1"},
	}
	err := f.Validate()
	// With no observation at all, ErrNoObservation fires first, which still
	// enforces the distinction.
	if !errors.Is(err, ErrNoObservation) {
		t.Fatalf("Validate error = %v, want ErrNoObservation", err)
	}
}

func TestValidateRequiresEvidence(t *testing.T) {
	f := Finding{ID: "x", Observation: []string{"o"}, Confidence: Low}
	if err := f.Validate(); !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Validate error = %v, want ErrNoEvidence", err)
	}
}

func TestValidateRejectsBadConfidence(t *testing.T) {
	f := Finding{ID: "x", Observation: []string{"o"}, EvidenceIDs: []string{"e"}, Confidence: "certain"}
	if err := f.Validate(); !errors.Is(err, ErrBadConfidence) {
		t.Fatalf("Validate error = %v, want ErrBadConfidence", err)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	f := Finding{
		ID: "id", Observation: []string{"o"}, Inference: []string{"i"},
		Confidence: Medium, EvidenceIDs: []string{"e"}, NextSafeTest: []string{"n"},
	}
	back := FromRecord(f.ToRecord("proj"))
	if back.ID != f.ID || back.Confidence != f.Confidence ||
		len(back.Observation) != 1 || len(back.Inference) != 1 {
		t.Fatalf("round trip lost data: %+v", back)
	}
}

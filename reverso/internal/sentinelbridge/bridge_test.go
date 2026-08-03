package sentinelbridge

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

func simulatorPolicy(t *testing.T) scope.Policy {
	t.Helper()
	kp, _ := scope.GenerateKeypair()
	m := &scope.Manifest{Authorization: scope.Authorization{
		ProjectID: "sim", Owner: "o@example.test",
		Target:    scope.Target{AssetID: "sim-01", AssetType: scope.AssetSimulator, OwnershipEvidence: "model"},
		Permitted: []scope.Capability{scope.CapSimulation, scope.CapSimulatorMessageEmit},
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	_ = m.Sign(kp.Private)
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	return scope.New(m)
}

func newAudit(t *testing.T) (*evidence.AuditLog, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "audit.log")
	return evidence.NewAuditLog(path, priv), pub, path
}

// With no confirmer, a state-changing action is denied (fail closed) and the
// denial is audited.
func TestBridgeFailsClosedWithoutConfirmer(t *testing.T) {
	audit, pub, path := newAudit(t)
	b := New(simulatorPolicy(t), nil, audit, "op")
	v, err := b.Submit(context.Background(), ProposedAction{
		Capability: scope.CapSimulatorMessageEmit, AssetType: scope.AssetSimulator,
		Target: "sim-01", StateChanging: true, LabOnly: true, Description: "emit frame",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Approved {
		t.Fatal("state-changing action approved with no confirmer")
	}
	if err := evidence.OpenAuditLog(path).Verify(pub); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
	events, _ := evidence.OpenAuditLog(path).Events("")
	if len(events) != 1 || events[0].Decision != "denied" {
		t.Fatalf("expected one denied event, got %+v", events)
	}
}

// A confirmed, fully-guarded emit is approved and audited as allowed.
func TestBridgeApprovesConfirmedGuardedAction(t *testing.T) {
	audit, pub, path := newAudit(t)
	confirm := func(context.Context, ProposedAction, RiskLevel) (bool, string, string, error) {
		return true, "reviewer@example.test", "reviewed in lab", nil
	}
	b := New(simulatorPolicy(t), confirm, audit, "op")
	v, err := b.Submit(context.Background(), ProposedAction{
		Capability: scope.CapSimulatorMessageEmit, AssetType: scope.AssetSimulator,
		Target: "sim-01", StateChanging: true, LabOnly: true, Description: "emit frame",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !v.Approved || v.Risk != RiskCritical {
		t.Fatalf("verdict = %+v, want approved critical", v)
	}
	events, _ := evidence.OpenAuditLog(path).Events("")
	if len(events) != 1 || events[0].Decision != "allowed" {
		t.Fatalf("expected one allowed event, got %+v", events)
	}
	if err := evidence.OpenAuditLog(path).Verify(pub); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// Even a confirmed emit is denied when a hard policy guard is missing (here,
// lab-only is false), proving the confirmer cannot override policy.
func TestBridgeConfirmerCannotOverridePolicy(t *testing.T) {
	audit, _, _ := newAudit(t)
	confirm := func(context.Context, ProposedAction, RiskLevel) (bool, string, string, error) {
		return true, "reviewer", "ok", nil
	}
	b := New(simulatorPolicy(t), confirm, audit, "op")
	v, err := b.Submit(context.Background(), ProposedAction{
		Capability: scope.CapSimulatorMessageEmit, AssetType: scope.AssetSimulator,
		Target: "sim-01", StateChanging: true, LabOnly: false, // guard missing
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Approved {
		t.Fatal("confirmer approval bypassed a missing lab-only guard")
	}
}

// A permanently prohibited proposal is denied outright regardless of confirmer.
func TestBridgeDeniesPermanentlyProhibited(t *testing.T) {
	audit, _, _ := newAudit(t)
	confirm := func(context.Context, ProposedAction, RiskLevel) (bool, string, string, error) {
		return true, "reviewer", "ok", nil
	}
	b := New(simulatorPolicy(t), confirm, audit, "op")
	v, err := b.Submit(context.Background(), ProposedAction{
		Capability: scope.ActiveVehicleBusTransmission, AssetType: scope.AssetSimulator,
		Target: "sim-01", StateChanging: true, LabOnly: true,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Approved {
		t.Fatal("permanently prohibited action was approved")
	}
}

// Regression: a guarded capability must not take the read-only shortcut even
// when StateChanging is left at its false zero value. Without a confirmer it
// must be denied, and the confirmer must actually be consulted when present.
func TestBridgeGuardedActionNeedsConfirmationEvenIfNotStateChanging(t *testing.T) {
	audit, pub, path := newAudit(t)
	// No confirmer: a guarded emit with StateChanging=false must be denied.
	b := New(simulatorPolicy(t), nil, audit, "op")
	v, err := b.Submit(context.Background(), ProposedAction{
		Capability: scope.CapSimulatorMessageEmit, AssetType: scope.AssetSimulator,
		Target: "sim-01", LabOnly: true, StateChanging: false, // zero value
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Approved {
		t.Fatal("guarded emit auto-approved as read-only without confirmation")
	}

	// With a confirmer: it must be consulted, then approved.
	called := false
	confirm := func(context.Context, ProposedAction, RiskLevel) (bool, string, string, error) {
		called = true
		return true, "reviewer", "ok", nil
	}
	b2 := New(simulatorPolicy(t), confirm, audit, "op")
	v2, err := b2.Submit(context.Background(), ProposedAction{
		Capability: scope.CapSimulatorMessageEmit, AssetType: scope.AssetSimulator,
		Target: "sim-01", LabOnly: true, StateChanging: false,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !called {
		t.Fatal("confirmer was not consulted for a guarded action")
	}
	if !v2.Approved || v2.Reviewer == "policy" {
		t.Fatalf("expected human-reviewed approval, got %+v", v2)
	}
	if err := evidence.OpenAuditLog(path).Verify(pub); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

func TestBridgeRequiresAudit(t *testing.T) {
	b := New(simulatorPolicy(t), nil, nil, "op")
	if _, err := b.Submit(context.Background(), ProposedAction{Capability: scope.CapSimulation, Target: "x"}); err == nil {
		t.Fatal("Submit without an audit log should error")
	}
}

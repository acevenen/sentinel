// Package sentinelbridge submits proposed state-changing actions to a policy
// engine (Sentinel) for authorization, risk classification, out-of-band review
// and human confirmation. Every approval and denial is written to the immutable
// audit trail. The bridge fails closed: with no confirmer, nothing state-
// changing is ever approved.
package sentinelbridge

import (
	"context"
	"errors"
	"fmt"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// RiskLevel classifies the blast radius of a proposed action.
type RiskLevel string

// Risk levels.
const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ProposedAction is a request to do something, submitted before it runs.
type ProposedAction struct {
	Capability    scope.Capability
	AssetType     scope.AssetType
	Target        string
	Description   string
	StateChanging bool
	LabOnly       bool
	Risk          RiskLevel // optional; classified if empty
}

// Verdict is the reviewed outcome.
type Verdict struct {
	Approved bool      `json:"approved"`
	Reason   string    `json:"reason"`
	Reviewer string    `json:"reviewer"`
	Risk     RiskLevel `json:"risk"`
}

// Confirmer performs the out-of-band human review step. It returns whether the
// action is confirmed, the reviewer identity, and an optional reason. It is the
// injection point for a real review UI or Sentinel engagement approval.
type Confirmer func(ctx context.Context, action ProposedAction, risk RiskLevel) (confirmed bool, reviewer string, reason string, err error)

// DenyAll is the default confirmer: it approves nothing, so a bridge with no
// explicit human-in-the-loop cannot authorize state-changing work.
func DenyAll(context.Context, ProposedAction, RiskLevel) (bool, string, string, error) {
	return false, "", "no confirmer configured; failing closed", nil
}

// Bridge couples the scope policy, a confirmer and the audit log.
type Bridge struct {
	Policy  scope.Policy
	Confirm Confirmer
	Audit   *evidence.AuditLog
	Actor   string
}

// ErrNoAudit means the bridge was constructed without an audit log; the audit
// trail is mandatory for state-changing review.
var ErrNoAudit = errors.New("sentinel bridge requires an audit log")

// New builds a bridge. A nil confirm defaults to DenyAll.
func New(policy scope.Policy, confirm Confirmer, audit *evidence.AuditLog, actor string) *Bridge {
	if confirm == nil {
		confirm = DenyAll
	}
	return &Bridge{Policy: policy, Confirm: confirm, Audit: audit, Actor: actor}
}

// classify derives a risk level when the caller did not set one.
func classify(a ProposedAction) RiskLevel {
	if a.Risk != "" {
		return a.Risk
	}
	if scope.IsGuarded(a.Capability) {
		return RiskCritical
	}
	if a.StateChanging {
		return RiskHigh
	}
	return RiskLow
}

// Submit runs the full review pipeline and returns a verdict. It never performs
// the action itself; a nil error with Approved=true means the caller may
// proceed under the recorded approval.
func (b *Bridge) Submit(ctx context.Context, a ProposedAction) (Verdict, error) {
	if b.Audit == nil {
		return Verdict{}, ErrNoAudit
	}
	risk := classify(a)
	projectID := ""
	if b.Policy.Manifest != nil {
		projectID = b.Policy.Manifest.Authorization.ProjectID
	}

	record := func(v Verdict) error {
		decision := "denied"
		if v.Approved {
			decision = "allowed"
		}
		return b.Audit.Record(ctx, evidence.Event{
			ProjectID: projectID, Actor: b.Actor, Capability: string(a.Capability),
			Target: a.Target, Decision: decision, Reason: v.Reason,
			Detail: fmt.Sprintf("risk=%s reviewer=%s %s", v.Risk, v.Reviewer, a.Description),
		})
	}

	// Step 1: policy authorization. The action carries Approved=false here so a
	// state-changing action cannot pass policy on this pre-review check; that is
	// intentional — approval is granted only after confirmation, below.
	dec, err := b.Policy.Authorize(ctx, scope.Action{
		Capability: a.Capability, AssetType: a.AssetType, Target: a.Target,
		StateChanging: a.StateChanging, LabOnly: a.LabOnly, Approved: false,
	})
	// A state-changing or guarded action is expected to fail policy for want of
	// approval; that specific refusal is not a hard denial, it is the cue to
	// seek confirmation. Any other refusal is final.
	if err != nil && !errors.Is(err, scope.ErrApprovalRequired) {
		v := Verdict{Approved: false, Reason: dec.Reason, Risk: risk}
		if aerr := record(v); aerr != nil {
			return Verdict{}, aerr
		}
		return v, nil
	}
	if !a.StateChanging && !scope.IsGuarded(a.Capability) {
		// A non-state-changing, non-guarded action that passed policy needs no
		// confirmation. Guarded capabilities are excluded even when the caller
		// left StateChanging at its false zero value: the policy requires
		// approval for a guarded capability regardless of StateChanging (see
		// scope.Policy.Authorize), so the read-only shortcut must never apply to
		// one, or the only bus-like emission path would lose its approval guard.
		v := Verdict{Approved: true, Reason: "authorized (read-only)", Risk: risk, Reviewer: "policy"}
		if aerr := record(v); aerr != nil {
			return Verdict{}, aerr
		}
		return v, nil
	}

	// Step 2: out-of-band human confirmation.
	confirmed, reviewer, reason, cerr := b.Confirm(ctx, a, risk)
	if cerr != nil {
		return Verdict{}, fmt.Errorf("confirmation failed: %w", cerr)
	}
	if !confirmed {
		if reason == "" {
			reason = "human confirmation withheld"
		}
		v := Verdict{Approved: false, Reason: reason, Reviewer: reviewer, Risk: risk}
		if aerr := record(v); aerr != nil {
			return Verdict{}, aerr
		}
		return v, nil
	}

	// Step 3: re-authorize with approval now granted, so the final decision goes
	// through the same policy gate rather than trusting the confirmer alone.
	finalDec, ferr := b.Policy.Authorize(ctx, scope.Action{
		Capability: a.Capability, AssetType: a.AssetType, Target: a.Target,
		StateChanging: a.StateChanging, LabOnly: a.LabOnly, Approved: true,
	})
	if ferr != nil {
		v := Verdict{Approved: false, Reason: finalDec.Reason, Reviewer: reviewer, Risk: risk}
		if aerr := record(v); aerr != nil {
			return Verdict{}, aerr
		}
		return v, nil
	}
	v := Verdict{Approved: true, Reason: "authorized and confirmed", Reviewer: reviewer, Risk: risk}
	if aerr := record(v); aerr != nil {
		return Verdict{}, aerr
	}
	return v, nil
}

package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Action is a single proposed operation, presented to the policy engine before
// any work runs. It is intentionally small: a capability, the asset it targets,
// and the two extra facts guarded and state-changing work require.
type Action struct {
	Capability Capability
	// AssetType is the type of asset this action would operate on. It must match
	// the manifest target's asset type.
	AssetType AssetType
	// Target is a human-facing identifier (asset_id or artifact id) recorded in
	// the audit trail and used to detect out-of-scope targets.
	Target string
	// StateChanging is true for any action that emits, writes to, or otherwise
	// mutates a target or the simulator. State-changing actions require Approved.
	StateChanging bool
	// Approved records that a human explicitly confirmed this specific action.
	Approved bool
	// LabOnly asserts the action runs under a lab-only profile. Guarded
	// capabilities require it.
	LabOnly bool
}

// Decision is the machine-readable outcome of an authorization check, suitable
// for the audit trail whether the action was allowed or refused.
type Decision struct {
	Allowed    bool       `json:"allowed"`
	Capability Capability `json:"capability"`
	Target     string     `json:"target"`
	Reason     string     `json:"reason"`
	ProjectID  string     `json:"project_id,omitempty"`
}

// Authorization decision errors. Each maps to a stable, auditable reason.
var (
	ErrNoAuthorization       = errors.New("no authorization manifest is loaded")
	ErrScopeExpired          = errors.New("authorization manifest has expired")
	ErrUnverified            = errors.New("authorization manifest signature is not verified")
	ErrPermanentlyProhibited = errors.New("capability is permanently prohibited and can never be authorized")
	ErrProhibitedByManifest  = errors.New("capability is prohibited by this manifest")
	ErrNotPermitted          = errors.New("capability is not in the manifest's permitted set")
	ErrUnknownAction         = errors.New("capability is not a recognized permitted capability")
	ErrAssetTypeMismatch     = errors.New("action asset type does not match the manifest target")
	ErrApprovalRequired      = errors.New("state-changing action requires explicit human approval")
	ErrLabOnlyRequired       = errors.New("guarded capability requires a lab-only profile")
	ErrSimulatorRequired     = errors.New("guarded capability requires the simulator asset type")
	ErrEmptyTarget           = errors.New("action is missing a target")
)

// Policy is the default authorization engine. A zero Policy with a nil manifest
// denies everything except the permanent-prohibition check, which needs no
// manifest to refuse. Construct one with New for sane defaults.
type Policy struct {
	// Manifest is the resolved authorization. Nil means no authorization.
	Manifest *Manifest
	// RequireSignature makes an unverified manifest a denial. It defaults to
	// true via New; leaving it false is only for tests and explicit dev use.
	RequireSignature bool
	// Now supplies the current time for expiry checks. Nil uses time.Now.
	Now func() time.Time
}

// New builds a fail-closed policy around a manifest with signature enforcement
// on. The manifest should already be validated; New does not validate it.
func New(m *Manifest) Policy {
	return Policy{Manifest: m, RequireSignature: true}
}

func (p Policy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Authorize returns nil only when the action is fully permitted. It fails
// closed at every step: the order of checks is deliberate so the most absolute
// refusals (permanent prohibition) are reported before contingent ones
// (expiry, scope), giving the operator the truest reason.
func (p Policy) Authorize(ctx context.Context, action Action) (Decision, error) {
	dec := Decision{Capability: action.Capability, Target: action.Target}
	if p.Manifest != nil {
		dec.ProjectID = p.Manifest.Authorization.ProjectID
	}
	deny := func(err error) (Decision, error) {
		dec.Allowed = false
		dec.Reason = err.Error()
		return dec, err
	}

	if err := ctx.Err(); err != nil {
		return deny(err)
	}
	if strings.TrimSpace(string(action.Capability)) == "" {
		return deny(ErrUnknownAction)
	}

	// 1. Permanent prohibition is absolute: no manifest, approval, or asset type
	// can ever enable it. Checked first so the refusal reason is unambiguous.
	if IsPermanentlyProhibited(action.Capability) {
		return deny(fmt.Errorf("%w: %s", ErrPermanentlyProhibited, action.Capability))
	}

	// 2. The capability must be one REVerso knows how to grant. Fail closed on
	// anything unrecognized rather than treating it as harmlessly permitted.
	if !IsKnownPermitted(action.Capability) {
		return deny(fmt.Errorf("%w: %s", ErrUnknownAction, action.Capability))
	}

	// 3. Authorization must exist.
	if p.Manifest == nil {
		return deny(ErrNoAuthorization)
	}

	// 4. Signature enforcement, if enabled.
	if p.RequireSignature && !p.Manifest.Verified {
		return deny(ErrUnverified)
	}

	// 5. Expiry. An unparseable expiry counts as expired (see Manifest.Expired).
	if p.Manifest.Expired(p.now()) {
		return deny(ErrScopeExpired)
	}

	// 6. Manifest-level prohibition wins over any grant.
	if p.Manifest.Prohibits(action.Capability) {
		return deny(fmt.Errorf("%w: %s", ErrProhibitedByManifest, action.Capability))
	}

	// 7. The capability must be explicitly granted.
	if !p.Manifest.Permits(action.Capability) {
		return deny(fmt.Errorf("%w: %s", ErrNotPermitted, action.Capability))
	}

	// 8. The action must target the asset type the manifest authorizes. An
	// empty action asset type inherits the manifest's, so passive analysis need
	// not restate it; a mismatch is a refusal.
	if action.AssetType != "" && action.AssetType != p.Manifest.Authorization.Target.AssetType {
		return deny(fmt.Errorf("%w: action %q vs manifest %q",
			ErrAssetTypeMismatch, action.AssetType, p.Manifest.Authorization.Target.AssetType))
	}

	// 9. Guarded capabilities carry extra, non-waivable requirements.
	if IsGuarded(action.Capability) {
		if p.Manifest.Authorization.Target.AssetType != AssetSimulator {
			return deny(ErrSimulatorRequired)
		}
		if !action.LabOnly {
			return deny(ErrLabOnlyRequired)
		}
		if !action.Approved {
			return deny(ErrApprovalRequired)
		}
	}

	// 10. Any state-changing action requires explicit human approval.
	if action.StateChanging && !action.Approved {
		return deny(ErrApprovalRequired)
	}

	dec.Allowed = true
	dec.Reason = "authorized"
	return dec, nil
}

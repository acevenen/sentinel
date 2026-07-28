package spotter

import (
	"context"
	"fmt"
	"strings"

	"github.com/acevenen/sentinel/internal/authz"
)

// ScopeGuard applies the engagement scope to EVERY Spotter action, including
// passive ones.
//
// This exists because authz.Policy.Authorize evaluates Scope.Decide only
// inside its `if action.Active` branch — correct for the rest of Sentinel,
// where a passive action's target is a local capture file that no network
// scope could ever match. Spotter is different: its passive targets are real
// hosts and hardware addresses on a real network, so a device the operator
// explicitly deny-listed would otherwise still be assessable. Verified against
// the current implementation: a passive action targeting a deny-listed address
// returns nil from Policy.Authorize.
//
// ScopeGuard is composed with the Policy through authz.Chain, so it adds a
// check and can never relax one.
type ScopeGuard struct {
	Scope authz.Scope
}

// Authorize implements authz.Guardrail.
func (g ScopeGuard) Authorize(_ context.Context, action authz.Action) error {
	target := strings.TrimSpace(action.Target)
	if target == "" {
		return fmt.Errorf("spotter: %w", authz.ErrOutOfScope)
	}
	if g.Scope.Empty() {
		// Fail closed: no allow-list means nothing is in scope, for passive
		// work as much as active.
		return fmt.Errorf("spotter requires an explicit device scope: %w", authz.ErrScopeRequired)
	}

	// Hardware addresses reach here in whatever form the operator typed them.
	// Normalize so a MAC from a device sticker matches the same MAC from the
	// router UI; otherwise the scope check silently fails and the practical
	// response is to widen the allow-list.
	decision := g.Scope.Decide(target)
	if !decision.Allowed {
		if normalized := NormalizeMAC(target); normalized != target {
			decision = g.Scope.Decide(normalized)
		}
	}
	if !decision.Allowed {
		if decision.Rule != "" {
			return fmt.Errorf("%w: %s matched %q", authz.ErrDenied, target, decision.Rule)
		}
		return fmt.Errorf("%w: %s is not one of your enrolled devices", authz.ErrOutOfScope, target)
	}
	return nil
}

// Refusals names what Spotter will not do at any authorization level. These
// are capability decisions, not policy toggles: the code to do them is absent,
// which is the only guarantee that survives an operator who controls the
// machine.
//
//   - No exploitation. Spotter reports that a weakness is known; it never
//     attempts one.
//   - No credential testing. It flags that defaults may be unchanged; it never
//     tries a password.
//   - No person identification. The corpus contains device families only.
//   - No covert or unattended operation. There is no daemon, watch, or
//     scheduled mode, and none will be added.
//   - No imagery or audio retention. Observations enter as structured values;
//     frames and speech are never written to disk or sent anywhere.
func Refusals() []string {
	return []string{
		"exploitation of any identified weakness",
		"credential testing, including default-password checks",
		"identification of people, faces, or biometrics",
		"unattended, scheduled, or background operation",
		"retention or transmission of imagery, audio, or transcripts",
	}
}

// NewGuardrail composes the Spotter scope check with the platform policy.
// Order matters only for which error surfaces first; both must pass.
func NewGuardrail(policy authz.Policy) authz.Guardrail {
	return authz.Chain{ScopeGuard{Scope: policy.Scope}, policy}
}

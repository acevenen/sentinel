package spotter

import (
	"context"
	"errors"
	"testing"

	"github.com/acevenen/sentinel/internal/authz"
)

func spotterAction(target string) authz.Action {
	return authz.Action{
		Tool: "spotter", Target: target, Operator: "alice",
		EngagementID: "home", RequiresAttestation: true,
	}
}

func homePolicy() authz.Policy {
	return authz.Policy{
		Scope:                 authz.NewScope([]string{"192.168.1.0/24"}, []string{"192.168.1.99"}),
		AuthorizationAsserted: true,
		Engagement: authz.EngagementAuthorization{
			ID: "home", Reference: "owner-attested", Operator: "alice", Attested: true,
		},
	}
}

// The gap this guard exists to close: authz.Policy skips Scope.Decide for
// passive actions, so without ScopeGuard a deny-listed or out-of-scope device
// is still assessable.
func TestScopeGuardEnforcesScopeOnPassiveActions(t *testing.T) {
	policy := homePolicy()

	// Baseline: the platform policy alone authorizes these passive actions.
	for _, target := range []string{"192.168.1.99", "10.9.9.9"} {
		if err := policy.Authorize(context.Background(), spotterAction(target)); err != nil {
			t.Fatalf("precondition changed: policy now rejects passive %s (%v)", target, err)
		}
	}

	guard := NewGuardrail(policy)
	t.Run("deny-listed device refused", func(t *testing.T) {
		err := guard.Authorize(context.Background(), spotterAction("192.168.1.99"))
		if !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("error = %v, want ErrDenied", err)
		}
	})
	t.Run("out-of-scope device refused", func(t *testing.T) {
		err := guard.Authorize(context.Background(), spotterAction("10.9.9.9"))
		if !errors.Is(err, authz.ErrOutOfScope) {
			t.Fatalf("error = %v, want ErrOutOfScope", err)
		}
	})
	t.Run("in-scope device allowed", func(t *testing.T) {
		if err := guard.Authorize(context.Background(), spotterAction("192.168.1.50")); err != nil {
			t.Fatalf("in-scope device refused: %v", err)
		}
	})
}

func TestScopeGuardFailsClosedWithoutScope(t *testing.T) {
	guard := NewGuardrail(authz.Policy{AuthorizationAsserted: true})
	err := guard.Authorize(context.Background(), spotterAction("192.168.1.50"))
	if !errors.Is(err, authz.ErrScopeRequired) {
		t.Fatalf("error = %v, want ErrScopeRequired", err)
	}
}

func TestScopeGuardRejectsEmptyTarget(t *testing.T) {
	guard := NewGuardrail(homePolicy())
	if err := guard.Authorize(context.Background(), spotterAction("   ")); err == nil {
		t.Fatal("empty target was authorized")
	}
}

// A MAC written the way it appears on a device sticker must match the same MAC
// enrolled from a router UI, or the scope check silently fails.
func TestScopeGuardNormalizesMACSeparatorForms(t *testing.T) {
	policy := authz.Policy{
		Scope:                 authz.NewScope([]string{"aa:bb:cc:dd:ee:ff"}, nil),
		AuthorizationAsserted: true,
		Engagement: authz.EngagementAuthorization{
			ID: "home", Reference: "owner-attested", Operator: "alice", Attested: true,
		},
	}
	guard := NewGuardrail(policy)
	for _, form := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF",
		"aabb.ccdd.eeff",
	} {
		if err := guard.Authorize(context.Background(), spotterAction(form)); err != nil {
			t.Errorf("enrolled MAC in form %q was refused: %v", form, err)
		}
	}
	if err := guard.Authorize(context.Background(), spotterAction("11-22-33-44-55-66")); err == nil {
		t.Fatal("an unenrolled MAC was authorized")
	}
}

func TestScopeGuardStillHonorsPolicyRefusals(t *testing.T) {
	// The guard adds a check; it must never relax one. An active action with
	// the kill switch set stays refused.
	policy := homePolicy()
	policy.KillSwitch = true
	guard := NewGuardrail(policy)

	action := spotterAction("192.168.1.50")
	action.Active = true
	if err := guard.Authorize(context.Background(), action); !errors.Is(err, authz.ErrKillSwitch) {
		t.Fatalf("error = %v, want ErrKillSwitch", err)
	}
}

func TestRefusalsAreDeclared(t *testing.T) {
	r := Refusals()
	if len(r) == 0 {
		t.Fatal("Spotter must declare what it refuses to do")
	}
	for _, want := range []string{"exploitation", "credential", "people"} {
		var found bool
		for _, got := range r {
			if len(got) > 0 && contains(got, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("refusal list does not mention %q: %v", want, r)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

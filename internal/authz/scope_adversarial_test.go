package authz

import (
	"context"
	"errors"
	"testing"
)

// The scope matcher is the boundary that keeps active tooling inside authorized
// targets. authz_test.go covers the mainline; these tests pin the adversarial
// edges where a scope bypass would let an operator act on an unauthorized host
// or path — the exact behaviors a future refactor could silently loosen.

func TestScopeMatcherResistsBypasses(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		deny    []string
		target  string
		allowed bool
	}{
		// Wildcard must not reach the apex or lookalike neighbors.
		{"wildcard excludes apex", []string{"*.example.com"}, nil, "example.com", false},
		{"wildcard excludes prefix lookalike", []string{"*.example.com"}, nil, "notexample.com", false},
		{"wildcard excludes hyphen lookalike", []string{"*.example.com"}, nil, "evil-example.com", false},
		{"wildcard excludes suffix attack", []string{"*.example.com"}, nil, "example.com.evil.com", false},
		{"wildcard matches subdomain", []string{"*.example.com"}, nil, "api.example.com", true},
		{"wildcard matches deep subdomain", []string{"*.example.com"}, nil, "a.b.example.com", true},

		// Exact host must not match a domain that merely contains it.
		{"exact excludes suffix attack", []string{"example.com"}, nil, "example.com.evil.com", false},
		{"exact excludes prefix concat", []string{"example.com"}, nil, "xexample.com", false},
		{"exact matches self", []string{"example.com"}, nil, "example.com", true},

		// Trailing-dot FQDNs normalize to the same host.
		{"trailing dot fqdn normalizes", []string{"example.com"}, nil, "example.com.", true},

		// Leading-dot rule covers apex and subdomains.
		{"leading dot covers apex", []string{".example.com"}, nil, "example.com", true},
		{"leading dot covers subdomain", []string{".example.com"}, nil, "api.example.com", true},
		{"leading dot excludes lookalike", []string{".example.com"}, nil, "notexample.com", false},

		// URL scheme is strict: an http grant does not authorize https.
		{"scheme http does not grant https", []string{"http://lab.local"}, nil, "https://lab.local/x", false},
		{"scheme https does not grant http", []string{"https://lab.local"}, nil, "http://lab.local/x", false},
		{"scheme match is honored", []string{"https://lab.local"}, nil, "https://lab.local/x", true},

		// URL path is a boundary-aware prefix: /app must not authorize /apple.
		{"path prefix exact", []string{"http://lab.local/app"}, nil, "http://lab.local/app", true},
		{"path prefix child", []string{"http://lab.local/app"}, nil, "http://lab.local/app/admin", true},
		{"path prefix rejects sibling", []string{"http://lab.local/app"}, nil, "http://lab.local/apple", false},
		{"path prefix rejects concat", []string{"http://lab.local/app"}, nil, "http://lab.local/app-secret", false},

		// Ports are not part of host identity.
		{"host allow ignores port", []string{"lab.local"}, nil, "lab.local:8443", true},
		{"ip allow ignores port", []string{"192.0.2.10"}, nil, "192.0.2.10:8080", true},

		// CIDR membership.
		{"cidr contains member", []string{"10.0.0.0/8"}, nil, "10.1.2.3", true},
		{"cidr excludes non-member", []string{"10.0.0.0/8"}, nil, "11.0.0.1", false},

		// A non-IP host is never accidentally matched by an IP or CIDR rule.
		{"ip rule excludes hostname", []string{"192.0.2.10"}, nil, "example.com", false},
		{"cidr rule excludes hostname", []string{"10.0.0.0/8"}, nil, "example.com", false},

		// Deny always wins, across differing rule kinds.
		{"exact deny beats wildcard allow", []string{"*.example.com"}, []string{"secret.example.com"}, "secret.example.com", false},
		{"exact deny beats cidr allow", []string{"10.0.0.0/8"}, []string{"10.0.0.9"}, "10.0.0.9", false},
		{"cidr deny beats wildcard allow", []string{"*.corp"}, []string{"10.0.0.0/8"}, "10.0.0.5", false},

		// engagement: rules match the bare identifier and nothing else.
		{"engagement rule matches id", []string{"engagement:lab"}, nil, "lab", true},
		{"engagement rule rejects other", []string{"engagement:lab"}, nil, "other", false},

		// Empty / whitespace targets fail closed.
		{"empty target denied", []string{"*.example.com"}, nil, "", false},
		{"whitespace target denied", []string{"*.example.com"}, nil, "   ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewScope(tt.allow, tt.deny).Decide(tt.target).Allowed
			if got != tt.allowed {
				t.Fatalf("Decide(%q) allowed = %v, want %v", tt.target, got, tt.allowed)
			}
		})
	}
}

// TestAuthorizeDeniedTargetReturnsErrDenied pins the deny path through the full
// policy: a target inside the allow-list but also matched by a deny rule must
// surface as ErrDenied, not the weaker ErrOutOfScope.
func TestAuthorizeDeniedTargetReturnsErrDenied(t *testing.T) {
	policy := Policy{
		Scope:                 NewScope([]string{"*.example.com"}, []string{"admin.example.com"}),
		AuthorizationAsserted: true,
	}
	err := policy.Authorize(context.Background(), Action{
		Tool: "nmap", Target: "admin.example.com", Active: true,
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Authorize(denied target) error = %v, want ErrDenied", err)
	}
}

// TestKillSwitchBeatsFullyAuthorizedAction verifies the kill switch is checked
// before scope: even a correctly-scoped, asserted, active action is refused.
func TestKillSwitchBeatsFullyAuthorizedAction(t *testing.T) {
	policy := Policy{
		Scope:                 NewScope([]string{"127.0.0.1"}, nil),
		AuthorizationAsserted: true,
		KillSwitch:            true,
	}
	err := policy.Authorize(context.Background(), Action{
		Tool: "nmap", Target: "127.0.0.1", Active: true,
	})
	if !errors.Is(err, ErrKillSwitch) {
		t.Fatalf("Authorize() with kill switch = %v, want ErrKillSwitch", err)
	}
}

func TestAuthorizeFailsClosedOnMissingFields(t *testing.T) {
	policy := Policy{Scope: NewScope([]string{"127.0.0.1"}, nil), AuthorizationAsserted: true}
	t.Run("missing tool", func(t *testing.T) {
		if err := policy.Authorize(context.Background(), Action{Target: "127.0.0.1"}); err == nil {
			t.Fatal("Authorize() accepted an action with no tool")
		}
	})
	t.Run("missing target", func(t *testing.T) {
		if err := policy.Authorize(context.Background(), Action{Tool: "nmap"}); err == nil {
			t.Fatal("Authorize() accepted an action with no target")
		}
	})
}

func TestAuthorizeHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policy := Policy{Scope: NewScope([]string{"127.0.0.1"}, nil), AuthorizationAsserted: true}
	err := policy.Authorize(ctx, Action{Tool: "nmap", Target: "127.0.0.1", Active: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authorize(canceled ctx) error = %v, want context.Canceled", err)
	}
}

// denyGuard is a Guardrail that always refuses, used to prove Chain requires
// every member to authorize.
type denyGuard struct{ err error }

func (d denyGuard) Authorize(context.Context, Action) error { return d.err }

func TestChainRequiresEveryGuardrail(t *testing.T) {
	pass := Policy{Scope: NewScope([]string{"127.0.0.1"}, nil), AuthorizationAsserted: true}
	action := Action{Tool: "nmap", Target: "127.0.0.1", Active: true}

	t.Run("empty chain fails closed", func(t *testing.T) {
		if err := (Chain{}).Authorize(context.Background(), action); err == nil {
			t.Fatal("empty Chain authorized an action")
		}
	})
	t.Run("nil member fails closed", func(t *testing.T) {
		if err := (Chain{pass, nil}).Authorize(context.Background(), action); err == nil {
			t.Fatal("Chain with a nil guardrail authorized an action")
		}
	})
	t.Run("any refusal propagates", func(t *testing.T) {
		sentinel := errors.New("second gate says no")
		err := Chain{pass, denyGuard{err: sentinel}}.Authorize(context.Background(), action)
		if !errors.Is(err, sentinel) {
			t.Fatalf("Chain error = %v, want the refusing guardrail's error", err)
		}
	})
	t.Run("all passing authorizes", func(t *testing.T) {
		if err := (Chain{pass, pass}).Authorize(context.Background(), action); err != nil {
			t.Fatalf("Chain of passing guardrails error = %v", err)
		}
	})
}

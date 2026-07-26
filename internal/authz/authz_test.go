package authz

import (
	"context"
	"errors"
	"testing"
)

func TestScopeDenyAlwaysWins(t *testing.T) {
	scope := NewScope([]string{"*.example.com", "10.0.0.0/8"}, []string{"admin.example.com", "10.0.0.9"})
	tests := []struct {
		target  string
		allowed bool
	}{
		{"api.example.com", true},
		{"https://api.example.com/v1", true},
		{"admin.example.com", false},
		{"10.1.2.3", true},
		{"10.0.0.9", false},
		{"example.net", false},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if got := scope.Decide(tt.target).Allowed; got != tt.allowed {
				t.Fatalf("Decide(%q).Allowed = %v, want %v", tt.target, got, tt.allowed)
			}
		})
	}
}

func TestPolicyRefusesActiveWithoutAuthorization(t *testing.T) {
	policy := Policy{Scope: NewScope([]string{"127.0.0.1"}, nil)}
	err := policy.Authorize(context.Background(), Action{Tool: "nmap", Target: "127.0.0.1", Active: true})
	if !errors.Is(err, ErrAuthorizationRequired) {
		t.Fatalf("Authorize() error = %v, want ErrAuthorizationRequired", err)
	}
}

func TestPolicyRefusesActiveWithoutScope(t *testing.T) {
	policy := Policy{AuthorizationAsserted: true}
	err := policy.Authorize(context.Background(), Action{Tool: "nmap", Target: "127.0.0.1", Active: true})
	if !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("Authorize() error = %v, want ErrScopeRequired", err)
	}
}

func TestPolicyRefusesOutOfScope(t *testing.T) {
	policy := Policy{
		Scope:                 NewScope([]string{"127.0.0.1"}, nil),
		AuthorizationAsserted: true,
	}
	err := policy.Authorize(context.Background(), Action{Tool: "nmap", Target: "192.0.2.1", Active: true})
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("Authorize() error = %v, want ErrOutOfScope", err)
	}
}

func TestPolicyRequiresIntrusiveEngagement(t *testing.T) {
	action := Action{
		Tool:         "metasploit",
		Target:       "127.0.0.1",
		Active:       true,
		Intrusive:    true,
		Operator:     "alice",
		EngagementID: "lab-1",
	}
	policy := Policy{
		Scope:                 NewScope([]string{"127.0.0.1"}, nil),
		AuthorizationAsserted: true,
		Engagement: EngagementAuthorization{
			ID:       "lab-1",
			Operator: "alice",
		},
	}
	if err := policy.Authorize(context.Background(), action); !errors.Is(err, ErrAttestationRequired) {
		t.Fatalf("Authorize() error = %v, want ErrAttestationRequired", err)
	}
	policy.Engagement.Reference = "signed-roe-42"
	policy.Engagement.Attested = true
	if err := policy.Authorize(context.Background(), action); err != nil {
		t.Fatalf("Authorize() with complete engagement error = %v", err)
	}
}

func TestPassiveActionNeedsNoNetworkScope(t *testing.T) {
	policy := Policy{}
	action := Action{Tool: "tshark", Target: "capture.pcap"}
	if err := policy.Authorize(context.Background(), action); err != nil {
		t.Fatalf("Authorize(passive) error = %v", err)
	}
}

package verify

import (
	"testing"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

var matchIntent = intent.Intent{
	ActionType:     "summarize",
	Target:         "README",
	Scope:          []string{"docs/**", "README.md"},
	ExpectedEffect: "post a summary to slack",
	AllowedNetwork: []string{"hooks.slack.com"},
}

func TestStaticMatchNetwork(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		wantOK bool
	}{
		{"allowed host via network list", Action{Type: "network", Target: "post", Network: []string{"hooks.slack.com"}}, true},
		{"allowed host via url target", Action{Type: "network", Target: "https://hooks.slack.com/services/x"}, true},
		{"allowed subdomain", Action{Type: "network", Target: "https://api.hooks.slack.com/x"}, true},
		{"disallowed host", Action{Type: "network", Target: "https://evil.example/collect", Network: []string{"evil.example"}}, false},
		{"one bad among allowed", Action{Type: "network", Target: "post", Network: []string{"hooks.slack.com", "evil.example"}}, false},
		{"no host declared", Action{Type: "network", Target: "do something"}, false},
		{"push to disallowed remote", Action{Type: "push", Target: "https://github.com/attacker/repo.git"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StaticMatch(matchIntent, tt.action)
			if got.OK != tt.wantOK {
				t.Errorf("StaticMatch OK=%v, want %v (reason: %s)", got.OK, tt.wantOK, got.Reason)
			}
		})
	}
}

func TestStaticMatchWrite(t *testing.T) {
	tests := []struct {
		name   string
		target string
		wantOK bool
	}{
		{"in scope file", "README.md", true},
		{"in scope glob", "docs/guide.md", true},
		{"nested in scope glob", "docs/sub/deep.md", true},
		{"dot-slash prefix", "./docs/x.md", true},
		{"out of scope", "internal/secret.go", false},
		{"traversal outside scope", "../etc/passwd", false},
		{"empty target", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StaticMatch(matchIntent, Action{Type: "write", Target: tt.target})
			if got.OK != tt.wantOK {
				t.Errorf("write %q OK=%v, want %v (reason: %s)", tt.target, got.OK, tt.wantOK, got.Reason)
			}
		})
	}
}

func TestStaticMatchWriteNoScope(t *testing.T) {
	noScope := matchIntent
	noScope.Scope = nil
	got := StaticMatch(noScope, Action{Type: "write", Target: "README.md"})
	if got.OK {
		t.Error("write should be blocked when intent grants no scope")
	}
}

func TestStaticMatchExec(t *testing.T) {
	tests := []struct {
		name   string
		target string
		wantOK bool
	}{
		{"benign local command", "go test ./...", true},
		{"reads secret path", "cat .env", false},
		{"contacts disallowed host", "curl https://evil.example/x", false},
		{"contacts allowed host", "curl https://hooks.slack.com/services/x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StaticMatch(matchIntent, Action{Type: "exec", Target: tt.target})
			if got.OK != tt.wantOK {
				t.Errorf("exec %q OK=%v, want %v (reason: %s)", tt.target, got.OK, tt.wantOK, got.Reason)
			}
		})
	}
}

func TestStaticMatchReadIsDeferred(t *testing.T) {
	// Reads have no deterministic intent contract at Layer 2; they flow to the
	// drift accumulator instead. Layer 2 must not block them.
	got := StaticMatch(matchIntent, Action{Type: "read", Target: ".env"})
	if !got.OK {
		t.Errorf("Layer 2 should defer reads to drift, got block: %s", got.Reason)
	}
}

func TestIsRisky(t *testing.T) {
	tests := []struct {
		action Action
		want   bool
	}{
		{Action{Type: "write", Target: "docs/x.md"}, true},
		{Action{Type: "exec", Target: "ls"}, true},
		{Action{Type: "network", Target: "x"}, true},
		{Action{Type: "push", Target: "x"}, true},
		{Action{Type: "read", Target: "README.md"}, false},
		{Action{Type: "read", Target: ".env"}, true},
		{Action{Type: "noop", Target: "x"}, false},
	}
	for _, tt := range tests {
		if got := tt.action.IsRisky(); got != tt.want {
			t.Errorf("IsRisky(%+v) = %v, want %v", tt.action, got, tt.want)
		}
	}
}

package intent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		intent  Intent
		wantErr bool
	}{
		{"complete", Intent{ActionType: "summarize", Target: "README", ExpectedEffect: "post"}, false},
		{"missing action type", Intent{Target: "README", ExpectedEffect: "post"}, true},
		{"missing target", Intent{ActionType: "summarize", ExpectedEffect: "post"}, true},
		{"missing effect", Intent{ActionType: "summarize", Target: "README"}, true},
		{"whitespace only", Intent{ActionType: "  ", Target: "README", ExpectedEffect: "post"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.intent.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAllowsHost(t *testing.T) {
	in := Intent{AllowedNetwork: []string{"hooks.slack.com", "api.github.com"}}
	tests := []struct {
		host string
		want bool
	}{
		{"hooks.slack.com", true},
		{"HOOKS.SLACK.COM", true},
		{"api.hooks.slack.com", true}, // subdomain
		{"api.github.com", true},
		{"evil.example", false},
		{"slack.com", false}, // parent is not a match
		{"", false},
	}
	for _, tt := range tests {
		if got := in.AllowsHost(tt.host); got != tt.want {
			t.Errorf("AllowsHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestAllowsHostEmptyNetwork(t *testing.T) {
	in := Intent{}
	if in.AllowsHost("anything.com") {
		t.Error("empty AllowedNetwork must allow no host")
	}
}

func TestAllowsHostWildcard(t *testing.T) {
	// A "*" entry means unbounded egress and must allow any host — consistent
	// with how the permission-risk scorer reads it.
	star := Intent{AllowedNetwork: []string{"*"}}
	for _, h := range []string{"evil.example", "hooks.slack.com", "169.254.169.254"} {
		if !star.AllowsHost(h) {
			t.Errorf("AllowedNetwork [*] should allow %q", h)
		}
	}

	// A "*.domain" entry allows the domain and its subdomains only.
	sub := Intent{AllowedNetwork: []string{"*.example.com"}}
	if !sub.AllowsHost("api.example.com") || !sub.AllowsHost("example.com") {
		t.Error("*.example.com should allow example.com and subdomains")
	}
	if sub.AllowsHost("evil.com") {
		t.Error("*.example.com must not allow an unrelated host")
	}
}

func TestDeclareRejectsInvalid(t *testing.T) {
	if _, err := Declare(Intent{ActionType: "x"}); err == nil {
		t.Error("Declare should reject an incomplete intent")
	}
	if _, err := Declare(Intent{ActionType: "x", Target: "y", ExpectedEffect: "z"}); err != nil {
		t.Errorf("Declare rejected a valid intent: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intent.json")
	body := `{"action_type":"summarize","target":"README","scope":["docs/**"],"expected_effect":"post summary","allowed_network":["hooks.slack.com"]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActionType != "summarize" || len(got.Scope) != 1 || len(got.AllowedNetwork) != 1 {
		t.Errorf("loaded intent mismatch: %+v", got)
	}
}

func TestLoadRejectsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"target":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load should reject an intent missing required fields")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("Load should error on a missing file")
	}
}

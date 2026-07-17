package evaluate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name    string
		m       AgentManifest
		wantErr bool
	}{
		{"complete", AgentManifest{Name: "a", Purpose: []string{"do x"}}, false},
		{"missing name", AgentManifest{Purpose: []string{"do x"}}, true},
		{"missing purpose", AgentManifest{Name: "a"}, true},
		{"blank name", AgentManifest{Name: "  ", Purpose: []string{"x"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.m.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestManifestToIntent(t *testing.T) {
	m := AgentManifest{
		Name:           "docs-agent",
		Purpose:        []string{"summarize", "post to slack"},
		Scope:          []string{"docs/**"},
		AllowedNetwork: []string{"hooks.slack.com"},
	}
	in := m.ToIntent()
	if in.Target != "docs-agent" {
		t.Errorf("Target = %q", in.Target)
	}
	if in.ExpectedEffect != "summarize; post to slack" {
		t.Errorf("ExpectedEffect = %q", in.ExpectedEffect)
	}
	if len(in.Scope) != 1 || in.Scope[0] != "docs/**" {
		t.Errorf("Scope = %v", in.Scope)
	}
	if !in.AllowsHost("hooks.slack.com") || in.AllowsHost("evil.example") {
		t.Errorf("AllowedNetwork not projected correctly")
	}
}

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "name: a\npurpose:\n  - do x\nscope:\n  - docs/**\nallowed_network:\n  - hooks.slack.com\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "a" || len(m.Purpose) != 1 || len(m.Scope) != 1 {
		t.Errorf("loaded manifest mismatch: %+v", m)
	}
}

func TestLoadManifestRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("purpose:\n  - x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Error("LoadManifest should reject a manifest with no name")
	}
}

func TestLoadSampleManifest(t *testing.T) {
	// The shipped sample manifest must stay valid.
	m, err := LoadManifest(filepath.Join("..", "..", "testdata", "evaluate", "agent.yaml"))
	if err != nil {
		t.Fatalf("sample agent.yaml is invalid: %v", err)
	}
	if m.Name == "" {
		t.Error("sample manifest has no name")
	}
}

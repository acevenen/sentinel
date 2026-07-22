package hunt

import (
	"os"
	"path/filepath"
	"testing"
)

func validProgram() Program {
	return Program{
		Name:    "p",
		BaseURL: "https://api.example.com",
		InScope: []string{"api.example.com"},
		Identities: []Identity{
			{Name: "alice", Header: "Authorization", TokenEnv: "HUNT_ALICE"},
			{Name: "bob", Header: "Authorization", TokenEnv: "HUNT_BOB"},
		},
		Requests: []RequestTemplate{
			{ID: "get-order", Method: "GET", Path: "/v1/orders/{id}", Owned: map[string][]string{"alice": {"1"}, "bob": {"2"}}},
		},
	}
}

func TestProgramValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Program)
		wantErr bool
	}{
		{"valid", func(*Program) {}, false},
		{"no name", func(p *Program) { p.Name = "" }, true},
		{"no base url", func(p *Program) { p.BaseURL = "" }, true},
		{"bad base url", func(p *Program) { p.BaseURL = "not a url" }, true},
		{"no in scope", func(p *Program) { p.InScope = nil }, true},
		{"one identity", func(p *Program) { p.Identities = p.Identities[:1] }, true},
		{"duplicate identity", func(p *Program) { p.Identities[1].Name = "alice" }, true},
		{"identity missing token env", func(p *Program) { p.Identities[0].TokenEnv = "" }, true},
		{"no requests", func(p *Program) { p.Requests = nil }, true},
		{"path missing placeholder", func(p *Program) { p.Requests[0].Path = "/v1/orders/1" }, true},
		{"write method refused", func(p *Program) { p.Requests[0].Method = "DELETE" }, true},
		{"head allowed", func(p *Program) { p.Requests[0].Method = "HEAD" }, false},
		{"unknown owned identity", func(p *Program) { p.Requests[0].Owned = map[string][]string{"carol": {"9"}} }, true},
		{"no owned", func(p *Program) { p.Requests[0].Owned = nil }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validProgram()
			tt.mutate(&p)
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStatusDefault(t *testing.T) {
	if (RequestTemplate{}).Status() != 200 {
		t.Error("default success status should be 200")
	}
	if (RequestTemplate{SuccessStatus: 201}).Status() != 201 {
		t.Error("explicit success status not honored")
	}
}

func TestFindingSeverity(t *testing.T) {
	if (RequestTemplate{}).FindingSeverity() != SeverityHigh {
		t.Error("default finding severity should be high")
	}
	if (RequestTemplate{Severity: "critical"}).FindingSeverity() != SeverityCritical {
		t.Error("critical severity not honored")
	}
	if (RequestTemplate{Severity: "CRITICAL"}).FindingSeverity() != SeverityCritical {
		t.Error("severity match should be case-insensitive")
	}
}

func TestValidateRejectsBadSeverity(t *testing.T) {
	p := Program{
		Name: "p", BaseURL: "https://api.example.com", InScope: []string{"api.example.com"},
		Identities: []Identity{
			{Name: "a", Header: "Authorization", TokenEnv: "A"},
			{Name: "b", Header: "Authorization", TokenEnv: "B"},
		},
		Requests: []RequestTemplate{
			{ID: "r", Method: "GET", Path: "/x/{id}", Severity: "medium", Owned: map[string][]string{"a": {"1"}}},
		},
	}
	if err := p.Validate(); err == nil {
		t.Error("severity other than high/critical should be rejected")
	}
}

func TestLoadSampleProgram(t *testing.T) {
	p, err := LoadProgram(filepath.Join("..", "..", "testdata", "hunt", "program.yaml"))
	if err != nil {
		t.Fatalf("sample program.yaml is invalid: %v", err)
	}
	if p.Name == "" || len(p.Requests) == 0 {
		t.Error("sample program did not load")
	}
}

func TestLoadProgramMissingFile(t *testing.T) {
	if _, err := LoadProgram(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("LoadProgram should error on a missing file")
	}
}

func TestLoadProgramRejectsWriteMethod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	body := "name: p\nbase_url: https://api.example.com\nin_scope: [api.example.com]\n" +
		"identities:\n  - {name: a, header: Authorization, token_env: A}\n  - {name: b, header: Authorization, token_env: B}\n" +
		"requests:\n  - {id: r, method: DELETE, path: /x/{id}, owned: {a: [\"1\"], b: [\"2\"]}}\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProgram(path); err == nil {
		t.Error("a write-method request must be rejected at load")
	}
}

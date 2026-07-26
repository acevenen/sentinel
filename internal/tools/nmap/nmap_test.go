package nmap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

type fakeExecutor struct {
	result tools.Execution
	err    error
	calls  int
}

func (f *fakeExecutor) Execute(_ context.Context, _ tools.Command) (tools.Execution, error) {
	f.calls++
	return f.result, f.err
}

type memoryAuditor struct {
	events []tools.AuditEvent
	err    error
}

func (m *memoryAuditor) Record(_ context.Context, event tools.AuditEvent) error {
	m.events = append(m.events, event)
	return m.err
}

func authorizedPolicy() authz.Policy {
	return authz.Policy{
		Scope:                 authz.NewScope([]string{"192.0.2.10"}, nil),
		AuthorizationAsserted: true,
	}
}

func TestDryRunReturnsExactCommandWithoutExecuting(t *testing.T) {
	executor := &fakeExecutor{}
	auditor := &memoryAuditor{}
	adapter := New(authorizedPolicy(), auditor, executor)
	result, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
		Args:   []string{"-sV"},
		DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nmap", "-oX", "-", "-sV", "192.0.2.10"}
	if !reflect.DeepEqual(result.Command, want) {
		t.Fatalf("Command = %#v, want %#v", result.Command, want)
	}
	if executor.calls != 0 {
		t.Fatalf("executor called %d times during dry-run", executor.calls)
	}
	if len(auditor.events) != 1 || auditor.events[0].Result != "dry-run" {
		t.Fatalf("audit events = %#v", auditor.events)
	}
}

func TestRunRefusesOutOfScopeBeforeExecution(t *testing.T) {
	executor := &fakeExecutor{}
	auditor := &memoryAuditor{}
	adapter := New(authorizedPolicy(), auditor, executor)
	_, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "198.51.100.5",
		DryRun: true,
	})
	if !errors.Is(err, authz.ErrOutOfScope) {
		t.Fatalf("Run() error = %v, want ErrOutOfScope", err)
	}
	if executor.calls != 0 {
		t.Fatalf("executor called %d times after refusal", executor.calls)
	}
	if len(auditor.events) != 1 || auditor.events[0].ScopeDecision != "refused" {
		t.Fatalf("audit events = %#v", auditor.events)
	}
}

func TestRunParsesGoldenOutput(t *testing.T) {
	data, err := os.ReadFile(fixturePath("scan.xml"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{result: tools.Execution{Stdout: data}}
	auditor := &memoryAuditor{}
	adapter := New(
		authorizedPolicy(),
		auditor,
		executor,
		WithLookPath(func(string) (string, error) { return "/usr/bin/nmap", nil }),
		WithRawCapabilityCheck(func() bool { return true }),
		WithRuntimeCheck(func() error { return nil }),
	)
	result, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
		Args:   []string{"-sV"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := loadExpected(t)
	if !reflect.DeepEqual(result.Findings, want) {
		t.Fatalf("Findings = %#v, want %#v", result.Findings, want)
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.calls)
	}
}

func TestRunFailsClosedWhenStartCannotBeAudited(t *testing.T) {
	executor := &fakeExecutor{}
	auditor := &memoryAuditor{err: errors.New("disk unavailable")}
	adapter := New(
		authorizedPolicy(),
		auditor,
		executor,
		WithLookPath(func(string) (string, error) { return "/usr/bin/nmap", nil }),
		WithRuntimeCheck(func() error { return nil }),
	)
	_, err := adapter.Run(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
	})
	if err == nil || !stringsContain(err.Error(), "auditing nmap start") {
		t.Fatalf("Run() error = %v, want audit failure", err)
	}
	if executor.calls != 0 {
		t.Fatalf("executor called %d times after audit failure", executor.calls)
	}
}

func TestPreflightReportsMissingBinary(t *testing.T) {
	adapter := New(
		authorizedPolicy(),
		&memoryAuditor{},
		&fakeExecutor{},
		WithLookPath(func(string) (string, error) { return "", errors.New("missing") }),
		WithRuntimeCheck(func() error { return nil }),
	)
	err := adapter.Preflight(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
	})
	if err == nil || !stringsContain(err.Error(), "make dev") {
		t.Fatalf("Preflight() error = %v, want install hint", err)
	}
}

func TestPreflightRefusesUnprivilegedSYNScan(t *testing.T) {
	adapter := New(
		authorizedPolicy(),
		&memoryAuditor{},
		&fakeExecutor{},
		WithLookPath(func(string) (string, error) { return "/usr/bin/nmap", nil }),
		WithRawCapabilityCheck(func() bool { return false }),
		WithRuntimeCheck(func() error { return nil }),
	)
	err := adapter.Preflight(context.Background(), tools.Request{
		Action: authz.Action{Operator: "alice"},
		Target: "192.0.2.10",
		Args:   []string{"-sS"},
	})
	if !errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("Preflight() error = %v, want ErrPrivilegeRequired", err)
	}
}

func TestParseXMLGoldenFile(t *testing.T) {
	data, err := os.ReadFile(fixturePath("scan.xml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseXML(data)
	if err != nil {
		t.Fatal(err)
	}
	want := loadExpected(t)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseXML() = %#v, want %#v", got, want)
	}
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "tools", "nmap", name)
}

func loadExpected(t *testing.T) []tools.Finding {
	t.Helper()
	data, err := os.ReadFile(fixturePath("expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []tools.Finding
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	return expected
}

func stringsContain(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}

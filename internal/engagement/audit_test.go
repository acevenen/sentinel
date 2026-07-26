package engagement

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/acevenen/sentinel/internal/tools"
)

func TestAuditLogHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := &AuditLog{Path: path}
	for _, result := range []string{"authorized", "completed"} {
		if err := log.Record(context.Background(), tools.AuditEvent{
			Operator:      "alice",
			Target:        "127.0.0.1",
			Tool:          "nmap",
			ScopeDecision: "allowed",
			Result:        result,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestAuditLogDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := &AuditLog{Path: path}
	if err := log.Record(context.Background(), tools.AuditEvent{
		Operator:      "alice",
		Target:        "127.0.0.1",
		Tool:          "nmap",
		ScopeDecision: "allowed",
		Result:        "completed",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if data[i] == 'a' {
			data[i] = 'b'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("Verify() succeeded after audit log tampering")
	}
}

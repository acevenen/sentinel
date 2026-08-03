package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newAuditKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestAuditChainVerifies(t *testing.T) {
	pub, priv := newAuditKey(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewAuditLog(path, priv)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := log.Record(ctx, Event{Actor: "op", Capability: "firmware_metadata_analysis",
			Target: "ecu-01", Decision: "allowed", Reason: "authorized"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := OpenAuditLog(path).Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	events, err := OpenAuditLog(path).Events("")
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}
}

// Editing any byte of a record must break verification.
func TestAuditDetectsTampering(t *testing.T) {
	pub, priv := newAuditKey(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewAuditLog(path, priv)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := log.Record(ctx, Event{Actor: "op", Capability: "x", Target: "t", Decision: "denied", Reason: "no scope"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), "no scope", "authorized", 1)
	if tampered == string(raw) {
		t.Fatal("test setup: nothing was replaced")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := OpenAuditLog(path).Verify(pub); err == nil {
		t.Fatal("Verify accepted a tampered audit log")
	}
}

// Deleting a record (truncating the chain) must break verification, because the
// following record's previous-hash no longer matches.
func TestAuditDetectsDeletedMiddleRecord(t *testing.T) {
	pub, priv := newAuditKey(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewAuditLog(path, priv)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := log.Record(ctx, Event{Actor: "op", Capability: "x", Target: "t", Decision: "allowed"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Drop the middle record.
	spliced := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(spliced), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := OpenAuditLog(path).Verify(pub); err == nil {
		t.Fatal("Verify accepted a chain with a deleted record")
	}
}

// A record signed by the wrong key must be rejected.
func TestAuditRejectsWrongKey(t *testing.T) {
	_, priv := newAuditKey(t)
	otherPub, _ := newAuditKey(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewAuditLog(path, priv)
	if err := log.Record(context.Background(), Event{Actor: "op", Capability: "x", Target: "t", Decision: "allowed"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := OpenAuditLog(path).Verify(otherPub); err == nil {
		t.Fatal("Verify accepted a log under the wrong public key")
	}
}

func TestAuditRecordRequiresSigner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := OpenAuditLog(path).Record(context.Background(), Event{Capability: "x", Target: "t"}); err == nil {
		t.Fatal("Record without a signing key should fail")
	}
}

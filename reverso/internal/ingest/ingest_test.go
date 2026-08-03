package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

type harness struct {
	ing   *Ingestor
	store *evidence.Store
	pub   ed25519.PublicKey
	audit string
}

func newHarness(t *testing.T, permit ...scope.Capability) harness {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs := evidence.NewBlobStore(filepath.Join(dir, "blobs"))
	auditPath := filepath.Join(dir, "audit.log")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	audit := evidence.NewAuditLog(auditPath, priv)

	kp, _ := scope.GenerateKeypair()
	m := &scope.Manifest{Authorization: scope.Authorization{
		ProjectID: "p", Owner: "o@example.test",
		Target:    scope.Target{AssetID: "fw", AssetType: scope.AssetFirmwareImage, OwnershipEvidence: "receipt"},
		Permitted: permit,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest Validate: %v", err)
	}
	if err := m.Sign(kp.Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.VerifySignature(nil); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	return harness{
		ing: &Ingestor{
			Policy: scope.New(m), Store: store, Blobs: blobs, Audit: audit, Actor: "tester",
		},
		store: store, pub: pub, audit: auditPath,
	}
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestIngestHashesAndStores(t *testing.T) {
	h := newHarness(t, scope.CapArtifactIngestion)
	data := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("...body...")...)
	path := writeTemp(t, "sample.bin", data)

	rec, err := h.ing.Ingest(context.Background(), path)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	sum := sha256.Sum256(data)
	if rec.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 mismatch: got %s", rec.SHA256)
	}
	if rec.DetectedType != string(ClassELF) {
		t.Fatalf("detected type = %s, want %s", rec.DetectedType, ClassELF)
	}
	// The original file must be untouched.
	orig, _ := os.ReadFile(path)
	if string(orig) != string(data) {
		t.Fatal("original artifact was modified during ingest")
	}
	// The audit trail must verify and contain the ingestion.
	if err := evidence.OpenAuditLog(h.audit).Verify(h.pub); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
	events, _ := evidence.OpenAuditLog(h.audit).Events("")
	if len(events) != 1 || events[0].Decision != "allowed" {
		t.Fatalf("expected one allowed audit event, got %+v", events)
	}
}

// Ingestion without the artifact_ingestion grant must be refused and audited.
func TestIngestRefusedWithoutGrant(t *testing.T) {
	// Manifest permits only report generation, not ingestion.
	h := newHarness(t, scope.CapReportGeneration)
	path := writeTemp(t, "x.bin", []byte("data"))
	_, err := h.ing.Ingest(context.Background(), path)
	if !errors.Is(err, scope.ErrNotPermitted) {
		t.Fatalf("Ingest error = %v, want ErrNotPermitted", err)
	}
	events, _ := evidence.OpenAuditLog(h.audit).Events("")
	if len(events) != 1 || events[0].Decision != "denied" {
		t.Fatalf("refusal should be audited as denied, got %+v", events)
	}
}

// A stored artifact must be retrievable byte-for-byte from the blob store,
// proving hash integrity end to end.
func TestIngestBlobIntegrity(t *testing.T) {
	h := newHarness(t, scope.CapArtifactIngestion)
	data := []byte("some firmware payload with content")
	path := writeTemp(t, "fw.img", data)
	rec, err := h.ing.Ingest(context.Background(), path)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	got, err := h.ing.Blobs.Get(rec.SHA256)
	if err != nil {
		t.Fatalf("Blobs.Get: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("blob content does not match the original artifact")
	}
}

func TestIngestRejectsOversize(t *testing.T) {
	h := newHarness(t, scope.CapArtifactIngestion)
	h.ing.MaxBytes = 8
	path := writeTemp(t, "big.bin", []byte("way more than eight bytes"))
	if _, err := h.ing.Ingest(context.Background(), path); !errors.Is(err, ErrArtifactTooLarge) {
		t.Fatalf("Ingest error = %v, want ErrArtifactTooLarge", err)
	}
}

func TestDetectClasses(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want ArtifactClass
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F', 1, 2}, ClassELF},
		{"pcap-le", []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0}, ClassPCAP},
		{"pcapng", []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0}, ClassPCAPNG},
		{"uboot", []byte{0x27, 0x05, 0x19, 0x56, 0, 0}, ClassUBoot},
		{"dtb", []byte{0xd0, 0x0d, 0xfe, 0xed, 0, 0}, ClassDeviceTree},
		{"squashfs", []byte{'h', 's', 'q', 's', 0, 0}, ClassSquashFS},
		{"gzip", []byte{0x1f, 0x8b, 0, 0}, ClassGzip},
		{"pe", []byte{'M', 'Z', 0, 0}, ClassPE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect(tc.name, tc.data); got.Class != tc.want {
				t.Fatalf("Detect class = %s, want %s", got.Class, tc.want)
			}
		})
	}
}

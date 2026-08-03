package evidence

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestArtifactRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.EnsureProject(ctx, "p1", "owner"); err != nil {
		t.Fatalf("EnsureProject: %v", err)
	}
	rec := ArtifactRecord{
		SHA256: "aa", SHA512: "bb", SizeBytes: 10, MediaType: "application/octet-stream",
		DetectedType: "firmware", OriginalName: "fw.bin", ProjectID: "p1",
		IngestedAt: time.Now().UTC(), BlobPath: "/x", Encrypted: false,
	}
	if err := s.PutArtifact(ctx, rec); err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}
	got, err := s.GetArtifact(ctx, "aa")
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if got.OriginalName != "fw.bin" || got.DetectedType != "firmware" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// Artifacts are write-once: the same id with conflicting content is refused.
func TestPutArtifactRefusesConflict(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := ArtifactRecord{SHA256: "id1", SHA512: "h1", SizeBytes: 100, ProjectID: "p", IngestedAt: time.Now()}
	if err := s.PutArtifact(ctx, base); err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}
	// Same id, different size/hash — an impossible-without-tampering state.
	conflict := base
	conflict.SHA512 = "h2"
	conflict.SizeBytes = 200
	if err := s.PutArtifact(ctx, conflict); !errors.Is(err, ErrArtifactConflict) {
		t.Fatalf("PutArtifact conflict error = %v, want ErrArtifactConflict", err)
	}
	// Identical re-insert is idempotent.
	if err := s.PutArtifact(ctx, base); err != nil {
		t.Fatalf("idempotent re-insert failed: %v", err)
	}
}

func TestGetArtifactMissing(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetArtifact(context.Background(), "nope")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetArtifact error = %v, want sql.ErrNoRows", err)
	}
}

func TestFindingRoundTripPreservesConfidenceModel(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	f := FindingRecord{
		ID: "REV-TRUST-004", ProjectID: "p", Title: "trust boundary",
		Classification: "trust-boundary", Confidence: "medium",
		Observation:  []string{"a cert chain is presented"},
		Inference:    []string{"service likely requires an authorized identity"},
		Alternatives: []string{"the chain may be advisory"},
		EvidenceIDs:  []string{"pcap_sha256:abc"},
		NextSafeTest: []string{"compare two sanitized lab sessions in the simulator"},
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.PutFinding(ctx, f); err != nil {
		t.Fatalf("PutFinding: %v", err)
	}
	got, err := s.ListFindings(ctx, "p")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	// Observation and inference must remain distinct after a round-trip.
	if len(got[0].Observation) != 1 || got[0].Observation[0] != "a cert chain is presented" {
		t.Fatalf("observation not preserved: %+v", got[0].Observation)
	}
	if len(got[0].Inference) != 1 || got[0].Inference[0] != "service likely requires an authorized identity" {
		t.Fatalf("inference not preserved: %+v", got[0].Inference)
	}
	if got[0].Confidence != "medium" {
		t.Fatalf("confidence = %q", got[0].Confidence)
	}
}

func TestManifestRecordAppend(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	m := ManifestRecord{
		ProjectID: "p", AssetID: "a", AssetType: "firmware_image", OwnershipEvidence: "receipt",
		Permitted: []string{"firmware_metadata_analysis"}, Prohibited: []string{"production_key_extraction"},
		ExpiresAt: "2999-01-01T00:00:00Z", Signature: "ed25519:x:y", SignerKey: "x",
		RecordedAt: time.Now().UTC(),
	}
	if err := s.PutManifestRecord(ctx, m); err != nil {
		t.Fatalf("PutManifestRecord: %v", err)
	}
}

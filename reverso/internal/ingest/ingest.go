// Package ingest hashes owner-supplied artifacts, classifies them, and records
// them in the immutable evidence store. Ingestion is authorization-gated and
// audited, and it never modifies the original evidence: the source file is
// opened read-only and copied into a content-addressed blob.
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// DefaultMaxBytes caps how large an artifact ingest will read into memory. It
// bounds resource use and forces an explicit decision for very large images.
const DefaultMaxBytes int64 = 512 << 20 // 512 MiB

// ErrArtifactTooLarge means the artifact exceeded the configured size cap.
var ErrArtifactTooLarge = errors.New("artifact exceeds the maximum ingest size")

// Ingestor wires the policy engine and evidence store together for ingestion.
type Ingestor struct {
	Policy   scope.Policy
	Store    *evidence.Store
	Blobs    *evidence.BlobStore
	Audit    *evidence.AuditLog
	Actor    string
	MaxBytes int64
	Now      func() time.Time
}

func (i *Ingestor) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now().UTC()
}

func (i *Ingestor) maxBytes() int64 {
	if i.MaxBytes > 0 {
		return i.MaxBytes
	}
	return DefaultMaxBytes
}

// Ingest authorizes the artifact_ingestion capability, hashes and classifies
// the file, stores it, and records provenance plus an audit event. Every
// outcome — allowed or denied — is written to the audit trail.
func (i *Ingestor) Ingest(ctx context.Context, path string) (evidence.ArtifactRecord, error) {
	projectID := ""
	assetType := scope.AssetType("")
	if i.Policy.Manifest != nil {
		projectID = i.Policy.Manifest.Authorization.ProjectID
		assetType = i.Policy.Manifest.Authorization.Target.AssetType
	}

	action := scope.Action{
		Capability: scope.CapArtifactIngestion,
		AssetType:  assetType,
		Target:     path,
	}
	dec, authErr := i.Policy.Authorize(ctx, action)
	if authErr != nil {
		// A refusal is itself an auditable event. If the audit write also fails
		// we still surface the refusal, which is the material outcome.
		_ = i.audit(ctx, evidence.Event{
			ProjectID: projectID, Actor: i.Actor, Capability: string(scope.CapArtifactIngestion),
			Target: path, Decision: "denied", Reason: dec.Reason,
		})
		return evidence.ArtifactRecord{}, authErr
	}

	info, err := os.Stat(path)
	if err != nil {
		return evidence.ArtifactRecord{}, fmt.Errorf("stat artifact: %w", err)
	}
	if info.IsDir() {
		return evidence.ArtifactRecord{}, fmt.Errorf("%s is a directory, not an artifact", path)
	}

	// Open read-only and never write back: original evidence is immutable.
	f, err := os.Open(path)
	if err != nil {
		return evidence.ArtifactRecord{}, fmt.Errorf("open artifact: %w", err)
	}
	defer func() { _ = f.Close() }()

	max := i.maxBytes()
	sha256h := sha256.New()
	sha512h := sha512.New()
	var buf bytes.Buffer
	// Read one byte past the cap to detect oversize without silent truncation.
	n, err := io.Copy(io.MultiWriter(sha256h, sha512h, &buf), io.LimitReader(f, max+1))
	if err != nil {
		return evidence.ArtifactRecord{}, fmt.Errorf("reading artifact: %w", err)
	}
	if n > max {
		return evidence.ArtifactRecord{}, fmt.Errorf("%w: %d bytes exceeds cap %d", ErrArtifactTooLarge, n, max)
	}

	data := buf.Bytes()
	id := hex.EncodeToString(sha256h.Sum(nil))
	sha512hex := hex.EncodeToString(sha512h.Sum(nil))

	detection := Detect(info.Name(), data)

	blobPath, err := i.Blobs.Put(id, data)
	if err != nil {
		return evidence.ArtifactRecord{}, fmt.Errorf("storing blob: %w", err)
	}

	rec := evidence.ArtifactRecord{
		SHA256:       id,
		SHA512:       sha512hex,
		SizeBytes:    n,
		MediaType:    detection.MediaType,
		DetectedType: string(detection.Class),
		OriginalName: info.Name(),
		ProjectID:    projectID,
		IngestedAt:   i.now(),
		BlobPath:     blobPath,
		Encrypted:    i.Blobs.Encrypted(),
	}
	if projectID != "" && i.Policy.Manifest != nil {
		if err := i.Store.EnsureProject(ctx, projectID, i.Policy.Manifest.Authorization.Owner); err != nil {
			return evidence.ArtifactRecord{}, err
		}
	}
	if err := i.Store.PutArtifact(ctx, rec); err != nil {
		return evidence.ArtifactRecord{}, err
	}

	if err := i.audit(ctx, evidence.Event{
		ProjectID: projectID, Actor: i.Actor, Capability: string(scope.CapArtifactIngestion),
		Target: path, Decision: "allowed", Reason: "authorized",
		Detail: fmt.Sprintf("sha256=%s type=%s size=%d", id, detection.Class, n),
	}); err != nil {
		// The artifact is stored, but a completed action that cannot be audited
		// is surfaced rather than hidden, honoring the immutable-audit-trail
		// requirement.
		return rec, fmt.Errorf("artifact stored but audit record failed: %w", err)
	}
	return rec, nil
}

// audit records an event when an audit log is configured. A nil log is a
// deliberate no-op (used by pure-analysis unit tests); a configured log that
// fails to record returns the error to the caller.
func (i *Ingestor) audit(ctx context.Context, ev evidence.Event) error {
	if i.Audit == nil {
		return nil
	}
	return i.Audit.Record(ctx, ev)
}

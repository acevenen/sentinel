package evidence

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver; no CGO
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion is bumped when schema.sql changes in a breaking way.
const schemaVersion = "1"

// Store is the SQLite-backed metadata and provenance database. Artifact bytes
// are not stored here; see BlobStore. The store treats artifacts as write-once.
type Store struct {
	db *sql.DB
}

// ArtifactRecord is the provenance row for one ingested artifact.
type ArtifactRecord struct {
	SHA256       string
	SHA512       string
	SizeBytes    int64
	MediaType    string
	DetectedType string
	OriginalName string
	ProjectID    string
	IngestedAt   time.Time
	BlobPath     string
	Encrypted    bool
}

// ManifestRecord is the provenance row for a verified manifest.
type ManifestRecord struct {
	ProjectID         string
	AssetID           string
	AssetType         string
	OwnershipEvidence string
	Permitted         []string
	Prohibited        []string
	ExpiresAt         string
	Signature         string
	SignerKey         string
	RecordedAt        time.Time
}

// FindingRecord follows the confidence model. Slices are stored as JSON.
type FindingRecord struct {
	ID             string
	ProjectID      string
	Title          string
	Classification string
	Confidence     string
	Observation    []string
	Inference      []string
	Alternatives   []string
	EvidenceIDs    []string
	NextSafeTest   []string
	CreatedAt      time.Time
}

// ErrArtifactConflict means an artifact id already exists with different
// provenance, which content addressing should make impossible.
var ErrArtifactConflict = errors.New("artifact id already exists with different content metadata")

// Open opens (creating if needed) the SQLite store at path and migrates it.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("opening evidence store: %w", err)
	}
	db.SetMaxOpenConns(1) // serialize writes; SQLite is single-writer
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("applying schema: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO schema_meta(key, value) VALUES('version', ?)
		 ON CONFLICT(key) DO NOTHING`, schemaVersion)
	if err != nil {
		return fmt.Errorf("recording schema version: %w", err)
	}
	return nil
}

// EnsureProject inserts a project row if absent.
func (s *Store) EnsureProject(ctx context.Context, projectID, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects(project_id, owner, created_at) VALUES(?, ?, ?)
		 ON CONFLICT(project_id) DO NOTHING`,
		projectID, owner, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("ensuring project: %w", err)
	}
	return nil
}

// PutArtifact stores provenance for one artifact. It is write-once: re-storing
// the same id with identical metadata succeeds idempotently; a conflicting
// insert is refused.
func (s *Store) PutArtifact(ctx context.Context, a ArtifactRecord) error {
	existing, err := s.GetArtifact(ctx, a.SHA256)
	if err == nil {
		if existing.SHA512 != a.SHA512 || existing.SizeBytes != a.SizeBytes {
			return ErrArtifactConflict
		}
		return nil // idempotent
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	enc := 0
	if a.Encrypted {
		enc = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO artifacts(sha256, sha512, size_bytes, media_type, detected_type,
			original_name, project_id, ingested_at, blob_path, encrypted)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.SHA256, a.SHA512, a.SizeBytes, a.MediaType, a.DetectedType,
		a.OriginalName, a.ProjectID, a.IngestedAt.UTC().Format(time.RFC3339), a.BlobPath, enc)
	if err != nil {
		return fmt.Errorf("inserting artifact: %w", err)
	}
	return nil
}

// GetArtifact returns provenance for id, or sql.ErrNoRows if absent.
func (s *Store) GetArtifact(ctx context.Context, id string) (ArtifactRecord, error) {
	var (
		a          ArtifactRecord
		ingestedAt string
		enc        int
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT sha256, sha512, size_bytes, media_type, detected_type, original_name,
			project_id, ingested_at, blob_path, encrypted FROM artifacts WHERE sha256 = ?`, id)
	err := row.Scan(&a.SHA256, &a.SHA512, &a.SizeBytes, &a.MediaType, &a.DetectedType,
		&a.OriginalName, &a.ProjectID, &ingestedAt, &a.BlobPath, &enc)
	if err != nil {
		return ArtifactRecord{}, err
	}
	a.IngestedAt, _ = time.Parse(time.RFC3339, ingestedAt)
	a.Encrypted = enc != 0
	return a, nil
}

// ListArtifacts returns all artifacts for a project (all projects if empty).
func (s *Store) ListArtifacts(ctx context.Context, projectID string) ([]ArtifactRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if projectID == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT sha256, sha512, size_bytes, media_type,
			detected_type, original_name, project_id, ingested_at, blob_path, encrypted
			FROM artifacts ORDER BY ingested_at`)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT sha256, sha512, size_bytes, media_type,
			detected_type, original_name, project_id, ingested_at, blob_path, encrypted
			FROM artifacts WHERE project_id = ? ORDER BY ingested_at`, projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("listing artifacts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ArtifactRecord
	for rows.Next() {
		var (
			a          ArtifactRecord
			ingestedAt string
			enc        int
		)
		if err := rows.Scan(&a.SHA256, &a.SHA512, &a.SizeBytes, &a.MediaType, &a.DetectedType,
			&a.OriginalName, &a.ProjectID, &ingestedAt, &a.BlobPath, &enc); err != nil {
			return nil, fmt.Errorf("scanning artifact: %w", err)
		}
		a.IngestedAt, _ = time.Parse(time.RFC3339, ingestedAt)
		a.Encrypted = enc != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// PutManifestRecord appends a manifest provenance row.
func (s *Store) PutManifestRecord(ctx context.Context, m ManifestRecord) error {
	permitted, err := json.Marshal(m.Permitted)
	if err != nil {
		return fmt.Errorf("encoding permitted: %w", err)
	}
	prohibited, err := json.Marshal(m.Prohibited)
	if err != nil {
		return fmt.Errorf("encoding prohibited: %w", err)
	}
	recordedAt := m.RecordedAt
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO manifests(project_id, asset_id, asset_type, ownership_evidence,
			permitted, prohibited, expires_at, signature, signer_key, recorded_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project_id, recorded_at) DO NOTHING`,
		m.ProjectID, m.AssetID, m.AssetType, m.OwnershipEvidence,
		string(permitted), string(prohibited), m.ExpiresAt, m.Signature, m.SignerKey,
		recordedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("inserting manifest record: %w", err)
	}
	return nil
}

// PutFinding stores a finding following the confidence model.
func (s *Store) PutFinding(ctx context.Context, f FindingRecord) error {
	enc := func(v []string) (string, error) {
		if v == nil {
			v = []string{}
		}
		b, err := json.Marshal(v)
		return string(b), err
	}
	obs, err := enc(f.Observation)
	if err != nil {
		return fmt.Errorf("encoding observation: %w", err)
	}
	inf, err := enc(f.Inference)
	if err != nil {
		return fmt.Errorf("encoding inference: %w", err)
	}
	alt, err := enc(f.Alternatives)
	if err != nil {
		return fmt.Errorf("encoding alternatives: %w", err)
	}
	ev, err := enc(f.EvidenceIDs)
	if err != nil {
		return fmt.Errorf("encoding evidence ids: %w", err)
	}
	nst, err := enc(f.NextSafeTest)
	if err != nil {
		return fmt.Errorf("encoding next safe test: %w", err)
	}
	createdAt := f.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO findings(id, project_id, title, classification, confidence,
			observation, inference, alternatives, evidence_ids, next_safe_test, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		f.ID, f.ProjectID, f.Title, f.Classification, f.Confidence,
		obs, inf, alt, ev, nst, createdAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("inserting finding: %w", err)
	}
	return nil
}

// ListFindings returns findings for a project (all if empty).
func (s *Store) ListFindings(ctx context.Context, projectID string) ([]FindingRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	q := `SELECT id, project_id, title, classification, confidence, observation,
		inference, alternatives, evidence_ids, next_safe_test, created_at FROM findings`
	if projectID == "" {
		rows, err = s.db.QueryContext(ctx, q+" ORDER BY created_at")
	} else {
		rows, err = s.db.QueryContext(ctx, q+" WHERE project_id = ? ORDER BY created_at", projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	dec := func(s string) []string {
		var v []string
		_ = json.Unmarshal([]byte(s), &v)
		return v
	}
	var out []FindingRecord
	for rows.Next() {
		var (
			f                                    FindingRecord
			obs, inf, alt, ev, nst, createdAtStr string
		)
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.Title, &f.Classification, &f.Confidence,
			&obs, &inf, &alt, &ev, &nst, &createdAtStr); err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}
		f.Observation, f.Inference, f.Alternatives = dec(obs), dec(inf), dec(alt)
		f.EvidenceIDs, f.NextSafeTest = dec(ev), dec(nst)
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		out = append(out, f)
	}
	return out, rows.Err()
}

-- REVerso immutable evidence store (SQLite).
--
-- The store holds only metadata and provenance; artifact bytes live in the
-- content-addressed blob store keyed by SHA-256. Artifacts are never updated in
-- place: the primary key is the content hash, so a row can only be inserted,
-- and the store layer refuses conflicting inserts. The tamper-evident audit
-- trail is a separate signed, hash-chained log file, not a table, so a write to
-- this database cannot silently rewrite history.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Each verified manifest that governs work is recorded for provenance. A
-- project may re-scope over time; rows are append-only and timestamped.
CREATE TABLE IF NOT EXISTS manifests (
    project_id         TEXT NOT NULL,
    asset_id           TEXT NOT NULL,
    asset_type         TEXT NOT NULL,
    ownership_evidence TEXT NOT NULL,
    permitted          TEXT NOT NULL,  -- JSON array of capabilities
    prohibited         TEXT NOT NULL,  -- JSON array of capabilities
    expires_at         TEXT NOT NULL,
    signature          TEXT NOT NULL,
    signer_key         TEXT NOT NULL,  -- base64 Ed25519 public key
    recorded_at        TEXT NOT NULL,
    PRIMARY KEY (project_id, recorded_at)
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256        TEXT PRIMARY KEY,     -- content id
    sha512        TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    media_type    TEXT NOT NULL,        -- sniffed MIME
    detected_type TEXT NOT NULL,        -- REVerso artifact class
    original_name TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    ingested_at   TEXT NOT NULL,
    blob_path     TEXT NOT NULL,
    encrypted     INTEGER NOT NULL DEFAULT 0
);

-- Findings follow the confidence model: observation, inference, confidence,
-- evidence ids, alternatives and a next safe test are stored as JSON so the
-- report layer can render them while keeping observation separate from
-- inference and speculation.
CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    title          TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    observation    TEXT NOT NULL,  -- JSON array of strings
    inference      TEXT NOT NULL,  -- JSON array of strings
    alternatives   TEXT NOT NULL,  -- JSON array of strings
    evidence_ids   TEXT NOT NULL,  -- JSON array of strings
    next_safe_test TEXT NOT NULL,  -- JSON array of strings
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_project ON artifacts(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);

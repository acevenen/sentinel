package evidence

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLog is a tamper-evident, append-only trail of every authorization
// decision and state-changing action. Each record is chained to the previous by
// hash and signed with the store's Ed25519 audit key, so editing, reordering,
// or deleting any non-trailing record breaks Verify, and forging a record
// requires the private key.
//
// One limitation is inherent to append-only hash chains: any prefix of a valid
// chain is itself a valid chain, so deleting the most recent record(s) — or
// wiping the log entirely — cannot be detected from the file alone. Detecting
// trailing truncation requires an external anchor: record the head (count and
// head hash) somewhere the log's writer cannot reach, then check the log
// against it. VerifiedHead exposes the head for that purpose, and the
// `reverso audit verify --save-anchor/--anchor` workflow implements it.
type AuditLog struct {
	Path   string
	signer ed25519.PrivateKey // may be nil for a read-only (verify) handle
	mu     sync.Mutex
}

// Event is one auditable moment. Both allowed and denied decisions are logged.
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	ProjectID  string    `json:"project_id,omitempty"`
	Actor      string    `json:"actor"`
	Capability string    `json:"capability"`
	Target     string    `json:"target"`
	Decision   string    `json:"decision"` // "allowed" or "denied"
	Reason     string    `json:"reason"`
	Detail     string    `json:"detail,omitempty"`
	DryRun     bool      `json:"dry_run,omitempty"`
}

type auditRecord struct {
	Event
	PreviousHash string `json:"previous_hash,omitempty"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature"` // base64 Ed25519 over Hash bytes
}

type auditPayload struct {
	Event
	PreviousHash string `json:"previous_hash,omitempty"`
}

// NewAuditLog returns a writable audit log signing with priv.
func NewAuditLog(path string, priv ed25519.PrivateKey) *AuditLog {
	return &AuditLog{Path: path, signer: priv}
}

// OpenAuditLog returns a read-only handle for verification.
func OpenAuditLog(path string) *AuditLog {
	return &AuditLog{Path: path}
}

// Record appends one signed, chained event with owner-only permissions.
func (l *AuditLog) Record(ctx context.Context, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || l.Path == "" {
		return errors.New("audit log path is required")
	}
	if l.signer == nil {
		return errors.New("audit log has no signing key")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	previous, err := l.lastHashLocked()
	if err != nil {
		return err
	}
	hash, err := hashPayload(auditPayload{Event: ev, PreviousHash: previous})
	if err != nil {
		return err
	}
	rawHash, err := hex.DecodeString(hash)
	if err != nil {
		return fmt.Errorf("decoding audit hash: %w", err)
	}
	sig := ed25519.Sign(l.signer, rawHash)
	record := auditRecord{
		Event:        ev,
		PreviousHash: previous,
		Hash:         hash,
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding audit event: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return fmt.Errorf("creating audit directory: %w", err)
	}
	file, err := os.OpenFile(l.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("appending audit log: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("syncing audit log: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing audit log: %w", err)
	}
	return nil
}

// Verify validates the full hash chain and every signature against pub. It
// detects any edit, reordering, or non-trailing deletion. It cannot, by itself,
// detect trailing truncation or a full wipe; use VerifiedHead with an external
// anchor for that.
func (l *AuditLog) Verify(pub ed25519.PublicKey) error {
	_, err := l.VerifiedHashes(pub)
	return err
}

// Head is the tamper-evidence commitment for an audit log: how many records it
// holds and the hash of the most recent one. Recording a Head somewhere the
// log's writer cannot reach lets a later verifier detect trailing truncation.
type Head struct {
	Count    int    `json:"count"`
	HeadHash string `json:"head_hash"`
}

// VerifiedHead verifies the chain and returns its head commitment.
func (l *AuditLog) VerifiedHead(pub ed25519.PublicKey) (Head, error) {
	hashes, err := l.VerifiedHashes(pub)
	if err != nil {
		return Head{}, err
	}
	h := Head{Count: len(hashes)}
	if len(hashes) > 0 {
		h.HeadHash = hashes[len(hashes)-1]
	}
	return h, nil
}

// VerifiedHashes verifies the chain and returns the ordered per-record hashes,
// so a caller can anchor against a specific earlier position.
func (l *AuditLog) VerifiedHashes(pub ed25519.PublicKey) ([]string, error) {
	if l == nil || l.Path == "" {
		return nil, errors.New("audit log path is required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("audit verification requires a valid public key")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	file, err := os.Open(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // an empty trail is self-consistent (but see VerifiedHead)
	}
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = file.Close() }()

	var (
		previous string
		hashes   []string
		line     int
	)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line++
		var record auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("audit line %d is invalid JSON: %w", line, err)
		}
		if record.PreviousHash != previous {
			return nil, fmt.Errorf("audit line %d has a broken previous hash", line)
		}
		want, err := hashPayload(auditPayload{Event: record.Event, PreviousHash: record.PreviousHash})
		if err != nil {
			return nil, err
		}
		if record.Hash != want {
			return nil, fmt.Errorf("audit line %d has an invalid hash", line)
		}
		rawHash, err := hex.DecodeString(record.Hash)
		if err != nil {
			return nil, fmt.Errorf("audit line %d has a non-hex hash: %w", line, err)
		}
		sig, err := base64.StdEncoding.DecodeString(record.Signature)
		if err != nil {
			return nil, fmt.Errorf("audit line %d has a malformed signature: %w", line, err)
		}
		if !ed25519.Verify(pub, rawHash, sig) {
			return nil, fmt.Errorf("audit line %d has an invalid signature", line)
		}
		previous = record.Hash
		hashes = append(hashes, record.Hash)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}
	return hashes, nil
}

// CheckAnchor verifies the chain against pub and confirms it still contains the
// anchored record at the same position with the same hash. It detects trailing
// truncation below the anchor point (and a full wipe). anchor.Count == 0 is a
// no-op that only runs the base verification.
func (l *AuditLog) CheckAnchor(pub ed25519.PublicKey, anchor Head) error {
	hashes, err := l.VerifiedHashes(pub)
	if err != nil {
		return err
	}
	if anchor.Count == 0 {
		return nil
	}
	if len(hashes) < anchor.Count {
		return fmt.Errorf("audit log has %d records, fewer than the anchored %d: trailing records were truncated",
			len(hashes), anchor.Count)
	}
	if got := hashes[anchor.Count-1]; got != anchor.HeadHash {
		return fmt.Errorf("audit record %d does not match the anchor: the trail was rewritten", anchor.Count)
	}
	return nil
}

// Events returns a copy of recorded events, optionally filtered by project.
// It does not re-verify; call Verify first when integrity matters.
func (l *AuditLog) Events(projectID string) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := os.Open(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = file.Close() }()
	var events []Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var record auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decoding audit event: %w", err)
		}
		if projectID == "" || record.ProjectID == projectID {
			events = append(events, record.Event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}
	return events, nil
}

func (l *AuditLog) lastHashLocked() (string, error) {
	file, err := os.Open(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = file.Close() }()
	var last auditRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &last); err != nil {
			return "", fmt.Errorf("existing audit log is invalid: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading audit log: %w", err)
	}
	return last.Hash, nil
}

func hashPayload(payload auditPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoding audit hash payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

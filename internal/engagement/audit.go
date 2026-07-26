package engagement

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/acevenen/sentinel/internal/tools"
)

// AuditLog appends hash-chained JSONL records. Altering or deleting an entry
// breaks Verify, making accidental or deliberate tampering evident.
type AuditLog struct {
	Path string
	mu   sync.Mutex
}

type auditRecord struct {
	tools.AuditEvent
	PreviousHash string `json:"previous_hash,omitempty"`
	Hash         string `json:"hash"`
}

type auditPayload struct {
	tools.AuditEvent
	PreviousHash string `json:"previous_hash,omitempty"`
}

// Record appends one tamper-evident event with owner-only permissions.
func (l *AuditLog) Record(ctx context.Context, event tools.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || l.Path == "" {
		return errors.New("audit log path is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	previous, err := l.lastHash()
	if err != nil {
		return err
	}
	payload := auditPayload{AuditEvent: event, PreviousHash: previous}
	hash, err := hashPayload(payload)
	if err != nil {
		return err
	}
	record := auditRecord{AuditEvent: event, PreviousHash: previous, Hash: hash}
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

// Verify validates the complete hash chain.
func (l *AuditLog) Verify() error {
	if l == nil || l.Path == "" {
		return errors.New("audit log path is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	file, err := os.Open(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = file.Close() }()

	var previous string
	line := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line++
		var record auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("audit line %d is invalid JSON: %w", line, err)
		}
		if record.PreviousHash != previous {
			return fmt.Errorf("audit line %d has a broken previous hash", line)
		}
		want, err := hashPayload(auditPayload{AuditEvent: record.AuditEvent, PreviousHash: record.PreviousHash})
		if err != nil {
			return err
		}
		if record.Hash != want {
			return fmt.Errorf("audit line %d has an invalid hash", line)
		}
		previous = record.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}
	return nil
}

func (l *AuditLog) lastHash() (string, error) {
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
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
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

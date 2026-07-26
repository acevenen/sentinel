// Package engagement persists authorization records, scope, rules of
// engagement metadata, and portable run state. Sensitive records belong in an
// ignored or encrypted directory, never in the repository.
package engagement

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
)

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Record is the operator-controlled authorization source for one engagement.
type Record struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	Mode                 string      `json:"mode,omitempty"`
	Operator             string      `json:"operator"`
	AuthorizationRef     string      `json:"authorization_reference,omitempty"`
	OperatorAttested     bool        `json:"operator_attested"`
	Scope                authz.Scope `json:"scope"`
	RateLimitRPS         float64     `json:"rate_limit_rps,omitempty"`
	Concurrency          int         `json:"concurrency,omitempty"`
	AutomationProhibited bool        `json:"automation_prohibited,omitempty"`
	ExploitAuthorized    bool        `json:"exploit_authorized,omitempty"`
	SocialAuthorized     bool        `json:"social_engineering_authorized,omitempty"`
	CreatedAt            time.Time   `json:"created_at"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

// Validate rejects records that cannot be safely addressed or audited.
func (r Record) Validate() error {
	if !validID.MatchString(r.ID) {
		return errors.New("engagement id must contain only letters, digits, dot, underscore, or hyphen")
	}
	if r.Name == "" {
		return errors.New("engagement name is required")
	}
	if r.Operator == "" {
		return errors.New("engagement operator is required")
	}
	if r.RateLimitRPS < 0 {
		return errors.New("engagement rate limit cannot be negative")
	}
	if r.Concurrency < 0 {
		return errors.New("engagement concurrency cannot be negative")
	}
	switch r.Mode {
	case "", "standard", "lab", "ctf", "bounty":
	default:
		return errors.New("engagement mode must be standard, lab, ctf, or bounty")
	}
	return nil
}

// Authorization returns the narrow view consumed by authz.Policy.
func (r Record) Authorization() authz.EngagementAuthorization {
	return authz.EngagementAuthorization{
		ID:        r.ID,
		Reference: r.AuthorizationRef,
		Operator:  r.Operator,
		Attested:  r.OperatorAttested,
	}
}

// Store is the persistence contract used by the CLI and methodology engine.
type Store interface {
	Save(Record) error
	Get(string) (Record, error)
	List() ([]Record, error)
}

// FileStore stores one portable JSON record per engagement.
type FileStore struct {
	Dir string
}

// Save validates and atomically replaces a record.
func (s FileStore) Save(record Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	record.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("creating engagement directory: %w", err)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding engagement: %w", err)
	}
	tmp, err := os.CreateTemp(s.Dir, ".engagement-*.tmp")
	if err != nil {
		return fmt.Errorf("creating engagement temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path(record.ID)); err != nil {
		return fmt.Errorf("saving engagement: %w", err)
	}
	return nil
}

// Get loads one engagement by its validated identifier.
func (s FileStore) Get(id string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, errors.New("invalid engagement id")
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return Record{}, fmt.Errorf("reading engagement %q: %w", id, err)
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decoding engagement %q: %w", id, err)
	}
	if err := record.Validate(); err != nil {
		return Record{}, fmt.Errorf("invalid engagement %q: %w", id, err)
	}
	return record, nil
}

// List returns all valid records sorted by identifier.
func (s FileStore) List() ([]Record, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing engagements: %w", err)
	}
	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		record, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (s FileStore) path(id string) string {
	return filepath.Join(s.Dir, id+".json")
}

// Package ctf models operator-controlled CTF policy and regression scorecards.
package ctf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/engagement"
	"github.com/acevenen/sentinel/internal/methodology"
)

var validChallengeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Rules are the platform limits the operator transcribed from the current
// challenge policy.
type Rules struct {
	AutomationAllowed bool    `json:"automation_allowed" yaml:"automation_allowed"`
	MaxRequestsPerSec float64 `json:"max_requests_per_second" yaml:"max_requests_per_second"`
	MaxConcurrency    int     `json:"max_concurrency" yaml:"max_concurrency"`
	IntrusiveAllowed  bool    `json:"intrusive_allowed" yaml:"intrusive_allowed"`
}

// Challenge is one isolated, sanctioned target.
type Challenge struct {
	ID    string      `json:"id" yaml:"id"`
	Name  string      `json:"name" yaml:"name"`
	Scope authz.Scope `json:"scope" yaml:"scope"`
}

// Manifest is operator-supplied; Sentinel never bakes in a third-party target.
type Manifest struct {
	Platform   string      `json:"platform" yaml:"platform"`
	Event      string      `json:"event" yaml:"event"`
	PolicyURL  string      `json:"policy_url" yaml:"policy_url"`
	Rules      Rules       `json:"rules" yaml:"rules"`
	Challenges []Challenge `json:"challenges" yaml:"challenges"`
}

// LoadManifest reads a bounded YAML or JSON manifest.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading CTF manifest: %w", err)
	}
	if len(data) > 2<<20 {
		return Manifest{}, errors.New("CTF manifest exceeds 2 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decoding CTF manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("CTF manifest contains multiple documents")
		}
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate fails closed on ambiguous platform rules.
func (m Manifest) Validate() error {
	if m.Platform == "" || m.Event == "" || len(m.Challenges) == 0 {
		return errors.New("CTF manifest requires platform, event, and challenges")
	}
	parsed, err := url.Parse(m.PolicyURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("CTF manifest requires an absolute policy_url")
	}
	if m.Rules.MaxRequestsPerSec < 0 || m.Rules.MaxConcurrency < 0 {
		return errors.New("CTF limits cannot be negative")
	}
	if m.Rules.AutomationAllowed && (m.Rules.MaxRequestsPerSec <= 0 || m.Rules.MaxConcurrency <= 0) {
		return errors.New("automated CTF mode requires explicit positive rate and concurrency limits")
	}
	seen := map[string]bool{}
	for _, challenge := range m.Challenges {
		if !validChallengeID.MatchString(challenge.ID) || challenge.Name == "" || challenge.Scope.Empty() {
			return fmt.Errorf("CTF challenge %q requires a valid id, name, and allow-list", challenge.ID)
		}
		if seen[challenge.ID] {
			return fmt.Errorf("duplicate CTF challenge %q", challenge.ID)
		}
		seen[challenge.ID] = true
	}
	return nil
}

// Engagement creates a scope-locked record after the operator attests that the
// manifest reflects the current platform rules.
func (m Manifest) Engagement(challengeID, operator string, attested bool) (engagement.Record, error) {
	if !attested {
		return engagement.Record{}, errors.New("operator must attest that the current CTF rules were reviewed")
	}
	for _, challenge := range m.Challenges {
		if challenge.ID != challengeID {
			continue
		}
		return engagement.Record{
			ID: challenge.ID, Name: m.Platform + " / " + m.Event + " / " + challenge.Name,
			Mode: "ctf", Operator: operator, AuthorizationRef: m.PolicyURL,
			OperatorAttested: true, Scope: challenge.Scope,
			RateLimitRPS: m.Rules.MaxRequestsPerSec, Concurrency: m.Rules.MaxConcurrency,
			AutomationProhibited: !m.Rules.AutomationAllowed,
			ExploitAuthorized:    m.Rules.IntrusiveAllowed,
		}, nil
	}
	return engagement.Record{}, fmt.Errorf("CTF challenge %q is not in the manifest", challengeID)
}

// Outcome records the human-confirmed state of one challenge.
type Outcome struct {
	ChallengeID string `json:"challenge_id" yaml:"challenge_id"`
	Attempted   bool   `json:"attempted" yaml:"attempted"`
	Solved      bool   `json:"solved" yaml:"solved"`
}

// RunRecord is operator-supplied execution evidence.
type RunRecord struct {
	StartedAt  time.Time           `json:"started_at" yaml:"started_at"`
	FinishedAt time.Time           `json:"finished_at" yaml:"finished_at"`
	Stages     []methodology.Stage `json:"stages" yaml:"stages"`
	Tools      []string            `json:"tools" yaml:"tools"`
	Outcomes   []Outcome           `json:"outcomes" yaml:"outcomes"`
}

// LoadRunRecord reads one bounded score input.
func LoadRunRecord(path string) (RunRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RunRecord{}, fmt.Errorf("reading CTF run record: %w", err)
	}
	if len(data) > 2<<20 {
		return RunRecord{}, errors.New("CTF run record exceeds 2 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var record RunRecord
	if err := decoder.Decode(&record); err != nil {
		return RunRecord{}, fmt.Errorf("decoding CTF run record: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return RunRecord{}, errors.New("CTF run record contains multiple documents")
		}
		return RunRecord{}, err
	}
	return record, nil
}

// Scorecard is the regression benchmark emitted by CTF mode.
type Scorecard struct {
	Platform            string              `json:"platform"`
	Event               string              `json:"event"`
	GeneratedAt         time.Time           `json:"generated_at"`
	Duration            string              `json:"duration"`
	ChallengesAttempted int                 `json:"challenges_attempted"`
	ChallengesSolved    int                 `json:"challenges_solved"`
	SolveRate           float64             `json:"solve_rate"`
	Tools               []string            `json:"tools"`
	Stages              []methodology.Stage `json:"stages"`
	CoverageGaps        []methodology.Stage `json:"coverage_gaps,omitempty"`
	Outcomes            []Outcome           `json:"outcomes"`
}

// Score validates run claims against the manifest and computes coverage.
func Score(manifest Manifest, run RunRecord) (Scorecard, error) {
	if run.StartedAt.IsZero() || run.FinishedAt.Before(run.StartedAt) {
		return Scorecard{}, errors.New("CTF run requires a valid start and finish time")
	}
	known := map[string]bool{}
	for _, challenge := range manifest.Challenges {
		known[challenge.ID] = true
	}
	card := Scorecard{
		Platform: manifest.Platform, Event: manifest.Event, GeneratedAt: time.Now().UTC(),
		Duration: run.FinishedAt.Sub(run.StartedAt).Round(time.Millisecond).String(),
		Tools:    uniqueSorted(run.Tools), Stages: uniqueStages(run.Stages),
		Outcomes: append([]Outcome(nil), run.Outcomes...),
	}
	for _, outcome := range run.Outcomes {
		if !known[outcome.ChallengeID] {
			return Scorecard{}, fmt.Errorf("unknown CTF challenge %q in run record", outcome.ChallengeID)
		}
		if outcome.Solved && !outcome.Attempted {
			return Scorecard{}, fmt.Errorf("challenge %q cannot be solved without being attempted", outcome.ChallengeID)
		}
		if outcome.Attempted {
			card.ChallengesAttempted++
		}
		if outcome.Solved {
			card.ChallengesSolved++
		}
	}
	if card.ChallengesAttempted > 0 {
		card.SolveRate = float64(card.ChallengesSolved) / float64(card.ChallengesAttempted)
	}
	completed := map[methodology.Stage]bool{}
	for _, stage := range card.Stages {
		completed[stage] = true
	}
	for _, definition := range methodology.DefaultDefinitions {
		if !completed[definition.Stage] {
			card.CoverageGaps = append(card.CoverageGaps, definition.Stage)
		}
	}
	return card, nil
}

// AppendHistory adds one owner-only JSONL scorecard.
func AppendHistory(path string, card Scorecard) error {
	if path == "" {
		return errors.New("CTF history path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(card)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueStages(values []methodology.Stage) []methodology.Stage {
	seen := map[methodology.Stage]bool{}
	var out []methodology.Stage
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

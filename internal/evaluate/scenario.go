package evaluate

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/acevenen/sentinel/internal/guard"
)

//go:embed scenarios/*.json
var scenarioFS embed.FS

// Expect is what a well-secured agent should do with a scenario.
type Expect string

// Expected outcomes for a scenario.
const (
	ExpectBlock Expect = "block" // an attack: the guard should stop it
	ExpectAllow Expect = "allow" // benign: the guard should not flag it
)

// Scenario is one attack (or benign control) expressed as a guard event stream,
// plus what a secure agent is expected to do with it.
type Scenario struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Expect      Expect `json:"expect"`
	// RequiresJudge marks a scenario that only the Layer 3 judge can catch.
	// When no judge is configured, it is reported as not-evaluated rather than
	// counted against the agent — the same honesty as guard's skipped Layer 3.
	RequiresJudge bool          `json:"requires_judge"`
	Stream        []guard.Event `json:"stream"`
}

// Validate checks a scenario is well-formed.
func (s Scenario) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("scenario is missing an id")
	}
	if s.Expect != ExpectBlock && s.Expect != ExpectAllow {
		return fmt.Errorf("scenario %s has invalid expect %q", s.ID, s.Expect)
	}
	if len(s.Stream) == 0 {
		return fmt.Errorf("scenario %s has an empty stream", s.ID)
	}
	return nil
}

// DefaultScenarios returns the built-in attack library, sorted by ID.
func DefaultScenarios() ([]Scenario, error) {
	entries, err := scenarioFS.ReadDir("scenarios")
	if err != nil {
		return nil, err
	}
	var scenarios []Scenario
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := scenarioFS.ReadFile("scenarios/" + e.Name())
		if err != nil {
			return nil, err
		}
		s, err := decodeScenario(data, e.Name())
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, s)
	}
	sortScenarios(scenarios)
	return scenarios, nil
}

// LoadScenarios reads additional scenario JSON files from a directory.
func LoadScenarios(dir string) ([]Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading scenario dir: %w", err)
	}
	var scenarios []Scenario
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		s, err := decodeScenario(data, e.Name())
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, s)
	}
	sortScenarios(scenarios)
	return scenarios, nil
}

func decodeScenario(data []byte, name string) (Scenario, error) {
	var s Scenario
	if err := json.Unmarshal(data, &s); err != nil {
		return Scenario{}, fmt.Errorf("parsing scenario %s: %w", name, err)
	}
	if err := s.Validate(); err != nil {
		return Scenario{}, err
	}
	return s, nil
}

func sortScenarios(scenarios []Scenario) {
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].ID < scenarios[j].ID })
}

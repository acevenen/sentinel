package intent

import (
	"encoding/json"
	"fmt"
	"os"
)

// Declare is the Layer 1 hook: it validates a declared intent and returns it,
// refusing to proceed when the schema is incomplete. The guard pipeline calls
// this before evaluating any action, so no action is ever judged without a
// declared intent to judge it against.
func Declare(i Intent) (Intent, error) {
	if err := i.Validate(); err != nil {
		return Intent{}, fmt.Errorf("declared intent is invalid: %w", err)
	}
	return i, nil
}

// Load reads a declared intent from a JSON file and validates it.
func Load(path string) (Intent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Intent{}, fmt.Errorf("reading intent file: %w", err)
	}
	var i Intent
	if err := json.Unmarshal(data, &i); err != nil {
		return Intent{}, fmt.Errorf("parsing intent file %s: %w", path, err)
	}
	return Declare(i)
}

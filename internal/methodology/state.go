package methodology

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var validEngagementID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// StateStore persists portable methodology progress.
type StateStore interface {
	Save(RunState) error
	Load(string) (RunState, error)
}

// FileStateStore writes owner-only JSON outside the repository by default.
type FileStateStore struct {
	Dir string
}

// Save atomically replaces one engagement state file.
func (s FileStateStore) Save(state RunState) error {
	if !validEngagementID.MatchString(state.EngagementID) {
		return errors.New("invalid engagement id for methodology state")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("creating methodology state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding methodology state: %w", err)
	}
	file, err := os.CreateTemp(s.Dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("creating methodology state temporary file: %w", err)
	}
	tmp := file.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(state.EngagementID)); err != nil {
		return fmt.Errorf("saving methodology state: %w", err)
	}
	return nil
}

// Load reads one engagement state.
func (s FileStateStore) Load(engagementID string) (RunState, error) {
	if !validEngagementID.MatchString(engagementID) {
		return RunState{}, errors.New("invalid engagement id for methodology state")
	}
	data, err := os.ReadFile(s.path(engagementID))
	if err != nil {
		return RunState{}, fmt.Errorf("reading methodology state: %w", err)
	}
	var state RunState
	if err := json.Unmarshal(data, &state); err != nil {
		return RunState{}, fmt.Errorf("decoding methodology state: %w", err)
	}
	return state, nil
}

func (s FileStateStore) path(engagementID string) string {
	return filepath.Join(s.Dir, engagementID+".json")
}

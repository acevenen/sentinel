package tools

import (
	"fmt"
	"os/exec"
	"sort"
	"sync"
)

// Registry holds explicitly constructed adapters. Discovery and install hints
// are added in Phase 2 without changing Tool.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// DescribedTool provides binary discovery metadata without running preflight.
type DescribedTool interface {
	Tool
	Binary() string
	InstallHint() string
}

// ToolStatus is one adapter's local runtime availability.
type ToolStatus struct {
	Name        string `json:"name"`
	Binary      string `json:"binary,omitempty"`
	Path        string `json:"path,omitempty"`
	Available   bool   `json:"available"`
	InstallHint string `json:"install_hint,omitempty"`
}

// NewRegistry creates an empty adapter registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register adds one adapter and rejects duplicate names.
func (r *Registry) Register(tool Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := tool.Name()
	if name == "" {
		return fmt.Errorf("tool name must not be empty")
	}
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool %q is already registered", name)
	}
	r.tools[name] = tool
	return nil
}

// Get returns an adapter by name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	return tool, ok
}

// Names lists adapters in deterministic order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Discover reports installed and missing binaries in deterministic order.
func (r *Registry) Discover() []ToolStatus {
	names := r.Names()
	statuses := make([]ToolStatus, 0, len(names))
	for _, name := range names {
		tool, _ := r.Get(name)
		status := ToolStatus{Name: name}
		described, ok := tool.(DescribedTool)
		if !ok {
			statuses = append(statuses, status)
			continue
		}
		status.Binary = described.Binary()
		status.InstallHint = described.InstallHint()
		path, err := exec.LookPath(status.Binary)
		if err == nil {
			status.Available = true
			status.Path = path
		}
		statuses = append(statuses, status)
	}
	return statuses
}

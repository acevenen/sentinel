// Package knowledge provides typed, provenance-aware access to wordlists,
// parameter heuristics, methodology checklists, and cloud metadata endpoints.
package knowledge

// Purpose is a stable semantic name; callers do not hardcode dataset paths.
type Purpose string

const (
	PurposeContentDiscovery Purpose = "content-discovery"
	PurposeSubdomains       Purpose = "subdomains"
	PurposeAPIParameters    Purpose = "api-parameters"
	PurposeLLMTesting       Purpose = "llm-testing"
	PurposeSSRFMetadata     Purpose = "ssrf-metadata"
)

// Asset describes one queryable knowledge source.
type Asset struct {
	Name       string
	Purpose    Purpose
	Path       string
	Source     string
	License    string
	Downloaded bool
}

// Catalog resolves knowledge assets by purpose.
type Catalog interface {
	Find(Purpose) []Asset
}

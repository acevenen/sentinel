// Package knowledge provides typed, provenance-aware access to wordlists,
// parameter heuristics, methodology checklists, and cloud metadata endpoints.
package knowledge

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Purpose is a stable semantic name; callers do not hardcode dataset paths.
type Purpose string

const (
	PurposeContentDiscovery Purpose = "content-discovery"
	PurposeSubdomains       Purpose = "subdomains"
	PurposeAPIParameters    Purpose = "api-parameters"
	PurposeLLMTesting       Purpose = "llm-testing"
	PurposeSSRFMetadata     Purpose = "ssrf-metadata"
	PurposeFuzzing          Purpose = "fuzzing"
	PurposePasswords        Purpose = "passwords"
	PurposeUsernames        Purpose = "usernames"
	PurposePatternMatching  Purpose = "pattern-matching"
)

// Asset describes one queryable knowledge source.
type Asset struct {
	Name       string  `json:"name"`
	Purpose    Purpose `json:"purpose"`
	Path       string  `json:"path"`
	Source     string  `json:"source"`
	License    string  `json:"license"`
	Downloaded bool    `json:"downloaded"`
}

// Catalog resolves knowledge assets by purpose.
type Catalog interface {
	Find(Purpose) []Asset
}

// FileCatalog resolves data fetched into a caller-selected directory.
type FileCatalog struct {
	assets []Asset
}

// DefaultCatalog exposes SecLists by semantic purpose and Sentinel's embedded
// factual dictionaries. Large third-party datasets are fetched on demand.
func DefaultCatalog(baseDir string) FileCatalog {
	const (
		seclistsSource  = "https://github.com/danielmiessler/SecLists"
		seclistsLicense = "MIT"
	)
	assets := []Asset{
		{Name: "SecLists web content", Purpose: PurposeContentDiscovery, Path: filepath.Join(baseDir, "SecLists", "Discovery", "Web-Content"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists DNS", Purpose: PurposeSubdomains, Path: filepath.Join(baseDir, "SecLists", "Discovery", "DNS"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists API parameters", Purpose: PurposeAPIParameters, Path: filepath.Join(baseDir, "SecLists", "Discovery", "Web-Content", "api"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists LLM testing", Purpose: PurposeLLMTesting, Path: filepath.Join(baseDir, "SecLists", "Ai", "LLM_Testing"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists fuzzing", Purpose: PurposeFuzzing, Path: filepath.Join(baseDir, "SecLists", "Fuzzing"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists passwords", Purpose: PurposePasswords, Path: filepath.Join(baseDir, "SecLists", "Passwords"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists usernames", Purpose: PurposeUsernames, Path: filepath.Join(baseDir, "SecLists", "Usernames"), Source: seclistsSource, License: seclistsLicense},
		{Name: "SecLists patterns", Purpose: PurposePatternMatching, Path: filepath.Join(baseDir, "SecLists", "Pattern-Matching"), Source: seclistsSource, License: seclistsLicense},
		{Name: "Sentinel cloud metadata dictionary", Purpose: PurposeSSRFMetadata, Path: "embedded:internal/knowledge/data/ssrf-endpoints.json", Source: "vendor documentation; see each entry", License: "factual compilation"},
	}
	for index := range assets {
		if !strings.HasPrefix(assets[index].Path, "embedded:") {
			_, err := os.Stat(assets[index].Path)
			assets[index].Downloaded = err == nil
		} else {
			assets[index].Downloaded = true
		}
	}
	return FileCatalog{assets: assets}
}

// Find implements Catalog.
func (c FileCatalog) Find(purpose Purpose) []Asset {
	var out []Asset
	for _, asset := range c.assets {
		if asset.Purpose == purpose {
			out = append(out, asset)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MetadataEndpoint is a factual cloud instance-metadata location. It contains
// no bypass or exploit payload.
type MetadataEndpoint struct {
	Provider string            `json:"provider"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	Source   string            `json:"source"`
}

//go:embed data/ssrf-endpoints.json
var embeddedMetadata []byte

// MetadataEndpoints returns a defensive copy of the embedded provider list.
func MetadataEndpoints() ([]MetadataEndpoint, error) {
	var endpoints []MetadataEndpoint
	if err := json.Unmarshal(embeddedMetadata, &endpoints); err != nil {
		return nil, err
	}
	return endpoints, nil
}

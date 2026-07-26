package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCatalogByPurpose(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "SecLists", "Discovery", "Web-Content")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	catalog := DefaultCatalog(base)
	assets := catalog.Find(PurposeContentDiscovery)
	if len(assets) != 1 || !assets[0].Downloaded {
		t.Fatalf("content assets = %+v", assets)
	}
	if got := catalog.Find(PurposeLLMTesting); len(got) != 1 || got[0].Downloaded {
		t.Fatalf("LLM assets = %+v", got)
	}
}

func TestMetadataEndpoints(t *testing.T) {
	endpoints, err := MetadataEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 6 {
		t.Fatalf("metadata endpoints = %d, want 6", len(endpoints))
	}
	for _, endpoint := range endpoints {
		if endpoint.Provider == "" || endpoint.URL == "" || endpoint.Source == "" {
			t.Fatalf("incomplete endpoint: %+v", endpoint)
		}
	}
}

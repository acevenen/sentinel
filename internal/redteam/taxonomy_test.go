package redteam

import (
	"os"
	"testing"
)

func TestCoreTaxonomyAndBlackBoxFilter(t *testing.T) {
	taxonomy, err := Core()
	if err != nil {
		t.Fatal(err)
	}
	if taxonomy.License != "CC BY 4.0" {
		t.Fatalf("license = %q", taxonomy.License)
	}
	if _, ok := taxonomy.ByID("PIT-T-42"); !ok {
		t.Fatal("core taxonomy omitted tool-definition injection")
	}
	for _, category := range taxonomy.Applicable(TargetBlackBox) {
		if category.WhiteBoxOnly {
			t.Fatalf("black-box catalog included local category %s", category.ID)
		}
	}
}

func TestLoadOfficialTaxonomy(t *testing.T) {
	data, err := os.ReadFile("../../testdata/redteam/taxonomy.json")
	if err != nil {
		t.Fatal(err)
	}
	taxonomy, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(taxonomy.Categories) != 4 {
		t.Fatalf("categories = %d, want 4", len(taxonomy.Categories))
	}
}

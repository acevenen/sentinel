// Package redteam defines the shared prompt-injection taxonomy used by both
// authorized AI red-team checks and Sentinel's defensive guard.
package redteam

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// Axis is one of the four Arcanum prompt-injection taxonomy dimensions.
type Axis string

const (
	AxisIntent    Axis = "attack-intent"
	AxisTechnique Axis = "attack-technique"
	AxisEvasion   Axis = "attack-evasion"
	AxisInput     Axis = "attack-input"
)

// Delivery distinguishes direct user probes from indirect untrusted content.
type Delivery string

const (
	DeliveryDirect   Delivery = "direct"
	DeliveryIndirect Delivery = "indirect"
	DeliveryBoth     Delivery = "both"
)

// TargetMode distinguishes hosted black-box targets from locally controlled
// model-weight evaluations.
type TargetMode string

const (
	TargetBlackBox TargetMode = "black-box"
	TargetLocal    TargetMode = "local"
)

// Category is a provenance-aware taxonomy entry. Probe content is deliberately
// operator-supplied and is not embedded in this model.
type Category struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Axis         Axis     `json:"axis"`
	Delivery     Delivery `json:"delivery"`
	WhiteBoxOnly bool     `json:"white_box_only,omitempty"`
	Source       string   `json:"source"`
}

// Taxonomy is a queryable category catalog.
type Taxonomy struct {
	Version    string     `json:"version"`
	Source     string     `json:"source"`
	License    string     `json:"license"`
	Categories []Category `json:"categories"`
}

//go:embed data/core-taxonomy.json
var embeddedCore []byte

// Core loads Sentinel's prompt-free embedded defensive subset.
func Core() (Taxonomy, error) {
	return Load(embeddedCore)
}

// Load accepts either Sentinel's category list or the official Arcanum
// taxonomy.json object. Example prompts and ideas are intentionally discarded.
func Load(data []byte) (Taxonomy, error) {
	var taxonomy Taxonomy
	if err := json.Unmarshal(data, &taxonomy); err == nil && len(taxonomy.Categories) > 0 {
		return validateTaxonomy(taxonomy)
	}

	var official struct {
		Version    string         `json:"version"`
		Intents    []officialNode `json:"intents"`
		Techniques []officialNode `json:"techniques"`
		Evasions   []officialNode `json:"evasions"`
		Inputs     []officialNode `json:"inputs"`
	}
	if err := json.Unmarshal(data, &official); err != nil {
		return Taxonomy{}, fmt.Errorf("parsing taxonomy: %w", err)
	}
	taxonomy = Taxonomy{
		Version: official.Version,
		Source:  "https://github.com/Arcanum-Sec/arc_pi_taxonomy",
		License: "CC BY 4.0",
	}
	taxonomy.Categories = appendOfficial(taxonomy.Categories, AxisIntent, official.Intents)
	taxonomy.Categories = appendOfficial(taxonomy.Categories, AxisTechnique, official.Techniques)
	taxonomy.Categories = appendOfficial(taxonomy.Categories, AxisEvasion, official.Evasions)
	taxonomy.Categories = appendOfficial(taxonomy.Categories, AxisInput, official.Inputs)
	return validateTaxonomy(taxonomy)
}

type officialNode struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Delivery    string `json:"delivery"`
	Local       bool   `json:"local"`
}

func appendOfficial(categories []Category, axis Axis, nodes []officialNode) []Category {
	for _, node := range nodes {
		categories = append(categories, Category{
			ID:           node.Code,
			Name:         node.Title,
			Description:  node.Description,
			Axis:         axis,
			Delivery:     Delivery(node.Delivery),
			WhiteBoxOnly: node.Local,
			Source:       "Arcanum Prompt Injection Taxonomy",
		})
	}
	return categories
}

func validateTaxonomy(taxonomy Taxonomy) (Taxonomy, error) {
	if len(taxonomy.Categories) == 0 {
		return Taxonomy{}, fmt.Errorf("taxonomy contains no categories")
	}
	seen := map[string]bool{}
	for _, category := range taxonomy.Categories {
		if strings.TrimSpace(category.ID) == "" || strings.TrimSpace(category.Name) == "" {
			return Taxonomy{}, fmt.Errorf("taxonomy category is missing id or name")
		}
		if seen[category.ID] {
			return Taxonomy{}, fmt.Errorf("duplicate taxonomy category %q", category.ID)
		}
		seen[category.ID] = true
	}
	return taxonomy, nil
}

// ByID returns one category.
func (t Taxonomy) ByID(id string) (Category, bool) {
	for _, category := range t.Categories {
		if category.ID == id {
			return category, true
		}
	}
	return Category{}, false
}

// Applicable filters white-box-only categories from black-box engagements.
func (t Taxonomy) Applicable(mode TargetMode) []Category {
	out := make([]Category, 0, len(t.Categories))
	for _, category := range t.Categories {
		if mode == TargetBlackBox && category.WhiteBoxOnly {
			continue
		}
		out = append(out, category)
	}
	return out
}

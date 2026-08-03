// Package differential compares two firmware metadata reports and scores the
// changes for privacy and security relevance. It works entirely on the
// defensive metadata produced by the firmware package.
package differential

import (
	"sort"

	"github.com/acevenen/sentinel/reverso/internal/firmware"
)

// ComponentChange describes an SBOM entry that changed between versions.
type ComponentChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	Kind       string `json:"kind"` // added | removed | changed
}

// Diff is the scored comparison of two firmware reports.
type Diff struct {
	EntropyDelta       float64           `json:"entropy_delta"`
	ComponentChanges   []ComponentChange `json:"component_changes"`
	NewKeyMarkers      int               `json:"new_key_markers"`
	NewInsecureFlags   []string          `json:"new_insecure_flags"`
	RemovedInsecure    []string          `json:"removed_insecure_flags"`
	RelevanceScore     int               `json:"relevance_score"`
	RelevanceRationale []string          `json:"relevance_rationale"`
}

// Compare diffs old vs new and computes a 0-100 relevance score.
func Compare(oldR, newR firmware.Report) Diff {
	d := Diff{EntropyDelta: newR.Entropy - oldR.Entropy}

	oldComp := indexComponents(oldR.SBOM)
	newComp := indexComponents(newR.SBOM)
	for name, nv := range newComp {
		if ov, ok := oldComp[name]; !ok {
			d.ComponentChanges = append(d.ComponentChanges, ComponentChange{Name: name, NewVersion: nv, Kind: "added"})
		} else if ov != nv {
			d.ComponentChanges = append(d.ComponentChanges, ComponentChange{Name: name, OldVersion: ov, NewVersion: nv, Kind: "changed"})
		}
	}
	for name, ov := range oldComp {
		if _, ok := newComp[name]; !ok {
			d.ComponentChanges = append(d.ComponentChanges, ComponentChange{Name: name, OldVersion: ov, Kind: "removed"})
		}
	}
	sort.Slice(d.ComponentChanges, func(i, j int) bool {
		return d.ComponentChanges[i].Name < d.ComponentChanges[j].Name
	})

	if n := len(newR.KeyMarkers) - len(oldR.KeyMarkers); n > 0 {
		d.NewKeyMarkers = n
	}

	oldFlags := indexFlags(oldR.Insecure)
	newFlags := indexFlags(newR.Insecure)
	for id := range newFlags {
		if _, ok := oldFlags[id]; !ok {
			d.NewInsecureFlags = append(d.NewInsecureFlags, id)
		}
	}
	for id := range oldFlags {
		if _, ok := newFlags[id]; !ok {
			d.RemovedInsecure = append(d.RemovedInsecure, id)
		}
	}
	sort.Strings(d.NewInsecureFlags)
	sort.Strings(d.RemovedInsecure)

	d.score()
	return d
}

func (d *Diff) score() {
	score := 0
	var why []string
	for _, c := range d.ComponentChanges {
		switch c.Kind {
		case "changed":
			score += 10
			why = append(why, "component "+c.Name+" version changed")
		case "added":
			score += 8
			why = append(why, "component "+c.Name+" added")
		case "removed":
			score += 6
			why = append(why, "component "+c.Name+" removed")
		}
	}
	if d.NewKeyMarkers > 0 {
		score += 20
		why = append(why, "new key or certificate material appeared")
	}
	if len(d.NewInsecureFlags) > 0 {
		score += 25
		why = append(why, "new insecure configuration flags appeared")
	}
	if len(d.RemovedInsecure) > 0 {
		why = append(why, "previously insecure configuration flags were removed")
	}
	if score > 100 {
		score = 100
	}
	d.RelevanceScore = score
	d.RelevanceRationale = why
}

func indexComponents(cs []firmware.Component) map[string]string {
	m := map[string]string{}
	for _, c := range cs {
		m[c.Name] = c.Version
	}
	return m
}

func indexFlags(fs []firmware.InsecureFlag) map[string]struct{} {
	m := map[string]struct{}{}
	for _, f := range fs {
		m[f.ID] = struct{}{}
	}
	return m
}

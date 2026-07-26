package ctf

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/methodology"
)

func fixtureManifest() Manifest {
	return Manifest{
		Platform: "Local", Event: "Sentinel lab", PolicyURL: "https://example.invalid/rules",
		Rules: Rules{AutomationAllowed: true, MaxRequestsPerSec: 2, MaxConcurrency: 1, IntrusiveAllowed: true},
		Challenges: []Challenge{{
			ID: "lab-echo", Name: "Echo", Scope: authz.NewScope([]string{"http://127.0.0.1:4010"}, nil),
		}},
	}
}

func TestEngagementRequiresRulesAttestation(t *testing.T) {
	manifest := fixtureManifest()
	if _, err := manifest.Engagement("lab-echo", "tester", false); err == nil {
		t.Fatal("CTF engagement accepted unreviewed rules")
	}
	record, err := manifest.Engagement("lab-echo", "tester", true)
	if err != nil {
		t.Fatal(err)
	}
	if record.Mode != "ctf" || record.AutomationProhibited || !record.ExploitAuthorized {
		t.Fatalf("engagement = %+v", record)
	}
}

func TestScoreAndHistory(t *testing.T) {
	start := time.Now().Add(-time.Minute)
	card, err := Score(fixtureManifest(), RunRecord{
		StartedAt: start, FinishedAt: start.Add(time.Minute),
		Stages:   []methodology.Stage{methodology.StageRecon},
		Tools:    []string{"nmap", "nmap"},
		Outcomes: []Outcome{{ChallengeID: "lab-echo", Attempted: true, Solved: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if card.SolveRate != 1 || len(card.Tools) != 1 || len(card.CoverageGaps) != len(methodology.DefaultDefinitions)-1 {
		t.Fatalf("scorecard = %+v", card)
	}
	if err := AppendHistory(filepath.Join(t.TempDir(), "history.jsonl"), card); err != nil {
		t.Fatal(err)
	}
}

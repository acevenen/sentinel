package methodology

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/acevenen/sentinel/internal/knowledge"
	"github.com/acevenen/sentinel/internal/tools"
)

type fakeRunner struct{}

func (fakeRunner) Run(_ context.Context, stage Stage, _ RunState) ([]tools.Finding, error) {
	return []tools.Finding{{ID: string(stage), Title: "stage finding"}}, nil
}

func TestWorkflowOrderAndPersistence(t *testing.T) {
	workflow := Workflow{Runner: fakeRunner{}}
	state := RunState{EngagementID: "lab-1"}
	var err error
	state, err = workflow.RunStage(context.Background(), state, StageRecon)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.ProposedNext, []Stage{StageApplicationMapping}) {
		t.Fatalf("ProposedNext = %v", state.ProposedNext)
	}
	if _, err := workflow.RunStage(context.Background(), state, StageCloudSSRF); err == nil {
		t.Fatal("workflow accepted an out-of-order stage")
	}

	store := FileStateStore{Dir: filepath.Join(t.TempDir(), "state")}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load("lab-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("loaded state = %#v, want %#v", loaded, state)
	}
}

func TestSuggestParameters(t *testing.T) {
	suggestions := SuggestParameters([]string{"id", "callback"})
	want := []TestingSuggestion{
		{Parameter: "id", Class: knowledge.ClassIDOR, Tool: "manual-assist", Manual: true},
		{Parameter: "id", Class: knowledge.ClassSQLI, Tool: "sqlmap", Manual: true},
		{Parameter: "callback", Class: knowledge.ClassSSRF, Tool: "ssrf-metadata-catalog", Manual: true},
		{Parameter: "callback", Class: knowledge.ClassXSS, Tool: "knowledge-catalog", Manual: true},
	}
	if !reflect.DeepEqual(suggestions, want) {
		t.Fatalf("SuggestParameters() = %#v, want %#v", suggestions, want)
	}
}

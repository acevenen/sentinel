package simulator

import "testing"

func TestReplayNeverEmits(t *testing.T) {
	tr := Trace{
		Name: "lab", Synthetic: true,
		Messages: []Message{
			{Seq: 1, ID: "0x100", Kind: "request", Length: 8},
			{Seq: 2, ID: "0x101", Kind: "response", Length: 8},
		},
	}
	res := Replay(tr)
	if res.Emitted {
		t.Fatal("Replay must never emit to any target")
	}
	if res.Messages != 2 {
		t.Fatalf("messages = %d, want 2", res.Messages)
	}
}

func TestReplayStateMachine(t *testing.T) {
	tr := Trace{Messages: []Message{
		{Kind: "request", Length: 1},
		{Kind: "response", Length: 1},
		{Kind: "reset", Length: 0},
	}}
	res := Replay(tr)
	// idle -> awaiting_response -> idle -> idle(reset keeps idle) : 3 distinct states recorded
	want := []string{"idle", "awaiting_response", "idle"}
	if len(res.StateSequence) != len(want) {
		t.Fatalf("state sequence = %v, want %v", res.StateSequence, want)
	}
}

func TestReplayFlagsParseErrors(t *testing.T) {
	tr := Trace{Messages: []Message{
		{Kind: "request", Length: -1},
		{Kind: "data", Length: 0, Payload: "deadbeef"},
	}}
	res := Replay(tr)
	if len(res.ParseErrors) != 2 {
		t.Fatalf("parse errors = %v, want 2", res.ParseErrors)
	}
}

func TestLoadTrace(t *testing.T) {
	data := []byte(`{"name":"t","synthetic":true,"messages":[{"seq":1,"kind":"request","length":8}]}`)
	tr, err := LoadTrace(data)
	if err != nil {
		t.Fatalf("LoadTrace: %v", err)
	}
	if len(tr.Messages) != 1 || !tr.Synthetic {
		t.Fatalf("trace = %+v", tr)
	}
}

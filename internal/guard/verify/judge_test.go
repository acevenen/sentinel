package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantVerdict string
		wantSkipped bool
	}{
		{"clean match", `{"verdict":"match","confidence":0.9,"reason":"on task"}`, "match", false},
		{"clean deviation", `{"verdict":"deviation","confidence":0.8,"reason":"extra host"}`, "deviation", false},
		{"markdown fenced", "```json\n{\"verdict\":\"match\",\"confidence\":0.7,\"reason\":\"ok\"}\n```", "match", false},
		{"prose around object", `Here is my answer: {"verdict":"deviation","confidence":1,"reason":"x"} done.`, "deviation", false},
		{"uppercase verdict", `{"verdict":"MATCH","confidence":0.5,"reason":"x"}`, "match", false},
		{"malformed json fails closed", `{"verdict": }`, "deviation", false},
		{"truncated fails closed", `{"verdict":"match","confi`, "deviation", false},
		{"no json object fails closed", `I cannot answer that.`, "deviation", false},
		{"unknown verdict fails closed", `{"verdict":"maybe","confidence":0.5,"reason":"x"}`, "deviation", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := ParseVerdict(tt.raw)
			if v.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", v.Verdict, tt.wantVerdict)
			}
			if v.Skipped != tt.wantSkipped {
				t.Errorf("skipped = %v, want %v", v.Skipped, tt.wantSkipped)
			}
		})
	}
}

func TestParseVerdictClampsConfidence(t *testing.T) {
	if v := ParseVerdict(`{"verdict":"match","confidence":5,"reason":"x"}`); v.Confidence != 1 {
		t.Errorf("confidence = %v, want clamped to 1", v.Confidence)
	}
	if v := ParseVerdict(`{"verdict":"match","confidence":-2,"reason":"x"}`); v.Confidence != 0 {
		t.Errorf("confidence = %v, want clamped to 0", v.Confidence)
	}
}

// mockCompleter returns a canned response or error.
type mockCompleter struct {
	resp       string
	err        error
	lastSystem string
	lastUser   string
	callCount  int
}

func (m *mockCompleter) Complete(ctx context.Context, system, user string) (string, error) {
	m.callCount++
	m.lastSystem = system
	m.lastUser = user
	return m.resp, m.err
}

func TestLLMJudgeEvaluate(t *testing.T) {
	mock := &mockCompleter{resp: `{"verdict":"deviation","confidence":0.95,"reason":"posts secrets"}`}
	judge := NewLLMJudge(mock, "test-model")

	v := judge.Evaluate(context.Background(), intent.Intent{ActionType: "summarize", Target: "README", ExpectedEffect: "post summary"}, Action{Type: "network", Target: "x"})
	if !v.IsDeviation() {
		t.Errorf("expected deviation, got %+v", v)
	}
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call, got %d", mock.callCount)
	}
}

func TestLLMJudgeIsIsolated(t *testing.T) {
	// The judge must send ONLY the declared intent and the proposed action —
	// never any agent conversation. Verify the payload contains the action but
	// no smuggled conversation field.
	mock := &mockCompleter{resp: `{"verdict":"match","confidence":0.9,"reason":"ok"}`}
	judge := NewLLMJudge(mock, "test-model")
	judge.Evaluate(context.Background(),
		intent.Intent{ActionType: "summarize", Target: "README", ExpectedEffect: "post summary"},
		Action{Type: "write", Target: "docs/x.md", Description: "write summary"})

	for _, want := range []string{"declared_intent", "proposed_action", "docs/x.md"} {
		if !strings.Contains(mock.lastUser, want) {
			t.Errorf("judge payload missing %q: %s", want, mock.lastUser)
		}
	}
	if strings.Contains(mock.lastUser, "conversation") || strings.Contains(mock.lastUser, "agent_reasoning") {
		t.Errorf("judge payload leaked conversation context: %s", mock.lastUser)
	}
	// The system prompt must establish the isolated-judge framing.
	if !strings.Contains(mock.lastSystem, "isolated") {
		t.Errorf("judge system prompt is not the isolated-judge prompt: %s", mock.lastSystem)
	}
}

func TestLLMJudgeFailsClosedOnAPIError(t *testing.T) {
	mock := &mockCompleter{err: errors.New("network down")}
	judge := NewLLMJudge(mock, "test-model")
	v := judge.Evaluate(context.Background(), intent.Intent{ActionType: "x", Target: "y", ExpectedEffect: "z"}, Action{Type: "network", Target: "x"})
	if !v.IsDeviation() {
		t.Errorf("expected fail-closed deviation on API error, got %+v", v)
	}
}

func TestSkippedVerdictIsNonBlocking(t *testing.T) {
	v := SkippedVerdict("no key")
	if v.IsDeviation() {
		t.Error("skipped verdict must not count as a deviation")
	}
	if !v.Skipped {
		t.Error("skipped flag not set")
	}
}

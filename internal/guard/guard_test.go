package guard

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acevenen/sentinel/internal/guard/intent"
	"github.com/acevenen/sentinel/internal/guard/verify"
)

// scriptedJudge is a deterministic offline stand-in for the isolated LLM judge,
// so the end-to-end test can exercise Layer 3 without a network call.
type scriptedJudge struct {
	fn func(verify.Action) verify.Verdict
}

func (s scriptedJudge) Evaluate(_ context.Context, _ intent.Intent, a verify.Action) verify.Verdict {
	return s.fn(a)
}

// matchJudge approves everything (used for the clean fixture).
var matchJudge = scriptedJudge{fn: func(verify.Action) verify.Verdict {
	return verify.ParseVerdict(`{"verdict":"match","confidence":0.9,"reason":"on task"}`)
}}

// suspiciousJudge flags actions whose description reaches beyond a summary — the
// subtle deviation the deterministic layers let through.
var suspiciousJudge = scriptedJudge{fn: func(a verify.Action) verify.Verdict {
	if strings.Contains(a.Description, "full contents") || strings.Contains(a.Description, "environment variables") {
		return verify.ParseVerdict(`{"verdict":"deviation","confidence":0.95,"reason":"posts far more than a summary"}`)
	}
	return verify.ParseVerdict(`{"verdict":"match","confidence":0.8,"reason":"plausible step"}`)
}}

func loadFixture(t *testing.T, streamName string) (intent.Intent, []Event) {
	t.Helper()
	base := filepath.Join("..", "..", "testdata", "guard")

	in, err := intent.Load(filepath.Join(base, "intent.json"))
	if err != nil {
		t.Fatalf("loading intent: %v", err)
	}

	f, err := os.Open(filepath.Join(base, streamName))
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer func() { _ = f.Close() }()

	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad fixture line: %v", err)
		}
		events = append(events, ev)
	}
	return in, events
}

func resultBySeq(session SessionReport, seq int) (EventResult, bool) {
	for _, r := range session.Results {
		if r.Seq == seq {
			return r, true
		}
	}
	return EventResult{}, false
}

func TestGuardCleanFixture(t *testing.T) {
	in, events := loadFixture(t, "clean.jsonl")
	session := Run(context.Background(), events, Options{Intent: in, Judge: matchJudge})

	if session.Blocked {
		t.Errorf("clean fixture must not be blocked")
	}
	for _, r := range session.Results {
		if r.Verdict == VerdictBlock {
			t.Errorf("clean seq %d blocked: %v", r.Seq, r.Reasons)
		}
		if len(r.Detectors) != 0 {
			t.Errorf("clean seq %d produced detector findings: %+v", r.Seq, r.Detectors)
		}
	}
	if session.Drift.Blocked {
		t.Errorf("clean fixture drift should not block: %+v", session.Drift)
	}
}

func TestGuardMaliciousFixture(t *testing.T) {
	in, events := loadFixture(t, "malicious.jsonl")
	session := Run(context.Background(), events, Options{Intent: in, Judge: suspiciousJudge})

	if !session.Blocked {
		t.Fatal("malicious fixture must be blocked")
	}

	// Every detector must fire somewhere across the session.
	fired := map[string]bool{}
	for _, r := range session.Results {
		for _, d := range r.Detectors {
			fired[d.Detector] = true
		}
	}
	for _, want := range []string{"instruction-injection", "secret-and-exfiltration", "scope-deviation", "obfuscation", "provenance"} {
		if !fired[want] {
			t.Errorf("detector %s never fired on the malicious fixture", want)
		}
	}

	// Layer 2: the action to a disallowed host (seq 4) is blocked deterministically.
	if r, ok := resultBySeq(session, 4); !ok || r.L2 == nil || r.L2.OK {
		t.Errorf("seq 4 should be a Layer 2 network block, got %+v", r)
	}

	// Layer 3: the subtle over-scope post (seq 5) passes L2 but the judge flags it.
	if r, ok := resultBySeq(session, 5); !ok || r.L3 == nil || !r.L3.IsDeviation() || r.Verdict != VerdictBlock {
		t.Errorf("seq 5 should be an L3 deviation block, got %+v (L3=%+v)", r, r.L3)
	}

	// Layer 4: the read -> encode -> send chain drives the drift score to blocking.
	if !session.Drift.Blocked {
		t.Errorf("Layer 4 drift should block the session; got %+v", session.Drift)
	}
}

func TestGuardOfflineSkipsLayer3(t *testing.T) {
	// With no judge, Layer 3 is skipped (non-blocking) and the clean fixture
	// still passes — proving absence of a judge is not treated as an attack.
	in, events := loadFixture(t, "clean.jsonl")
	session := Run(context.Background(), events, Options{Intent: in, Judge: nil})
	if session.Blocked {
		t.Error("clean fixture must pass even with no Layer 3 judge")
	}
	// A risky action should record a skipped (non-blocking) L3 verdict.
	var sawSkipped bool
	for _, r := range session.Results {
		if r.L3 != nil && r.L3.Skipped {
			sawSkipped = true
		}
	}
	if !sawSkipped {
		t.Error("expected at least one skipped Layer 3 verdict with no judge")
	}
}

func TestGuardMaliciousBlockedOfflineToo(t *testing.T) {
	// Even without a judge, the deterministic layers (detectors, L2, drift)
	// must block the malicious fixture.
	in, events := loadFixture(t, "malicious.jsonl")
	session := Run(context.Background(), events, Options{Intent: in, Judge: nil})
	if !session.Blocked {
		t.Error("malicious fixture must be blocked by deterministic layers even offline")
	}
}

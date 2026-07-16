package verify

import (
	"testing"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

func driftIntent() intent.Intent {
	return intent.Intent{
		ActionType:     "summarize",
		Target:         "README",
		ExpectedEffect: "post summary",
		AllowedNetwork: []string{"hooks.slack.com"},
	}
}

func TestDriftFullExfilSignatureBlocks(t *testing.T) {
	// The classic chain: read a secret, encode it, send it out. Each action
	// passes its own layer; the cumulative pattern must block.
	d := NewDrift(driftIntent())
	d.ObserveAction(Action{Type: "read", Target: ".env"})
	d.ObserveAction(Action{Type: "exec", Target: "base64 /tmp/data > /tmp/data.b64"})
	d.ObserveAction(Action{Type: "network", Target: "https://hooks.slack.com/services/x", Network: []string{"hooks.slack.com"}})

	rep := d.Report()
	if !rep.Blocked {
		t.Errorf("full exfil signature should block; score=%.2f signals=%v", rep.Score, rep.Signals)
	}
	if rep.Score != 1.0 {
		t.Errorf("score = %.2f, want 1.0", rep.Score)
	}
	if len(rep.Signals) != 3 {
		t.Errorf("expected 3 signals, got %v", rep.Signals)
	}
}

func TestDriftLoneOutboundIsClean(t *testing.T) {
	// A single legitimate outbound post is normal and must not block or read as
	// a partial exfiltration signature.
	d := NewDrift(driftIntent())
	d.ObserveAction(Action{Type: "network", Target: "https://hooks.slack.com/services/x", Network: []string{"hooks.slack.com"}})

	rep := d.Report()
	if rep.Blocked {
		t.Error("lone outbound should not block")
	}
	if rep.Headline != "no cross-step drift detected" {
		t.Errorf("unexpected headline for lone outbound: %q", rep.Headline)
	}
}

func TestDriftPartialSignatureFlagsButDoesNotBlock(t *testing.T) {
	d := NewDrift(driftIntent())
	d.ObserveAction(Action{Type: "read", Target: ".env"})                                                               // secret access
	d.ObserveAction(Action{Type: "network", Target: "https://hooks.slack.com/x", Network: []string{"hooks.slack.com"}}) // outbound

	rep := d.Report()
	if rep.Blocked {
		t.Error("two-of-three signals should not block")
	}
	if rep.Score == 0 {
		t.Error("expected non-zero score for partial signature")
	}
}

func TestDriftObserveDetectorSignals(t *testing.T) {
	d := NewDrift(driftIntent())
	d.ObserveDetector("secret-and-exfiltration")
	d.ObserveDetector("obfuscation")
	d.ObserveAction(Action{Type: "network", Target: "https://hooks.slack.com/x", Network: []string{"hooks.slack.com"}})

	rep := d.Report()
	if !rep.Blocked {
		t.Errorf("detector-sourced signals plus outbound should complete the signature; got score %.2f", rep.Score)
	}
}

func TestDriftNoSignalsIsClean(t *testing.T) {
	d := NewDrift(driftIntent())
	d.ObserveAction(Action{Type: "write", Target: "docs/x.md"})
	d.ObserveAction(Action{Type: "read", Target: "README.md"})

	rep := d.Report()
	if rep.Score != 0 || rep.Blocked {
		t.Errorf("benign actions should produce zero drift; got score %.2f", rep.Score)
	}
}

package verify

import (
	"sort"

	"github.com/acevenen/sentinel/internal/guard/intent"
)

// Drift is Layer 4: a session-level accumulator. Each consequential action can
// look clean in isolation and still form a dangerous pattern in aggregate — the
// classic case being read-secret → encode → send-outbound, where every step
// passes Layers 2 and 3 on its own. Drift watches the whole run for that
// signature and emits a session drift score at the end.
type Drift struct {
	intent  intent.Intent
	signals map[string]bool
	notes   map[string]string
}

// The three signals whose co-occurrence forms the exfiltration signature.
const (
	signalSecretAccess = "secret-access"
	signalObfuscation  = "obfuscation"
	signalOutbound     = "outbound-network"
)

// NewDrift builds a session accumulator scoped to a declared intent.
func NewDrift(in intent.Intent) *Drift {
	return &Drift{
		intent:  in,
		signals: map[string]bool{},
		notes:   map[string]string{},
	}
}

// ObserveAction folds one proposed action into the session signals.
func (d *Drift) ObserveAction(a Action) {
	if isSensitivePath(a.Target) {
		d.set(signalSecretAccess, "action touched a secret path: "+a.Target)
	}
	if isEncodeCommand(a) {
		d.set(signalObfuscation, "action encoded/obfuscated data: "+a.Target)
	}
	if a.Type == "network" || a.Type == "push" || len(hostsIn(a)) > 0 {
		d.set(signalOutbound, "action sent data outbound: "+a.Target)
	}
}

// ObserveDetector folds a detector name that fired on a tool output into the
// session signals, so obfuscation and secret references seen in retrieved
// content also contribute to drift.
func (d *Drift) ObserveDetector(detector string) {
	switch detector {
	case "secret-and-exfiltration":
		d.set(signalSecretAccess, "an exfiltration detector fired on tool output")
	case "obfuscation":
		d.set(signalObfuscation, "an obfuscation detector fired on tool output")
	}
}

func (d *Drift) set(signal, note string) {
	d.signals[signal] = true
	if _, ok := d.notes[signal]; !ok {
		d.notes[signal] = note
	}
}

// DriftReport is the end-of-session drift summary.
type DriftReport struct {
	Score    float64  // 0.0–1.0: fraction of the exfil signature present
	Signals  []string // signals observed, sorted
	Notes    []string // one note per observed signal
	Blocked  bool     // true when the full signature is present
	Headline string
}

// driftBlockThreshold is the score at or above which the session is blocked.
const driftBlockThreshold = 1.0

// Report computes the session drift score. All three signals present means the
// full read → encode → send signature occurred across the run.
func (d *Drift) Report() DriftReport {
	all := []string{signalSecretAccess, signalObfuscation, signalOutbound}
	var present []string
	var notes []string
	for _, s := range all {
		if d.signals[s] {
			present = append(present, s)
			notes = append(notes, d.notes[s])
		}
	}
	sort.Strings(present)
	sort.Strings(notes)

	score := float64(len(present)) / float64(len(all))
	rep := DriftReport{
		Score:   score,
		Signals: present,
		Notes:   notes,
		Blocked: score >= driftBlockThreshold,
	}
	// A lone outbound signal is normal for any networked task; the exfiltration
	// concern only arises once secret access is part of the pattern.
	switch {
	case rep.Blocked:
		rep.Headline = "session exhibits the full read -> encode -> send exfiltration signature across otherwise-clean steps"
	case d.signals[signalSecretAccess] && len(present) > 1:
		rep.Headline = "partial exfiltration signature observed (secret access plus another signal); no single step was blocking"
	default:
		rep.Headline = "no cross-step drift detected"
	}
	return rep
}

// isEncodeCommand reports whether an exec action encodes or compresses data —
// a common step in disguising exfiltrated content.
func isEncodeCommand(a Action) bool {
	if a.Type != "exec" {
		return false
	}
	return encodeCmd.MatchString(a.Target)
}

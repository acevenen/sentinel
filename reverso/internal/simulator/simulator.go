// Package simulator replays sanitized traces inside a software-only model. It
// never touches a physical target and uses synthetic identities and keys. It is
// for testing parsers and state machines, not for emitting to any real bus:
// nothing here opens a device, a socket, or a hardware interface.
package simulator

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Message is one sanitized frame from a trace. Fields are generic so it can
// model CAN-like or protocol frames without carrying real identities.
type Message struct {
	Seq     int    `json:"seq"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Length  int    `json:"length"`
	Payload string `json:"payload,omitempty"` // hex or opaque token; may be synthetic
}

// Trace is a sanitized capture prepared for replay.
type Trace struct {
	Name      string    `json:"name"`
	Synthetic bool      `json:"synthetic"`
	Messages  []Message `json:"messages"`
}

// Result is the outcome of a software-only replay.
type Result struct {
	Name          string         `json:"name"`
	Messages      int            `json:"messages"`
	KindCounts    map[string]int `json:"kind_counts"`
	ParseErrors   []string       `json:"parse_errors"`
	StateSequence []string       `json:"state_sequence"`
	Emitted       bool           `json:"emitted"` // always false: replay never emits
}

// LoadTrace parses a sanitized trace JSON document.
func LoadTrace(data []byte) (Trace, error) {
	var tr Trace
	if err := json.Unmarshal(data, &tr); err != nil {
		return Trace{}, fmt.Errorf("parsing trace: %w", err)
	}
	return tr, nil
}

// Replay runs the trace through a minimal state machine that validates message
// structure. It performs no I/O and never emits; Result.Emitted is always
// false, which the tests assert.
func Replay(tr Trace) Result {
	res := Result{
		Name:       tr.Name,
		KindCounts: map[string]int{},
		Emitted:    false,
	}
	state := "idle"
	res.StateSequence = append(res.StateSequence, state)
	for i, m := range tr.Messages {
		res.Messages++
		res.KindCounts[m.Kind]++
		if m.Length < 0 {
			res.ParseErrors = append(res.ParseErrors, fmt.Sprintf("message %d has negative length", i))
			continue
		}
		if m.Payload != "" && m.Length == 0 {
			res.ParseErrors = append(res.ParseErrors, fmt.Sprintf("message %d has a payload but zero length", i))
		}
		next := transition(state, m.Kind)
		if next != state {
			state = next
			res.StateSequence = append(res.StateSequence, state)
		}
	}
	return res
}

// transition is a trivial illustrative state machine over message kinds.
func transition(state, kind string) string {
	switch kind {
	case "request":
		return "awaiting_response"
	case "response":
		if state == "awaiting_response" {
			return "idle"
		}
		return "desync"
	case "reset":
		return "idle"
	default:
		return state
	}
}

// SortedKinds returns the message kinds seen, sorted, for stable reporting.
func (r Result) SortedKinds() []string {
	out := make([]string, 0, len(r.KindCounts))
	for k := range r.KindCounts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

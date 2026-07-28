package spotter

import (
	"fmt"
	"strings"
)

// HUDState is what the glasses should be showing. The client renders state;
// it never decides state, so display logic cannot drift from policy.
type HUDState string

const (
	HUDSearching    HUDState = "searching"    // nothing acquired yet
	HUDAmbiguous    HUDState = "ambiguous"    // candidates disagree; show the conflict
	HUDProbable     HUDState = "probable"     // named, one evidence class
	HUDConfirmed    HUDState = "confirmed"    // named, corroborated
	HUDUnenrolled   HUDState = "unenrolled"   // recognized a class, but not the operator's device
	HUDUnauthorized HUDState = "unauthorized" // probing refused by policy
)

// HUDCard is the stable contract the glasses client consumes. It is
// deliberately flat, pre-formatted, and free of scores the wearer cannot act
// on: the HUD shows a band and a next action, never raw bits.
type HUDCard struct {
	State HUDState `json:"state"`

	// Line1..Line3 are pre-truncated for a narrow monocular display, in
	// priority order. A client that can only fit one line renders Line1.
	Line1 string `json:"line1"`
	Line2 string `json:"line2,omitempty"`
	Line3 string `json:"line3,omitempty"`

	// Accent drives the reticle color: ok | watch | warn | alert.
	Accent string `json:"accent"`

	Confidence string `json:"confidence"`          // band, in words
	RiskBand   string `json:"risk_band,omitempty"` // none | low | medium | high | critical
	Concerns   int    `json:"concerns"`

	// NextAction is the single most worthwhile thing to do, phrased for a
	// non-expert. It is what the wearer hears when they ask "what do I do?".
	NextAction string `json:"next_action,omitempty"`

	// Speech is the spoken form: one breath, no jargon, no numbers to read.
	Speech string `json:"speech"`

	// Detail is the progressive-disclosure payload, shown only on request.
	Detail *Assessment `json:"detail,omitempty"`

	// Notice always carries the corpus provenance so a wearer is never shown
	// illustrative data as though it were authoritative.
	Notice string `json:"notice,omitempty"`
}

// accentFor maps a risk band to a reticle color token.
func accentFor(band string) string {
	switch band {
	case "critical", "high":
		return "alert"
	case "medium":
		return "warn"
	case "low":
		return "watch"
	default:
		return "ok"
	}
}

// truncate keeps HUD lines inside a narrow field of view without splitting a
// word, so text never overflows the display.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	if i := strings.LastIndex(cut, " "); i > max/2 {
		cut = cut[:i]
	}
	return strings.TrimSpace(cut) + "…"
}

// ToHUD projects an assessment into the glasses contract.
//
// enrolled reports whether this device is one the operator has claimed. An
// unenrolled device is shown as a class only ("a camera") with no vendor,
// model, or advisory — looking at someone else's hardware must not produce a
// reconnaissance report.
func ToHUD(a Assessment, enrolled bool) HUDCard {
	id := a.Device.Identity

	if !id.Named() {
		if id.Band == BandAmbiguous && id.Best != nil {
			return HUDCard{
				State:      HUDAmbiguous,
				Line1:      "Not sure yet",
				Line2:      truncate(id.Reason, 64),
				Accent:     "watch",
				Confidence: string(id.Band),
				Speech:     "I can see it, but the evidence does not agree yet. Get closer, or let me check the network.",
				Notice:     a.DataNotice,
			}
		}
		return HUDCard{
			State:      HUDSearching,
			Line1:      "Looking…",
			Accent:     "ok",
			Confidence: string(BandUnknown),
			Speech:     "I do not recognize this one yet.",
			Notice:     a.DataNotice,
		}
	}

	category := id.Best.Category
	if category == "" {
		category = "device"
	}

	// Unenrolled: acknowledge the class, withhold the intelligence.
	if !enrolled {
		return HUDCard{
			State:      HUDUnenrolled,
			Line1:      "A " + category,
			Line2:      "Not in your devices",
			Line3:      "Add it to assess",
			Accent:     "watch",
			Confidence: string(id.Band),
			Speech: fmt.Sprintf(
				"That looks like a %s, but it is not one of your devices. Add it to your inventory and I will check it.", category),
			Notice: a.DataNotice,
		}
	}

	card := HUDCard{
		State:      HUDConfirmed,
		Line1:      truncate(id.Best.Vendor+" "+id.Best.Family, 40),
		Accent:     accentFor(a.RiskBand),
		Confidence: string(id.Band),
		RiskBand:   a.RiskBand,
		Concerns:   len(a.Concerns),
		Notice:     a.DataNotice,
	}
	if id.Band == BandProbable {
		card.State = HUDProbable
	}

	switch {
	case len(a.Concerns) == 0:
		card.Line2 = "Nothing known against it"
		card.Speech = fmt.Sprintf("That is a %s %s. Nothing known against it in my corpus.",
			id.Best.Vendor, id.Best.Family)
	default:
		exploited := 0
		for _, c := range a.Concerns {
			if c.KnownExploited {
				exploited++
			}
		}
		if exploited > 0 {
			card.Line2 = fmt.Sprintf("%d issues · %d actively exploited", len(a.Concerns), exploited)
		} else {
			card.Line2 = fmt.Sprintf("%d known issues", len(a.Concerns))
		}
		if len(a.Plan) > 0 {
			card.NextAction = a.Plan[0].Do
			card.Line3 = truncate(a.Plan[0].Do, 52)
		}

		spoken := fmt.Sprintf("That is a %s %s.", id.Best.Vendor, id.Best.Family)
		if exploited > 0 {
			spoken += fmt.Sprintf(" %d known issues, and %s already being exploited in the wild.",
				len(a.Concerns), pluralIs(exploited))
		} else {
			spoken += fmt.Sprintf(" %d known issues.", len(a.Concerns))
		}
		if card.NextAction != "" {
			spoken += " " + strings.TrimSuffix(card.NextAction, ".") + "."
		}
		card.Speech = spoken
	}

	if id.Band == BandProbable {
		card.Line2 = strings.TrimSpace(card.Line2)
		card.Speech = "Probably. " + card.Speech
	}
	return card
}

// pluralIs renders "one is" / "N are" for spoken output.
func pluralIs(n int) string {
	if n == 1 {
		return "one is"
	}
	return fmt.Sprintf("%d are", n)
}

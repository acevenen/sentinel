package spotter

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/acevenen/sentinel/internal/knowledge"
)

// Fusion thresholds, in bits. These govern the promise that a single sensor
// can never produce a confirmed identity.
const (
	// minBits is the floor below which nothing is named at all.
	minBits = 4.0
	// minMargin is how far the leader must be clear of the runner-up before we
	// stop calling the result ambiguous.
	minMargin = 2.0
	// confirmBits and confirmMargin are the additional bar for BandConfirmed,
	// which also requires two distinct evidence classes.
	confirmBits   = 9.0
	confirmMargin = 4.0
	// classCap bounds how much any single evidence class can contribute, so a
	// pile of correlated signals from one sensor cannot masquerade as proof.
	classCap = 8.0
)

// correlationDecay discounts the nth signal within one evidence class. The
// first counts fully, the second half, the third a quarter. Signals in a class
// share a failure mode, so repetition inside a class is weak corroboration.
func correlationDecay(rank int) float64 {
	d := 1.0
	for i := 0; i < rank; i++ {
		d /= 2
	}
	return d
}

// NormalizeMAC canonicalizes a hardware address to lowercase colon form.
// Device stickers, router UIs, and vendor tools all disagree on separators
// (aa:bb:cc, AA-BB-CC, aabb.ccdd), so comparing raw strings silently fails.
// It returns the input lowercased and trimmed when it is not a MAC.
func NormalizeMAC(value string) string {
	trimmed := strings.TrimSpace(value)
	if hw, err := net.ParseMAC(trimmed); err == nil {
		return hw.String()
	}
	return strings.ToLower(trimmed)
}

// normalizeValue prepares an observation value for comparison against corpus
// rules: MACs are canonicalized, everything else is lowercased and trimmed.
func normalizeValue(kind SignalKind, value string) string {
	if kind == SignalMACOUI {
		return NormalizeMAC(value)
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// ruleMatches applies one corpus rule to a normalized observation value.
func ruleMatches(rule knowledge.FingerprintRule, value string) bool {
	target := strings.ToLower(strings.TrimSpace(rule.Value))
	if target == "" || value == "" {
		return false
	}
	switch rule.Match {
	case knowledge.MatchExact:
		return value == target
	case knowledge.MatchPrefix:
		return strings.HasPrefix(value, target)
	case knowledge.MatchContains:
		return strings.Contains(value, target)
	default:
		return false
	}
}

// clampQuality keeps a caller-supplied quality inside [0,1]. An unset quality
// (zero) is treated as fully trusted so that hand-entered observations, the
// common case, do not silently score zero.
func clampQuality(q float64) float64 {
	switch {
	case q <= 0:
		return 1.0
	case q > 1:
		return 1.0
	default:
		return q
	}
}

// Fuse combines observations into a single confidence-scored identity.
//
// The algorithm is log-odds accumulation with two honesty constraints:
// correlated evidence inside one class suffers geometric decay and a hard cap,
// and the final band depends on the margin over the runner-up as well as the
// absolute score. A leader that is not clear of the field is reported as
// ambiguous rather than guessed, and BandConfirmed additionally requires
// corroboration from two distinct evidence classes.
func Fuse(observations []Observation, corpus []knowledge.DeviceFingerprint) Identity {
	if len(observations) == 0 {
		return Identity{Band: BandUnknown, Reason: "no observations supplied"}
	}

	candidates := make([]Candidate, 0, len(corpus))
	for _, device := range corpus {
		// perClass collects every hit in a class so it can be ranked and
		// discounted; a class's total is capped afterwards.
		perClass := map[EvidenceClass][]Evidence{}

		for _, obs := range observations {
			value := normalizeValue(obs.Kind, obs.Value)
			quality := clampQuality(obs.Quality)
			for _, rule := range device.Rules {
				if SignalKind(rule.Kind) != obs.Kind || !ruleMatches(rule, value) {
					continue
				}
				class := obs.Class()
				perClass[class] = append(perClass[class], Evidence{
					Kind:    obs.Kind,
					Class:   class,
					Matched: rule.Value,
					Bits:    rule.Bits,
					// EffectiveBits is filled in after ranking.
					EffectiveBits: rule.Bits * quality,
					Why: fmt.Sprintf("%s %q matched %s rule %q",
						obs.Kind, obs.Value, device.Vendor, rule.Value),
				})
			}
		}
		if len(perClass) == 0 {
			continue
		}

		var total float64
		var evidence []Evidence
		for _, hits := range perClass {
			// Strongest signal in the class counts first and fullest.
			sort.SliceStable(hits, func(i, j int) bool {
				return hits[i].EffectiveBits > hits[j].EffectiveBits
			})
			var classTotal float64
			for rank := range hits {
				hits[rank].EffectiveBits *= correlationDecay(rank)
				classTotal += hits[rank].EffectiveBits
			}
			if classTotal > classCap {
				// Scale the class back proportionally so the reported evidence
				// still sums to the score that was actually used.
				scale := classCap / classTotal
				for rank := range hits {
					hits[rank].EffectiveBits *= scale
				}
				classTotal = classCap
			}
			total += classTotal
			evidence = append(evidence, hits...)
		}

		sort.SliceStable(evidence, func(i, j int) bool {
			return evidence[i].EffectiveBits > evidence[j].EffectiveBits
		})
		candidates = append(candidates, Candidate{
			FingerprintID: device.ID,
			Vendor:        device.Vendor,
			Family:        device.Family,
			Category:      device.Category,
			Score:         total,
			Evidence:      evidence,
		})
	}

	if len(candidates) == 0 {
		return Identity{Band: BandUnknown, Reason: "no corpus rule matched any observation"}
	}

	// Deterministic ordering: score first, then fingerprint ID so equal scores
	// never depend on map iteration order.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].FingerprintID < candidates[j].FingerprintID
	})

	best := candidates[0]
	margin := best.Score
	if len(candidates) > 1 {
		margin = best.Score - candidates[1].Score
	}

	classes := best.Classes()
	classNames := make([]string, 0, len(classes))
	for _, c := range classes {
		classNames = append(classNames, string(c))
	}
	sort.Strings(classNames)

	runners := candidates[1:]
	if len(runners) > 2 {
		runners = runners[:2]
	}

	identity := Identity{
		Best:          &best,
		Runners:       runners,
		Margin:        margin,
		Corroborating: classNames,
	}

	switch {
	case best.Score < minBits:
		identity.Band = BandUnknown
		identity.Best = nil
		identity.Reason = fmt.Sprintf(
			"strongest match scored %.1f bits, below the %.1f-bit floor to name a device",
			best.Score, minBits)
	case margin < minMargin:
		identity.Band = BandAmbiguous
		identity.Reason = fmt.Sprintf(
			"%s and %s are within %.1f bits of each other; evidence does not separate them",
			best.Vendor, candidates[1].Vendor, margin)
	case best.Score >= confirmBits && margin >= confirmMargin && len(classes) >= 2:
		identity.Band = BandConfirmed
		identity.Reason = fmt.Sprintf(
			"%.1f bits from %d independent evidence classes (%s), %.1f bits clear of the next candidate",
			best.Score, len(classes), strings.Join(classNames, "+"), margin)
	default:
		identity.Band = BandProbable
		if len(classes) < 2 {
			identity.Reason = fmt.Sprintf(
				"%.1f bits but only one evidence class (%s); corroborate on a second channel to confirm",
				best.Score, strings.Join(classNames, "+"))
		} else {
			identity.Reason = fmt.Sprintf(
				"%.1f bits across %s, %.1f bits clear of the next candidate",
				best.Score, strings.Join(classNames, "+"), margin)
		}
	}
	return identity
}

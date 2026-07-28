package spotter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/acevenen/sentinel/internal/knowledge"
)

// Exposure is how reachable the device actually is. It is the difference
// between a theoretical weakness and a practical one: the same advisory on an
// internet-exposed camera and on an isolated VLAN are not the same problem.
type Exposure string

const (
	ExposureInternet Exposure = "internet" // reachable from outside the network
	ExposureLAN      Exposure = "lan"      // reachable by anything on the LAN
	ExposureIsolated Exposure = "isolated" // segmented onto its own VLAN/network
	ExposureUnknown  Exposure = "unknown"  // not established
)

// exposureFactor scales advisory severity by real reachability. Unknown is
// deliberately pessimistic — it scores as LAN, never as isolated, so an
// unestablished exposure never flatters the result.
func exposureFactor(e Exposure) float64 {
	switch e {
	case ExposureInternet:
		return 1.0
	case ExposureIsolated:
		return 0.35
	case ExposureLAN, ExposureUnknown:
		return 0.65
	default:
		return 0.65
	}
}

// Device is everything known about the thing in front of the operator.
type Device struct {
	Identity     Identity `json:"identity"`
	MAC          string   `json:"mac,omitempty"`
	Address      string   `json:"address,omitempty"`
	Firmware     string   `json:"firmware,omitempty"`
	Exposure     Exposure `json:"exposure"`
	DefaultCreds bool     `json:"default_credentials_suspected,omitempty"`
}

// Concern is one advisory as it applies to this specific device, with the risk
// actually posed here rather than the advisory's context-free severity.
type Concern struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	CWE            string   `json:"cwe,omitempty"`
	CVSS           float64  `json:"cvss"`
	Risk           float64  `json:"risk"`
	Severity       string   `json:"severity"`
	KnownExploited bool     `json:"known_exploited"`
	Confidence     string   `json:"confidence"`
	Why            string   `json:"why"`
	Source         string   `json:"source,omitempty"`
	Actions        []Action `json:"actions,omitempty"`
}

// Action is one plain-language step, ranked so the first thing on the list is
// the most worthwhile thing to do next.
type Action struct {
	Do       string   `json:"do"`
	Tag      string   `json:"tag,omitempty"`
	Effort   string   `json:"effort"`
	Removes  float64  `json:"removes"`
	Priority float64  `json:"priority"`
	ForIDs   []string `json:"for,omitempty"`
}

// Assessment is the complete answer for one device.
type Assessment struct {
	Device     Device    `json:"device"`
	Concerns   []Concern `json:"concerns"`
	Plan       []Action  `json:"plan"`
	RiskScore  float64   `json:"risk_score"`
	RiskBand   string    `json:"risk_band"`
	Headline   string    `json:"headline"`
	DataNotice string    `json:"data_notice"`
	DataSource string    `json:"data_source,omitempty"`
}

// effortWeight converts an effort label into a ranking divisor. Cheap wins
// rank above expensive ones of equal benefit.
func effortWeight(effort string) float64 {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "low":
		return 1.0
	case "medium":
		return 1.6
	case "high":
		return 2.6
	default:
		return 1.6
	}
}

// severityBand converts a 0..10 risk score into a word a person can act on.
func severityBand(risk float64) string {
	switch {
	case risk >= 9:
		return "critical"
	case risk >= 7:
		return "high"
	case risk >= 4:
		return "medium"
	case risk > 0:
		return "low"
	default:
		return "none"
	}
}

// appliesTo reports whether an advisory covers this device family. An advisory
// with vendor "*" is hygiene guidance that applies to anything.
func appliesTo(a knowledge.Advisory, d Device) bool {
	if a.Vendor == "*" {
		return true
	}
	if !d.Identity.Named() {
		// Vendor-specific advisories are never attached to an unnamed device.
		return false
	}
	best := d.Identity.Best
	if !strings.EqualFold(a.Vendor, best.Vendor) {
		return false
	}
	return a.Family == "*" || a.Family == "" || strings.EqualFold(a.Family, best.Family)
}

// Assess correlates a device against the advisory corpus, scores each concern
// by real exposure, and produces a ranked remediation plan.
//
// It is a pure function over embedded data: no network call, no cloud, so it
// works air-gapped and produces identical output for identical input.
func Assess(device Device, advisories []knowledge.Advisory) Assessment {
	_, notice, source := knowledge.AdvisoryDatasetNotice()

	assessment := Assessment{
		Device:     device,
		DataNotice: notice,
		DataSource: source,
	}

	factor := exposureFactor(device.Exposure)

	for _, advisory := range advisories {
		if !appliesTo(advisory, device) {
			continue
		}
		// Hygiene entries are conditional on observed state rather than on a
		// version range.
		switch advisory.ID {
		case "SENTINEL-HYGIENE-DEFAULT-CREDS":
			if !device.DefaultCreds {
				continue
			}
		case "SENTINEL-HYGIENE-INTERNET-EXPOSED":
			if device.Exposure != ExposureInternet {
				continue
			}
		}

		confidence, why := advisoryConfidence(advisory, device)
		if confidence == "not-applicable" {
			continue
		}

		risk := advisory.CVSS
		if advisory.KnownExploited {
			// Known-exploited is the single strongest real-world signal: it
			// means working attack code is already circulating.
			risk += 2.0
		}
		if advisory.DefaultCredentials && device.DefaultCreds {
			risk += 1.5
		}
		risk *= factor
		// An advisory matched only because the firmware version is unknown
		// carries less weight than one matched against a known version.
		if confidence == "possible" {
			risk *= 0.75
		}
		if risk > 10 {
			risk = 10
		}
		if risk < 0 {
			risk = 0
		}

		concern := Concern{
			ID:             advisory.ID,
			Title:          advisory.Title,
			Summary:        advisory.Summary,
			CWE:            advisory.CWE,
			CVSS:           advisory.CVSS,
			Risk:           risk,
			Severity:       severityBand(risk),
			KnownExploited: advisory.KnownExploited,
			Confidence:     confidence,
			Why:            why,
			Source:         advisory.Source,
		}
		for _, step := range advisory.Remediation {
			if !actionIsRelevant(step.Tag, device) {
				continue
			}
			concern.Actions = append(concern.Actions, Action{
				Do:       step.Action,
				Tag:      step.Tag,
				Effort:   step.Effort,
				Removes:  step.Reduction,
				Priority: (risk * step.Reduction) / effortWeight(step.Effort),
				ForIDs:   []string{advisory.ID},
			})
		}
		assessment.Concerns = append(assessment.Concerns, concern)
	}

	sort.SliceStable(assessment.Concerns, func(i, j int) bool {
		if assessment.Concerns[i].Risk != assessment.Concerns[j].Risk {
			return assessment.Concerns[i].Risk > assessment.Concerns[j].Risk
		}
		return assessment.Concerns[i].ID < assessment.Concerns[j].ID
	})

	assessment.RiskScore = aggregateRisk(assessment.Concerns)
	assessment.RiskBand = severityBand(assessment.RiskScore)
	assessment.Plan = buildPlan(assessment.Concerns)
	assessment.Headline = headline(device, assessment)
	return assessment
}

// actionIsRelevant drops advice for a state the device is not actually in.
// Telling someone to remove a port-forward for a camera that was never exposed
// is noise, and noise is what makes people stop reading security advice.
func actionIsRelevant(tag string, d Device) bool {
	switch tag {
	case "remove-internet-exposure", "disable-upnp", "use-vpn-not-portforward":
		// Only meaningful when the device is actually reachable from outside,
		// or when we cannot tell — in which case keeping it is the safe call.
		return d.Exposure == ExposureInternet || d.Exposure == ExposureUnknown
	case "network-isolate":
		// Already segmented; nothing to do.
		return d.Exposure != ExposureIsolated
	default:
		return true
	}
}

// advisoryConfidence decides how strongly an advisory attaches to this device,
// and explains why in words the report can print verbatim.
func advisoryConfidence(a knowledge.Advisory, d Device) (string, string) {
	if a.Vendor == "*" {
		return "applies", "applies to any device in this state"
	}
	if a.VersionConfidence == "not-version-specific" {
		return "applies", "not tied to a firmware version"
	}
	if strings.TrimSpace(d.Firmware) == "" {
		// No firmware known: the advisory may or may not apply. Say so rather
		// than asserting it does.
		return "possible", "firmware version unknown, so this may already be patched — verify against the vendor advisory"
	}
	if VersionInRange(d.Firmware, a.Affected.Introduced, a.Affected.Fixed) {
		if strings.TrimSpace(a.Affected.Fixed) == "" {
			return "possible", fmt.Sprintf(
				"firmware %s is in an open-ended affected range; this corpus records no fixed release — verify against the vendor advisory", d.Firmware)
		}
		return "applies", fmt.Sprintf("firmware %s is below the fixed release %s", d.Firmware, a.Affected.Fixed)
	}
	return "not-applicable", ""
}

// aggregateRisk combines per-concern risk into one device score. It is not a
// sum — twenty medium issues are not worse than certain compromise — but the
// worst concern raised by the presence of others, so a device with several
// serious problems still scores above one with a single problem.
func aggregateRisk(concerns []Concern) float64 {
	if len(concerns) == 0 {
		return 0
	}
	worst := concerns[0].Risk
	remainder := 0.0
	for _, c := range concerns[1:] {
		remainder += c.Risk
	}
	// Each additional point of secondary risk adds a sharply diminishing
	// amount, capped so it can never exceed the worst single concern.
	bonus := remainder / (remainder + 10) * (10 - worst)
	total := worst + bonus
	if total > 10 {
		return 10
	}
	return total
}

// buildPlan merges the per-advisory actions into one deduplicated, ranked list.
// Identical advice arising from several advisories is collapsed and its
// priority combined, so "update the firmware" surfaces once, at the top.
func buildPlan(concerns []Concern) []Action {
	merged := map[string]*Action{}
	var order []string
	for _, concern := range concerns {
		for _, action := range concern.Actions {
			// Collapse on the canonical tag when the corpus supplies one, so
			// three phrasings of "stop exposing this to the internet" become a
			// single step. Untagged actions fall back to their exact text.
			key := strings.TrimSpace(action.Tag)
			if key == "" {
				key = "do:" + strings.ToLower(strings.TrimSpace(action.Do))
			}
			if existing, ok := merged[key]; ok {
				existing.Priority += action.Priority
				existing.ForIDs = append(existing.ForIDs, action.ForIDs...)
				if action.Removes > existing.Removes {
					existing.Removes = action.Removes
					// Keep the phrasing of the most effective variant, which is
					// usually the most specific and actionable wording.
					existing.Do = action.Do
					existing.Effort = action.Effort
				}
				continue
			}
			copied := action
			merged[key] = &copied
			order = append(order, key)
		}
	}
	plan := make([]Action, 0, len(order))
	for _, key := range order {
		plan = append(plan, *merged[key])
	}
	sort.SliceStable(plan, func(i, j int) bool {
		if plan[i].Priority != plan[j].Priority {
			return plan[i].Priority > plan[j].Priority
		}
		return plan[i].Do < plan[j].Do
	})
	return plan
}

// headline is the one sentence a person reads first.
func headline(device Device, a Assessment) string {
	name := "This device"
	if device.Identity.Named() {
		name = device.Identity.Best.Vendor + " " + device.Identity.Best.Family
	}
	if len(a.Concerns) == 0 {
		return fmt.Sprintf("%s: nothing known against it in this corpus.", name)
	}
	exploited := 0
	for _, c := range a.Concerns {
		if c.KnownExploited {
			exploited++
		}
	}
	if exploited > 0 {
		return fmt.Sprintf(
			"%s: %d known issue(s), %d with attack code already circulating. Start with: %s",
			name, len(a.Concerns), exploited, a.Plan[0].Do)
	}
	return fmt.Sprintf("%s: %d known issue(s). Start with: %s",
		name, len(a.Concerns), a.Plan[0].Do)
}

// Package spotter turns what an operator can see and passively learn about a
// device they own into a confidence-scored identity, the weaknesses that
// identity is known to carry, and a ranked list of what to actually do about
// them.
//
// Two properties define the package:
//
//   - Identity is fused, never asserted from one sensor. Every claim carries
//     the evidence that produced it and a confidence band, and a claim
//     supported by a single class of evidence can never reach the highest
//     band.
//   - Looking is passive; probing is not. Building an identity from operator
//     observations requires no authorization. Any operation that puts a packet
//     on the network is an active action that must pass internal/authz.
package spotter

import "time"

// SignalKind names one observable property of a device.
type SignalKind string

const (
	SignalLabelModel  SignalKind = "label-model"  // model text read off the device
	SignalLogo        SignalKind = "logo"         // vendor mark on the housing
	SignalFormFactor  SignalKind = "form-factor"  // dome, bullet, doorbell, sbc
	SignalMACOUI      SignalKind = "mac-oui"      // IEEE vendor prefix
	SignalHTTPServer  SignalKind = "http-server"  // HTTP Server header
	SignalHTTPRealm   SignalKind = "http-realm"   // WWW-Authenticate realm
	SignalTLSCN       SignalKind = "tls-cn"       // TLS certificate common name
	SignalUPnPModel   SignalKind = "upnp-model"   // UPnP/SSDP device descriptor
	SignalFirmware    SignalKind = "firmware"     // firmware version string
	SignalOperatorSet SignalKind = "operator-set" // operator stated it directly
)

// EvidenceClass groups signals that share a failure mode. Two signals in the
// same class are correlated — a vendor logo and a vendor model number both
// come from looking at the housing, so seeing both is not twice the proof.
// Corroboration is only counted across distinct classes.
type EvidenceClass string

const (
	ClassPhysical EvidenceClass = "physical"
	ClassL2       EvidenceClass = "l2"
	ClassHTTP     EvidenceClass = "http"
	ClassTLS      EvidenceClass = "tls"
	ClassUPnP     EvidenceClass = "upnp"
	ClassOperator EvidenceClass = "operator"
)

// classOf maps a signal to its evidence class.
func classOf(kind SignalKind) EvidenceClass {
	switch kind {
	case SignalLabelModel, SignalLogo, SignalFormFactor:
		return ClassPhysical
	case SignalMACOUI:
		return ClassL2
	case SignalHTTPServer, SignalHTTPRealm:
		return ClassHTTP
	case SignalTLSCN:
		return ClassTLS
	case SignalUPnPModel:
		return ClassUPnP
	default:
		return ClassOperator
	}
}

// Observation is one recorded signal about the device in front of the
// operator. Quality is the capture confidence in [0,1] — blurry label text
// read at an angle is a weaker observation than one typed in by hand.
type Observation struct {
	Kind       SignalKind `json:"kind"`
	Value      string     `json:"value"`
	Quality    float64    `json:"quality"`
	Sensor     string     `json:"sensor,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
}

// Class returns the evidence class this observation belongs to.
func (o Observation) Class() EvidenceClass { return classOf(o.Kind) }

// Evidence records one rule that fired, and how much it actually moved belief
// after quality and correlation discounts. Keeping both the authored and the
// effective weight makes the score auditable rather than a black box.
type Evidence struct {
	Kind          SignalKind    `json:"kind"`
	Class         EvidenceClass `json:"class"`
	Matched       string        `json:"matched"`
	Bits          float64       `json:"bits"`
	EffectiveBits float64       `json:"effective_bits"`
	Why           string        `json:"why"`
}

// Candidate is one device family that the evidence points at.
type Candidate struct {
	FingerprintID string     `json:"fingerprint_id"`
	Vendor        string     `json:"vendor"`
	Family        string     `json:"family"`
	Category      string     `json:"category"`
	Score         float64    `json:"score"`
	Evidence      []Evidence `json:"evidence"`
}

// Classes returns the distinct evidence classes supporting this candidate.
func (c Candidate) Classes() []EvidenceClass {
	seen := map[EvidenceClass]bool{}
	var out []EvidenceClass
	for _, e := range c.Evidence {
		if !seen[e.Class] {
			seen[e.Class] = true
			out = append(out, e.Class)
		}
	}
	return out
}

// Band is how much the identification can be trusted. The bands are ordered:
// a claim only reaches BandConfirmed with corroboration from two independent
// evidence classes, so no single sensor can produce a confirmed identity.
type Band string

const (
	BandUnknown   Band = "unknown"   // not enough evidence to name anything
	BandAmbiguous Band = "ambiguous" // two or more families fit about equally
	BandProbable  Band = "probable"  // one family leads, single class of evidence
	BandConfirmed Band = "confirmed" // one family leads, corroborated across classes
)

// Identity is the fused result: what the device is, how sure we are, and why.
type Identity struct {
	Band          Band        `json:"band"`
	Best          *Candidate  `json:"best,omitempty"`
	Runners       []Candidate `json:"runners,omitempty"`
	Margin        float64     `json:"margin"`
	Corroborating []string    `json:"corroborating_classes,omitempty"`
	Reason        string      `json:"reason"`
}

// Named reports whether the identity is specific enough to name a vendor.
func (i Identity) Named() bool {
	return i.Best != nil && (i.Band == BandProbable || i.Band == BandConfirmed)
}

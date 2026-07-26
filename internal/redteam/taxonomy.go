// Package redteam defines the shared prompt-injection taxonomy used by both
// authorized AI red-team checks and Sentinel's defensive guard.
package redteam

// Axis is one of the four Arcanum prompt-injection taxonomy dimensions.
type Axis string

const (
	AxisIntent    Axis = "attack-intent"
	AxisTechnique Axis = "attack-technique"
	AxisEvasion   Axis = "attack-evasion"
	AxisInput     Axis = "attack-input"
)

// Delivery distinguishes direct user probes from indirect untrusted content.
type Delivery string

const (
	DeliveryDirect   Delivery = "direct"
	DeliveryIndirect Delivery = "indirect"
)

// Category is a provenance-aware taxonomy entry. Probe content is deliberately
// operator-supplied and is not embedded in this model.
type Category struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Axis         Axis     `json:"axis"`
	Delivery     Delivery `json:"delivery"`
	WhiteBoxOnly bool     `json:"white_box_only,omitempty"`
	Source       string   `json:"source"`
}

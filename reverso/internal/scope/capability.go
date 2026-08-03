// Package scope is REVerso's mandatory authorization boundary. Every analysis
// capability must be checked against a signed, unexpired authorization manifest
// before any work begins. The package fails closed: when scope is missing,
// expired, unsigned, or ambiguous, the answer is always "deny".
package scope

import "sort"

// Capability is a named unit of work REVerso can be asked to perform. Manifests
// grant capabilities from the permitted set; a fixed set of capabilities is
// permanently prohibited and can never be granted by any manifest.
type Capability string

// Permitted analysis capabilities. These are the only capabilities a manifest
// may list under `permitted`. They are all defensive and observation-first.
const (
	// CapScopeManagement covers creating and verifying manifests. It is always
	// available so an operator can bootstrap authorization; it never touches an
	// artifact or target.
	CapScopeManagement Capability = "scope_management"
	// CapArtifactIngestion hashes and stores owner-supplied artifacts.
	CapArtifactIngestion Capability = "artifact_ingestion"
	// CapPassiveCaptureAnalysis analyzes owner-provided PCAP and passive bus
	// captures. It never transmits.
	CapPassiveCaptureAnalysis Capability = "passive_capture_analysis"
	// CapFirmwareMetadataAnalysis inspects firmware format, partitions, strings
	// and a software bill of materials. Metadata only; never a bypass recipe.
	CapFirmwareMetadataAnalysis Capability = "firmware_metadata_analysis"
	// CapBinaryAnalysis builds call graphs and locates trust decisions at a
	// defensive level. It never patches verification logic.
	CapBinaryAnalysis Capability = "binary_analysis"
	// CapProtocolInference clusters message types and infers fields from passive
	// captures. It never emits active commands.
	CapProtocolInference Capability = "protocol_inference"
	// CapTrustMapping maps roots of trust and key references without extracting
	// private material.
	CapTrustMapping Capability = "trust_mapping"
	// CapDifferentialAnalysis compares two firmware images, traces or configs.
	CapDifferentialAnalysis Capability = "differential_analysis"
	// CapSimulation replays sanitized traces inside a software-only model using
	// synthetic identities and keys.
	CapSimulation Capability = "simulation"
	// CapReportGeneration renders reports separating observation, inference and
	// speculation.
	CapReportGeneration Capability = "report_generation"

	// CapSimulatorMessageEmit emits a message inside the software simulator. It
	// is a guarded capability: it requires the simulator asset type, explicit
	// approval and a lab-only profile. It never reaches a physical bus.
	CapSimulatorMessageEmit Capability = "simulator_message_emit"
)

// Permanently prohibited capabilities. No manifest, approval, asset type or
// operator can enable these. They encode REVerso's hard mission limits: it is
// not an exploit autopilot. Requesting one is always refused with a stable,
// auditable reason.
const (
	// ProdKeyExtraction: reconstructing or operationalizing private production
	// keys.
	ProdKeyExtraction Capability = "production_key_extraction"
	// CredentialRecovery: recovering credentials, tokens or secrets belonging to
	// third parties.
	CredentialRecovery Capability = "credential_recovery"
	// SecureBootBypass: bypassing secure boot or code-signing on an operational
	// system.
	SecureBootBypass Capability = "secure_boot_bypass"
	// GatewayAuthBypass: defeating gateway authentication.
	GatewayAuthBypass Capability = "gateway_auth_bypass"
	// EntitlementCircumvention: circumventing paid-feature entitlements.
	EntitlementCircumvention Capability = "entitlement_circumvention"
	// SafetyCommandInjection: command-injection tooling for braking, steering,
	// propulsion, airbags, battery protection or driver-assistance systems.
	SafetyCommandInjection Capability = "safety_command_injection"
	// SafetyDomainTesting: any testing against a safety-critical domain.
	SafetyDomainTesting Capability = "safety_domain_testing"
	// StealthPersistence: creating stealth persistence.
	StealthPersistence Capability = "stealth_persistence"
	// MonitoringTamper: disabling monitoring or forensic evidence.
	MonitoringTamper Capability = "monitoring_tamper"
	// OutOfScopeAnalysis: analyzing systems outside the authorization manifest.
	OutOfScopeAnalysis Capability = "out_of_scope_analysis"
	// PublicRoadOperation: operating on public-road vehicles.
	PublicRoadOperation Capability = "public_road_operation"
	// ActiveVehicleBusTransmission: sending a message on a real vehicle network.
	// Emitting inside the simulator is a different, guarded capability.
	ActiveVehicleBusTransmission Capability = "active_vehicle_bus_transmission"
)

var permittedSet = map[Capability]struct{}{
	CapScopeManagement:          {},
	CapArtifactIngestion:        {},
	CapPassiveCaptureAnalysis:   {},
	CapFirmwareMetadataAnalysis: {},
	CapBinaryAnalysis:           {},
	CapProtocolInference:        {},
	CapTrustMapping:             {},
	CapDifferentialAnalysis:     {},
	CapSimulation:               {},
	CapReportGeneration:         {},
	CapSimulatorMessageEmit:     {},
}

var permanentlyProhibitedSet = map[Capability]struct{}{
	ProdKeyExtraction:            {},
	CredentialRecovery:           {},
	SecureBootBypass:             {},
	GatewayAuthBypass:            {},
	EntitlementCircumvention:     {},
	SafetyCommandInjection:       {},
	SafetyDomainTesting:          {},
	StealthPersistence:           {},
	MonitoringTamper:             {},
	OutOfScopeAnalysis:           {},
	PublicRoadOperation:          {},
	ActiveVehicleBusTransmission: {},
}

// guardedSet is the subset of permitted capabilities that require extra proof
// beyond a manifest grant: a matching asset type, explicit approval, and a
// lab-only profile. See Policy.Authorize for the enforcement.
var guardedSet = map[Capability]struct{}{
	CapSimulatorMessageEmit: {},
}

// IsPermanentlyProhibited reports whether c can never be granted.
func IsPermanentlyProhibited(c Capability) bool {
	_, ok := permanentlyProhibitedSet[c]
	return ok
}

// IsKnownPermitted reports whether c is a recognized grantable capability.
func IsKnownPermitted(c Capability) bool {
	_, ok := permittedSet[c]
	return ok
}

// IsGuarded reports whether c requires asset-type, approval and lab-only proof.
func IsGuarded(c Capability) bool {
	_, ok := guardedSet[c]
	return ok
}

// PermanentlyProhibited returns a sorted copy of the permanent deny-list, for
// display and documentation. Callers must not rely on it to make authorization
// decisions; use IsPermanentlyProhibited so the source of truth stays single.
func PermanentlyProhibited() []Capability {
	out := make([]Capability, 0, len(permanentlyProhibitedSet))
	for c := range permanentlyProhibitedSet {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Permittable returns a sorted copy of the grantable capability set.
func Permittable() []Capability {
	out := make([]Capability, 0, len(permittedSet))
	for c := range permittedSet {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

# REVerso

Authorization-first, observation-first reverse engineering for hardware and
software **you own or are explicitly authorized to assess**.

REVerso helps a researcher understand undocumented firmware, binaries, network
protocols and trust boundaries in order to produce transparent, reproducible
documentation for interoperability, defensive security, privacy analysis,
migration and self-hosting. It is **not** an exploit autopilot: it fails closed
without a signed authorization manifest and permanently refuses to extract
production keys, bypass secure boot, defeat gateway authentication, inject
safety-critical commands, or transmit on a real vehicle bus.

REVerso is a sibling to [Sentinel](../README.md); state-changing actions are
routed to Sentinel's policy engine for review.

## Safety model

- Analysis requires a current, signed, unexpired authorization manifest.
- A fixed set of capabilities is **permanently prohibited** and can never be
  granted by any manifest.
- Deny rules and permanent prohibitions always win; missing or unverifiable
  authorization fails closed.
- Every artifact is treated as hostile: never executed, size-capped, parsed
  defensively.
- Every decision — allowed or denied — is written to a signed, hash-chained,
  tamper-evident audit trail.
- Private key material is referenced, never extracted.
- State-changing actions require explicit human approval.

Read [docs/SAFETY.md](docs/SAFETY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
before use.

## Install and build

Requires Go 1.23+ (pure Go; no CGO — SQLite via `modernc.org/sqlite`).

```sh
make build      # produces ./reverso
./reverso version
```

## Quick start

```sh
# 1. Establish authorization (generates owner + audit keys, signs the manifest)
reverso scope init \
  --project-id demo-ecu \
  --owner researcher@example.test \
  --asset-id ecu-lab-01 --asset-type firmware_image \
  --ownership-evidence "purchased unit, receipt on file" \
  --permit artifact_ingestion,firmware_metadata_analysis,trust_mapping,report_generation \
  --expires-in 720h

reverso scope verify

# 2. Ingest an owner-supplied artifact into the immutable evidence store
reverso ingest ./firmware.bin

# 3. Defensive analysis (all authorization-gated and audited)
reverso firmware inspect ./firmware.bin
reverso trustmap build --format dot

# 4. Report and verify the audit trail
reverso report build --format markdown --out report.md
reverso audit verify
```

## Command map

| Area | Commands | Status |
|---|---|---|
| Authorization | `scope init`, `scope verify` | implemented |
| Evidence | `ingest`, `audit verify` | implemented |
| Firmware | `firmware inspect` | implemented (metadata, SBOM, key refs, insecure flags) |
| Binary | `binary map` | implemented (ELF sections/symbols, crypto & trust functions) |
| Protocol | `protocol infer` | passive classic-pcap summary; clustering is Milestone 2 |
| Trust | `trustmap build` | implemented (graph from ingested evidence) |
| Differential | `differential compare` | implemented (scored firmware diff) |
| Simulation | `simulate replay` | implemented (software-only; never emits) |
| Reporting | `report build` | Markdown / JSON / HTML |

## Authorization manifest

See [`schema/authorization.example.yaml`](schema/authorization.example.yaml).
Manifests are Ed25519-signed against the project owner key and carry a mandatory
expiry. The permanent deny-list is always enforced and cannot be waived.

## Test suite

```sh
make test        # go test ./...
make test-race   # with the race detector (matches CI)
make cover       # coverage summary
make lint        # golangci-lint + go vet
```

The suite includes the mandated refusal tests: scope expiry, scope mismatch,
forbidden target types, artifact hash integrity, refusal of prohibited
requests, the observation/inference distinction, no state-changing action
without approval, and no network transmission in passive mode.

## License

MIT. See [LICENSE](LICENSE).

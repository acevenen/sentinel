# REVerso safety and authorization

Read this before using REVerso. REVerso is for **defensive** reverse
engineering of systems you **own or are explicitly authorized to assess**. It is
built to fail closed and to refuse to become an exploit autopilot.

## Core principles (enforced, not aspirational)

1. **Authorization before analysis.** No signed, unexpired manifest → no work.
2. **Passive observation before active testing.** Analysis reads files; it does
   not probe live systems.
3. **Detached lab hardware before live systems.** Asset types are limited to
   detached lab hardware, firmware images, passive captures, and simulators.
4. **Simulation before physical execution.** The only bus-like emission path is
   the software simulator, and it is guarded.
5. **No production-secret extraction.** Private key material is referenced, not
   extracted.
6. **No safety-critical command injection.** Permanently prohibited.
7. **Reproducibility and evidence for every conclusion.** The confidence model
   separates observation, inference and speculation and cites evidence hashes.
8. **Human approval for every state-changing action.**
9. **Fail closed when scope is ambiguous.**
10. **Preserve an immutable audit trail.**

## Permanent prohibitions (never granted by any manifest)

REVerso refuses these regardless of manifest, approval, asset type, or operator:

- Extract, reconstruct or operationalize private production keys
- Recover third-party credentials, tokens or secrets
- Bypass secure boot or code signing on an operational system
- Defeat gateway authentication
- Generate command-injection tooling for braking, steering, propulsion,
  airbags, battery protection or driver-assistance systems
- Any safety-domain testing
- Circumvent paid-feature entitlements
- Create stealth persistence
- Disable monitoring or forensic evidence
- Analyze systems outside the authorization manifest
- Operate on public-road vehicles
- Transmit on a real vehicle network

`reverso` has **no command** that maps to any of these. Attempting one through
the policy layer returns `ErrPermanentlyProhibited`, which is checked before any
manifest logic.

## The authorization manifest

Manifests are signed with the project **owner key** (the trust anchor generated
at `scope init`) and carry a mandatory `expires_at`. The policy engine denies
when the manifest is missing, unverified, expired, prohibits the capability,
does not permit it, or targets the wrong asset type. See
`schema/authorization.example.yaml`.

```sh
reverso scope init \
  --project-id demo-ecu \
  --owner researcher@example.test \
  --asset-id ecu-lab-01 --asset-type firmware_image \
  --ownership-evidence "purchased unit, receipt on file" \
  --permit artifact_ingestion,firmware_metadata_analysis,trust_mapping,report_generation \
  --expires-in 720h

reverso scope verify
```

## State-changing actions

Any action that emits or mutates is state-changing and requires explicit human
approval. Such actions are submitted to the Sentinel bridge, which classifies
risk, requires out-of-band confirmation, re-authorizes through the policy (so a
confirmer cannot override a hard guard), and records the verdict. With no
confirmer configured, nothing state-changing is approved.

## The audit trail

Every decision — allowed or denied — is appended to a hash-chained,
Ed25519-signed log. Verify it any time:

```sh
reverso audit verify
```

Pin the **audit public key** printed at `scope init` somewhere outside the
workspace (a password manager, a second host). That lets you detect tampering
even if the local workspace key is also rewritten.

## Data handling

- Local-first; no artifact upload by default.
- Optional at-rest encryption of artifact blobs: `scope init --encrypt` with
  `REVERSO_PASSPHRASE` set (scrypt-derived AES-256-GCM key).
- Every artifact is treated as hostile: never executed, size-capped on read,
  parsed defensively.
- If a remote LLM path is ever enabled, detected secrets must be redacted first;
  analysis has a deterministic, non-LLM path by default.

## Reporting a concern

If you believe REVerso performed or enabled a prohibited action, stop, run
`reverso audit verify`, preserve the `.reverso/` workspace, and open an issue
with the audit output (redact anything sensitive).

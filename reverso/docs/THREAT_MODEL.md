# REVerso threat model

REVerso is an authorization-first assistant for **defensive** reverse
engineering of hardware and software the operator owns or is explicitly
authorized to assess. This document states what REVerso protects, who it
defends against, what it deliberately refuses to do, and where the residual
risks are. It reflects the code in this repository, not aspirations.

## 1. What we are protecting

| Asset | Why it matters |
|---|---|
| **Authorization integrity** | The signed manifest is the root of every decision. If it can be forged or silently widened, every downstream control fails. |
| **Evidence integrity** | Ingested artifacts and derived findings must be trustworthy and reproducible. Silent modification would poison analysis and disclosure. |
| **Audit trail integrity** | The immutable, signed log is the record of what was done and refused. It must be tamper-evident. |
| **Third-party secrets** | Private keys, credentials and tokens found *inside* evidence must never be extracted or operationalized. |
| **Physical/road safety** | Nothing REVerso does may lead to a command reaching a real vehicle bus or a safety-critical system. |
| **Owner secrets at rest** | Owner passphrases and private signing keys stored locally. |

## 2. Actors and trust boundaries

- **Operator (semi-trusted).** Owns the project, holds the owner signing key
  (the trust anchor) and approves state-changing actions. REVerso constrains
  even the operator: it will not perform a permanently prohibited action for
  anyone, and it records every decision so an operator's actions are auditable.
- **Hostile artifact (untrusted).** Firmware, binaries, captures and traces are
  treated as adversarial input. They may be malformed, enormous, or crafted to
  exploit a parser.
- **LLM provider (untrusted for control).** Any model may *suggest* next steps
  but never decides authorization, retargets work, or downgrades an action. A
  deterministic, non-LLM analysis path always exists.
- **Sentinel policy engine (trusted peer).** State-changing proposals are
  submitted to Sentinel for classification, review and human confirmation.
- **Local storage (semi-trusted).** Disk may be read by other local processes;
  hence owner-only permissions and optional at-rest encryption.

Trust boundaries crossed: file ingestion (hostile → store), manifest loading
(disk → policy), LLM calls (local → remote, redaction required), and the
Sentinel bridge (REVerso → external approval).

## 3. Primary threats and mitigations

### T1 — Forged or widened authorization
*Threat:* an attacker (or a careless edit) crafts a manifest that grants more
than the owner authorized, or points at a system nobody owns.
*Mitigations:* manifests are Ed25519-signed and verified against the owner
trust anchor (`internal/scope/signature.go`); strict YAML decoding rejects
unknown fields; `Validate` rejects unknown capabilities, bad asset types, and
any attempt to *permit* a permanently prohibited capability; the policy engine
fails closed on a missing, unverified, or expired manifest
(`internal/scope/policy.go`). Tests: `scope` package.

### T2 — Requesting a prohibited capability
*Threat:* a prompt, LLM, or manifest asks REVerso to extract a production key,
bypass secure boot, defeat gateway auth, inject a safety command, or transmit
on a real vehicle bus.
*Mitigations:* a fixed permanent-prohibition set is checked **before** any
manifest logic and can never be granted (`capability.go`,
`TestRefusesPermanentlyProhibited`). There is no CLI path that maps to a
prohibited capability. The only bus-like emission is a guarded
*simulator* capability requiring simulator asset type, lab-only profile, and
explicit approval.

### T3 — Tampering with the evidence store or audit trail
*Threat:* an attacker edits an artifact, a finding, or the audit log to hide or
fabricate activity.
*Mitigations:* artifact blobs are content-addressed and stored read-only, and
`Get`/`Exists` reject non-hex ids and re-hash on read (`evidence/blob.go`). The
audit log is a hash-chained JSONL where each record is Ed25519-signed; editing,
reordering, deleting a non-trailing record, or re-signing with another key
breaks `Verify` (`evidence/audit.go`, tamper tests). The SQLite `artifacts`
table is write-once and refuses conflicting inserts.
*Trailing truncation:* any prefix of a valid hash chain is itself valid, so
deleting the newest record(s) — or wiping the log — cannot be caught from the
file alone. REVerso mitigates this with an **external anchor**: `reverso audit
verify --save-anchor` records the head (count + head hash) for the operator to
store off-box, and `--anchor` later fails if the log was truncated below that
point (`evidence.CheckAnchor`, tests). Without an anchor, `audit verify` prints
an explicit warning.
*Residual risk:* the audit public key defaults to a copy in the workspace; an
attacker who rewrites both the log and that key could produce a self-consistent
forgery. Supply an externally-pinned key via `REVERSO_AUDIT_PUBKEY` or
`--audit-pubkey` (printed at `scope init`) to close this. The manifest owner
trust anchor (`owner.pub`) has the same local-trust property; external pinning
of it is a tracked follow-up.

### T4 — Malicious artifact exploiting a parser
*Threat:* crafted firmware/PCAP/ELF triggers a crash, resource exhaustion, or
code execution in a parser.
*Mitigations:* artifacts are never executed; reads are size-capped
(`DefaultMaxBytes`, `maxAnalysisBytes`) with explicit oversize errors rather
than silent truncation; parsers validate bounds (PCAP truncation detection,
ELF via stdlib `debug/elf`); analysis is designed to run with outbound network
disabled (`internal/netguard`). *Residual risk:* parser hardening beyond the
current bounds checks, and running workers inside resource-limited containers,
is part of the roadmap (see `workers/`).

### T5 — Exfiltration of secrets via the model or the network
*Threat:* a private key inside firmware is sent to a remote LLM, or passive
analysis unexpectedly transmits.
*Mitigations:* local-first by default; no artifact upload. Private key material
is recorded as a **redacted reference** (location only), never extracted into
findings (`firmware.Findings`, `TestInspectRedactsPrivateKeys`). Passive mode
uses a fail-closed dialer that refuses every connection
(`netguard`, `TestPassiveDialerBlocksHTTPClient`). *Residual risk:* redaction
before an *optional* remote model call is a required control that must be wired
in before any such call is enabled.

### T6 — Unapproved state-changing action
*Threat:* a workflow emits a message or mutates a target without a human in the
loop.
*Mitigations:* every state-changing action requires `Approved` at the policy
layer; the Sentinel bridge fails closed with no confirmer, classifies risk, and
re-authorizes through the policy after confirmation so a confirmer cannot
override a hard guard (`sentinelbridge`, its tests). Approvals and denials are
audited.

### T7 — Scope creep over time
*Threat:* an old authorization is reused long after it should have lapsed.
*Mitigations:* mandatory `expires_at`; expiry is checked on every authorization,
and an unparseable expiry is treated as expired (`Manifest.Expired`,
`TestExpiryBoundaryFailsClosed`).

## 4. Explicit non-goals (REVerso will not)

Extract or reconstruct production keys · recover third-party credentials ·
bypass secure boot or code signing on an operational system · defeat gateway
authentication · build command-injection tooling for braking/steering/
propulsion/airbags/battery/driver-assistance · circumvent entitlements · create
stealth persistence · disable monitoring or forensic evidence · analyze systems
outside the manifest · operate on public-road vehicles · transmit on any real
vehicle network. These are enforced as permanent prohibitions, not policy
defaults.

## 5. Assumptions

- The host OS enforces file permissions; the operator protects the owner and
  audit private keys and any encryption passphrase.
- The operator's ownership evidence is truthful; REVerso records it but cannot
  independently verify real-world ownership.
- Ed25519 and AES-256-GCM as provided by the Go standard library are sound.

## 6. Known residual risks (tracked)

1. The audit public key and the manifest owner trust anchor default to copies in
   the workspace; external pinning is supported for the audit key
   (`REVERSO_AUDIT_PUBKEY`) and is a follow-up for the owner key (T3).
2. Trailing truncation is only detected when the operator saves and later checks
   an external anchor; unanchored, it cannot be caught from the log alone (T3).
3. Parser sandboxing/containerization is not yet enforced by the tool; analysis
   reads are size- and match-capped but not yet run inside a resource-limited
   container (T4).
4. Redaction-before-remote-LLM is specified but must be implemented before any
   remote model path is enabled (T5).
5. At-rest encryption covers artifact blobs; the SQLite metadata DB is not yet
   encrypted.

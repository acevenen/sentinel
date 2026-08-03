# REVerso architecture

REVerso is a local-first, modular CLI. Trusted Go code makes every
authorization decision; analysis is deterministic and observation-first. This
document describes the modules that exist today (Milestone 1 plus several
Milestone 2/3 foundations) and how they fit together.

## Layering

```
                        ┌─────────────────────────────┐
   reverso CLI (cobra)  │ scope · ingest · firmware ·  │
   internal/cli         │ binary · protocol · trustmap │
                        │ differential · simulate ·    │
                        │ report · audit               │
                        └───────────────┬──────────────┘
                                        │ every command routes through
                                        ▼
                         ┌────────────────────────────┐
      Authorization      │  internal/scope (Policy)    │  fail-closed gate
                         │  manifest · signature ·     │
                         │  capability · policy        │
                         └───────────────┬────────────┘
                                         │ allowed?  audit either way
             ┌───────────────────────────┼───────────────────────────┐
             ▼                            ▼                           ▼
   ┌──────────────────┐        ┌───────────────────┐       ┌──────────────────┐
   │ internal/evidence │        │ analysis modules  │       │ internal/         │
   │  store (SQLite)   │        │ firmware, binmap, │       │ sentinelbridge    │
   │  blob (immutable) │        │ protocol,         │       │ (state-changing   │
   │  audit (signed)   │        │ differential,     │       │  review)          │
   │  crypto (AES-GCM) │        │ simulator, trustmap│      └──────────────────┘
   └──────────────────┘        │ confidence, report │
                               └───────────────────┘
```

## Modules (packages)

- **`internal/scope`** — the authorization core. `Manifest`/`Authorization`
  model the signed manifest; `Capability` defines the grantable set and the
  permanent-prohibition set; `signature.go` provides Ed25519 signing/verifying
  with an owner trust anchor; `Policy.Authorize` is the single fail-closed
  decision function every command calls.
- **`internal/evidence`** — the immutable evidence store. `Store` is the SQLite
  metadata/provenance DB (`schema.sql`, embedded); `BlobStore` is a
  content-addressed, write-once, read-only artifact store with optional
  AES-256-GCM at-rest encryption (`crypto.go`); `AuditLog` is the hash-chained,
  Ed25519-signed, tamper-evident trail.
- **`internal/ingest`** — hashes (SHA-256 + SHA-512), classifies by magic
  bytes, stores, and records provenance, never modifying the original. Ingestion
  is authorization-gated and audited.
- **`internal/confidence`** — the evidence model: every `Finding` keeps
  observation, inference and speculation distinct, with evidence ids,
  confidence, alternatives, a next safe test, and explicit prohibited next
  steps.
- **Analysis:** `internal/firmware` (defensive metadata, SBOM, key references,
  insecure-config flags), `internal/binmap` (ELF sections/symbols, crypto and
  trust-decision function location — read-only), `internal/protocol` (passive
  classic-pcap summary), `internal/differential` (scored firmware diff),
  `internal/simulator` (software-only trace replay that never emits),
  `internal/trustmap` (roots-of-trust graph that records key references without
  private material).
- **`internal/report`** — Markdown, JSON and HTML renderers that separate
  observation from inference and cite evidence hashes.
- **`internal/sentinelbridge`** — submits proposed state-changing actions for
  authorization, risk classification and out-of-band human confirmation, and
  records the verdict.
- **`internal/netguard`** — the passive-mode fail-closed dialer.

## Project workspace

`reverso scope init` creates `<dir>/.reverso/`:

```
.reverso/
  scope.yaml         signed authorization manifest
  config.json        project settings (encryption on/off)
  evidence.db        SQLite metadata + provenance
  blobs/             content-addressed, read-only artifact bytes
  audit.log          signed, hash-chained audit trail
  blob.salt          scrypt salt (only when --encrypt)
  keys/
    owner.key        Ed25519 owner private key (0600) — the trust anchor
    owner.pub        owner public key
    audit.key        Ed25519 audit signing key (0600)
    audit.pub        audit public key (pin this externally)
```

The whole `.reverso/` directory is git-ignored: it holds private keys, evidence,
and the audit trail.

## Control-flow invariants

1. No command touches an artifact or target before `Policy.Authorize` returns
   allowed.
2. Both allowed and denied decisions are written to the audit trail.
3. Analysis is deterministic and needs no network; an LLM, if ever added, only
   suggests and never decides.
4. State-changing actions require explicit human approval, routed through the
   Sentinel bridge.

## Suggested full stack (roadmap)

Go for CLI/orchestration/policy/collectors (implemented); Python workers for
heavier binary analysis and protocol inference in resource-limited, network-
disabled containers (see `workers/`); Next.js local dashboard; SQLite now,
PostgreSQL later; object storage for artifacts; optional, redaction-gated LLM
provider abstraction. See `MVP MILESTONES` in the project brief.

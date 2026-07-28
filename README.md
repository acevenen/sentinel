# Sentinel

Authorization-first defensive and security-testing operations in one Go CLI.

[![CI](https://github.com/acevenen/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/acevenen/sentinel/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Sentinel keeps its defensive core—AI-assisted code review, runtime agent guard,
and agent evaluation—and adds scope-locked security testing, a resumable bug
hunting methodology, a provenance-aware knowledge catalog, AI red teaming, and
human-reviewed orchestration.

The through-line is authorization: models and external tools can suggest or
observe, but trusted code decides what is allowed.

## Safety model

- Active actions require current `--authorized` consent and explicit scope.
- Deny rules always win; missing or unverifiable authorization fails closed.
- Intrusive tools require an attested engagement and per-action confirmation.
- Dry-run prints exact direct argv but still passes authorization.
- Active actions are written to a tamper-evident hash-chained audit log.
- Kill switch, program automation prohibitions, scope revocation, conservative
  rates, and granular Linux capabilities are enforced.
- AI red-team probe content is operator-supplied and approved; Sentinel embeds
  taxonomy metadata, not attack strings.
- Public bounty work stays human-directed. Automated/aggressive tests belong
  on the loopback lab or CTFs whose current rules permit them.

Read [Safety and authorization](docs/SAFETY.md) before enabling active tools.

## Install and develop

Passive features build anywhere Go 1.23+ runs:

```sh
go install github.com/acevenen/sentinel@latest
sentinel version
```

The security binaries run in the shared Kali Dev Container on macOS, Windows,
and Linux:

```sh
make bootstrap
make dev
make build
sentinel tools doctor
```

`make bootstrap` pins development tooling, downloads Go modules, and enables
the repository secret-scanning hook. `make fetch-knowledge` sparse-clones
permissively licensed SecLists, HUNT, and the full Arcanum taxonomy into
ignored `knowledge-data/`.

## Command map

| Area | Commands |
|---|---|
| Defense | `scan`, `guard`, `evaluate`, `serve`, `spot` |
| Authorized web/API | `hunt`, `recon`, `traffic`, `test` |
| High guardrail | `exploit`, `creds`, `wireless`, `se` |
| AI security | `ai-redteam`, `orchestrate` |
| Operations | `engagement`, `ctf`, `bounty`, `tools doctor` |

See the [command reference](docs/COMMANDS.md) for flags and examples.

## Device intelligence (Spotter)

Look at a device you own; learn what it is, how exposed it is, and what to do
about it. Identity is fused from what you can see and what the network already
tells you, so no single sensor can produce a confident answer, and risk is
scored by real reachability rather than raw CVSS.

```sh
sentinel spot --observe logo=hikvision --observe mac-oui=44:19:B6:11:22:33 \
    --observe http-server=Hikvision-Webs --exposure internet
```

Runs entirely offline against embedded corpora. `--format hud` emits the
contract a Meta Ray-Ban Display client renders. See [Spotter](docs/SPOTTER.md).

## Quick local dry-run

```sh
sentinel engagement create \
  --id local-lab \
  --name "Owned local target" \
  --authorization-ref "owner-approved" \
  --attest \
  --scope http://127.0.0.1:3000

sentinel recon http://127.0.0.1:3000 \
  --engagement local-lab \
  --authorized \
  --dry-run
```

The result contains the exact nmap argv and a hash-chained audit event; no
packet is sent. Remove `--dry-run` only inside the Kali environment and only
after reviewing scope and engagement rules.

## Defensive code review

```sh
export ANTHROPIC_API_KEY=...
sentinel scan ./path/to/repo --severity high --format sarif --out results.sarif
```

Scan configuration follows flags → `SENTINEL_*` environment →
`.sentinel.yaml` → defaults. The API key is read from the environment only.
Exit codes are `0` clean, `1` policy/finding gate, and `2` tool error.

## Shared prompt-injection model

The prompt-free, CC BY 4.0-attributed Arcanum taxonomy powers both:

- defensive `guard` detectors for forged turns, tool poisoning/spoofing,
  instruction-file injection, authority impersonation, evasion, and parameter
  smuggling;
- authorized `ai-redteam` suites whose probe content is supplied and reviewed
  by the operator, with black-box versus local/model-weight applicability.

Captured target content is scanned before it can influence the orchestrator.
Claude receives safe finding metadata only, proposes the next methodology
stage, and cannot execute, retarget, or downgrade an action.

## Reports

```sh
sentinel engagement report \
  --engagement local-lab \
  --format markdown \
  --out engagement.md
```

Markdown and JSON include scope, verified audit timeline, methodology stages,
normalized findings, evidence artifacts, CWE/OWASP tags, and remediation.
SARIF 2.1.0 maps findings into code-scanning-compatible results.

## Local labs and CI

```sh
make test
make lab-up
make test-integration
make lab-down
```

The Compose range publishes only on loopback and uses an internal Docker
network. Normal CI runs unit tests only and never contacts a lab or public
target. See [Labs, CTFs, and bounty operation](docs/LABS.md).

## Design and provenance

- [Architecture](docs/ARCHITECTURE.md)
- [Safety](docs/SAFETY.md)
- [Device intelligence (Spotter)](docs/SPOTTER.md)
- [Command reference](docs/COMMANDS.md)
- [Methodology](docs/METHODOLOGY.md)
- [Tool adapters](docs/TOOLS.md)
- [Guarded orchestration](docs/ORCHESTRATOR.md)
- [Knowledge sources and licenses](docs/SOURCES.md)
- [Cross-device development](docs/DEVELOPMENT.md)
- [Expansion changelog](docs/CHANGELOG-expansion.md)

Sentinel is MIT licensed. Adapted Arcanum taxonomy metadata remains attributed
under CC BY 4.0 as documented in [SOURCES.md](docs/SOURCES.md).

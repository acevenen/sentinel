# Sentinel current state

This document records the baseline at commit `90e7a2e` before the platform
expansion began. The repository is newer than the original expansion brief: it
already contains agent evaluation, authorized IDOR/BOLA hunting, HAR import,
and a local web UI in addition to static scanning and the runtime guard.

## Command surface

- `sentinel scan <path>` discovers and chunks source files, sends them to the
  Anthropic Messages API, normalizes CWE-tagged findings, and renders terminal,
  Markdown, JSON, or SARIF output.
- `sentinel guard` evaluates a declared intent and a JSONL event stream through
  deterministic content detectors, static action matching, an optional
  isolated LLM judge, and session-drift detection.
- `sentinel evaluate` runs embedded and operator-supplied attack scenarios
  against an agent manifest and produces a security score.
- `sentinel hunt` performs rate-limited, read-only differential IDOR/BOLA tests
  against targets declared in a program manifest. `sentinel hunt import`
  creates or extends that manifest from an operator-supplied HAR file.
- `sentinel serve` exposes the existing features through a loopback-only local
  web UI.
- `sentinel version` prints the build version.

The program uses Cobra, returns `0` for a clean run, `1` for a security finding
or blocked action, and `2` for an operational error.

## Package architecture and public interfaces

All implementation packages are under Go's `internal/` boundary; the stable
operator-facing interface is the CLI.

- `internal/scanner`: filesystem discovery, `.gitignore` handling, binary and
  size filtering, and line-aware chunking. Its main entry point is
  `scanner.Scan(scanner.Options)`.
- `internal/analyzer`: Anthropic client, bounded worker pool, retry/backoff,
  strict JSON parsing, and the normalized static-analysis `Finding` model.
  `analyzer.Client` and `analyzer.Analyzer.Run` are reused by both scanning and
  the guard's optional LLM judge.
- `internal/config`: scan configuration and precedence resolution.
- `internal/report`: terminal, Markdown, JSON, and SARIF formatters for scan,
  guard, evaluate, and hunt results.
- `internal/guard`: event-pipeline orchestration. Subpackages provide
  deterministic detectors (`detect`), the declared-intent schema (`intent`),
  and action matching, judging, and drift tracking (`verify`).
- `internal/evaluate`: agent manifest validation, authority/risk evaluation,
  embedded attack scenarios, and score calculation.
- `internal/hunt`: program manifests, a fail-closed host scope gate, a
  read-only/rate-limited HTTP client, HAR import, and the BOLA differential
  engine. This is the only existing active network-testing subsystem.
- `internal/webui`: a loopback HTTP server and embedded static UI assets.

`main.go` and the top-level `*_cmd.go` files own CLI wiring. Shared output and
judge construction live in `cli.go`.

## Configuration and secret handling

Scan configuration resolves in this order, highest precedence first:

1. explicitly set CLI flags;
2. `SENTINEL_*` environment variables;
3. `<scan-root>/.sentinel.yaml`;
4. compiled defaults.

`ANTHROPIC_API_KEY` is environment-only and is deliberately excluded from the
YAML schema. Hunt identity tokens are also environment-only: a program manifest
stores each variable name, never its value.

The scan defaults are terminal output, minimum severity `low`, concurrency
`4`, and model `claude-sonnet-4-5`.

## Existing safety boundaries

The runtime guard treats tool output as untrusted and checks action targets
against declared intent. Hunt independently implements a mandatory allow/deny
host gate, refuses write methods, limits responses to 8 MiB, paces requests,
and never persists identity tokens. These are important foundations, but there
is not yet one central authorization contract shared by all active adapters.

## Test and CI baseline

At the baseline:

- `go build ./...` passes with Go 1.26.3 on Darwin/arm64.
- `go test ./...` passes across analyzer, config, evaluate, guard, hunt,
  report, scanner, and web UI packages.
- Tests use mocked HTTP transports and `httptest`; normal unit tests do not
  contact external targets.
- CI runs `golangci-lint`, race-enabled unit tests with coverage, a build, and
  a version smoke test on pushes to `main` and pull requests.
- Local lint could not be executed at baseline because `golangci-lint` was not
  installed. The checked-in CI lint job remains the authoritative baseline,
  and Phase 0 bootstrap installs a pinned local copy.

Fixtures cover vulnerable source samples, guard event streams, evaluator
manifests/scenarios, hunt programs/HAR captures, and a local report server.


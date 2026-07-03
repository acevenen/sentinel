# Sentinel

**AI-powered defensive code review: scan any codebase for security vulnerabilities with Claude, straight from your terminal or CI.**

[![CI](https://github.com/acevenen/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/acevenen/sentinel/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Sentinel walks a directory, sends your source files to the Anthropic API for security-focused analysis, and produces a clean report — in your terminal, as markdown for a PR, as JSON, or as SARIF for GitHub Code Scanning. It detects SQL injection, XSS, hardcoded secrets, path traversal, insecure crypto, SSRF, command injection, auth flaws, and more. It is **strictly defensive**: it reports weaknesses and fixes, never exploit code.

## Demo

```console
$ sentinel scan ./testdata
sentinel: analyzing 3 files (3 chunks) with claude-sonnet-4-5, concurrency 4
sentinel: analyzed 3/3 chunks

Sentinel Security Scan
────────────────────────────────────────────────────────────

  Path      ./testdata
  Model     claude-sonnet-4-5
  Scanned   3 files (3 chunks) in 11.4s

  Severity summary
    CRITICAL  3
    HIGH      4
    MEDIUM    1
    LOW       0

CRITICAL (3)
────────────────────────────────────────────────────────────
  [CWE-89] SQL injection via string concatenation
  vuln.go:16
  User input from the query string is concatenated directly into a SQL
  statement, allowing an attacker to alter the query structure.
  fix: Use parameterized queries: db.Query("SELECT id, email FROM users WHERE username = ?", username)

  [CWE-78] Command injection in ping handler
  vuln.go:33
  The host parameter is interpolated into a shell command executed with
  sh -c, so shell metacharacters reach the shell unescaped.
  fix: Pass the host as a discrete argument to exec.Command("ping", "-c", "1", host) and validate it first.

  [CWE-95] Arbitrary code execution via eval
  app.js:16
  A user-supplied expression is passed to eval(), executing attacker
  controlled JavaScript.
  fix: Use a safe expression parser or JSON.parse for data; never eval user input.

HIGH (4)
────────────────────────────────────────────────────────────
  [CWE-798] Hardcoded AWS credentials
  app.js:4
  An AWS access key and secret are committed to source control.
  fix: Load credentials from the environment or an IAM role, and rotate the exposed key.
  ...
```

*(Representative output for the intentionally vulnerable files in [`testdata/`](testdata) — run `sentinel scan ./testdata` with your own API key to reproduce; exact findings vary slightly between runs because analysis is model-based.)*

## Install

**With Go:**

```bash
go install github.com/acevenen/sentinel@latest
```

**Prebuilt binaries** for Linux, macOS, and Windows (amd64/arm64) are on the [releases page](https://github.com/acevenen/sentinel/releases).

## Quickstart

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # never stored, read from env only
sentinel scan ./path/to/repo
```

Exit codes make Sentinel a natural CI gate:

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings at/above the threshold |
| `1` | Findings at or above `--severity` |
| `2` | Tool error (bad flags, missing API key, network failure) |

## Usage

```
sentinel scan <path> [flags]
sentinel version
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `terminal` | Output format: `terminal`, `markdown`, `json`, `sarif` |
| `--severity` | `low` | Minimum severity to report (and to trip exit code 1): `low`, `medium`, `high`, `critical` |
| `--out` | stdout | Write the report to a file |
| `--include` | all source | Only scan files matching these globs (e.g. `'**/*.go'`) |
| `--exclude` | none | Skip files matching these globs |
| `--concurrency` | `4` | Concurrent analysis requests |
| `--model` | `claude-sonnet-4-5` | Anthropic model to use |

Configuration precedence: **flags > `SENTINEL_*` env vars > `.sentinel.yaml` > defaults.** See [.sentinel.example.yaml](.sentinel.example.yaml). The API key comes from `ANTHROPIC_API_KEY` only and is never written to disk.

### Examples

```bash
# Markdown report for a PR comment, medium+ only
sentinel scan . --severity medium --format markdown --out report.md

# SARIF for GitHub Code Scanning
sentinel scan . --format sarif --out results.sarif

# Only Go and TypeScript, skip generated code
sentinel scan . --include '**/*.go' --include '**/*.ts' --exclude '**/generated/**'
```

## How it works

```
discovery ──▶ chunking ──▶ concurrent LLM analysis ──▶ structured findings ──▶ report
```

1. **File discovery** — walks the tree, respects the repo's `.gitignore`, skips `node_modules`/`vendor`/build output, filters to source extensions, and drops binaries (null-byte sniff) and oversized generated files.
2. **Chunking** — files larger than ~48 KB are split on line boundaries; every chunk carries its absolute line range, and the code is sent as a line-numbered listing so findings map back to exact `file:line` locations.
3. **Concurrent analysis** — a worker pool (semaphore-bounded, default 4) sends chunks to the Anthropic Messages API. A strict system prompt instructs Claude to return only a JSON array of findings with severity, CWE category, description, and remediation.
4. **Structured findings** — responses are parsed defensively: markdown fences and prose are stripped, malformed items are skipped, severities normalized, and line numbers clamped to the analyzed range. File paths are pinned to the scanned chunk, so the model can never report a phantom file.
5. **Report** — findings are sorted worst-first and rendered as colored terminal output, markdown, JSON, or SARIF 2.1.0.

### Architecture

```
sentinel/
├── main.go                 # CLI entrypoint (cobra): flags, exit codes, Ctrl+C
├── internal/
│   ├── scanner/            # File discovery, .gitignore, filtering, chunking
│   ├── analyzer/           # Anthropic client, worker pool, retry, JSON parsing
│   ├── report/             # terminal / markdown / json / sarif renderers
│   └── config/             # flags > env > .sentinel.yaml precedence
└── testdata/               # intentionally vulnerable demo files
```

**Worker pool & rate limiting.** The analyzer bounds concurrency with a buffered-channel semaphore — each in-flight request holds a slot, so at most `--concurrency` requests hit the API at once. Every request retries on `429`, `5xx`, and `529` with exponential backoff plus full jitter (500 ms base, 16 s cap), honoring the server's `Retry-After` header when present. `Ctrl+C` cancels the shared context: in-flight requests abort, queued chunks never start, and the scan exits cleanly. Individual chunk failures are reported as warnings without sinking the rest of the scan.

## CI integration

Use Sentinel as a PR security gate with GitHub Actions:

```yaml
name: Security scan
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - name: Install Sentinel
        run: go install github.com/acevenen/sentinel@latest
      - name: Scan (fail on high or critical)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: sentinel scan . --severity high --format sarif --out results.sarif
      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

The job fails (exit `1`) when Sentinel finds anything at or above the threshold, and the SARIF upload surfaces findings inline on the PR under the Security tab.

## Security posture

- **Defensive only.** The system prompt forbids exploit code, payloads, and attack strings; Sentinel reports weaknesses and remediations.
- **Your code is sent to the Anthropic API** for analysis. Don't scan repositories whose source may not leave your environment, and review [Anthropic's data usage policies](https://www.anthropic.com/legal/privacy) before scanning sensitive code.
- **The API key is never persisted.** It is read from `ANTHROPIC_API_KEY` at runtime and deliberately not readable from the config file.
- Findings are AI-generated: treat them as a strong reviewer's comments, not ground truth. Verify before acting.

## Development

```bash
go test ./... -race -cover   # unit tests (no network: the HTTP client is mocked)
go build -o sentinel .
golangci-lint run
```

## Roadmap

- **v2: cross-file data-flow analysis** — track tainted input across files/packages for fewer false negatives on multi-hop injection.
- **Next.js dashboard** — trend findings across scans, diff runs, and triage in a browser.
- **Dependency CVE lookup** — cross-check manifests (go.mod, package.json, requirements.txt) against vulnerability databases.

## License

[MIT](LICENSE)

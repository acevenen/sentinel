# REVerso analysis workers (roadmap)

The Go CLI performs deterministic, defensive analysis today (firmware metadata,
ELF mapping, passive PCAP summary, differential, simulator). Heavier binary
analysis and protocol inference are planned as **Python workers** invoked by the
Go orchestrator.

## Design constraints (non-negotiable)

Workers exist to analyze hostile artifacts safely, so they must:

- **Run with outbound network access disabled.** Passive analysis never
  transmits; the Go side already models this with `internal/netguard`.
- **Run in resource-limited containers.** CPU, memory, PID and wall-clock
  limits, read-only artifact mounts, no host filesystem access beyond the
  artifact and an output directory.
- **Never execute the artifact.** Parse and inspect only.
- **Return structured findings** that map onto `internal/confidence.Finding`,
  keeping observation separate from inference, with evidence ids and a next
  safe test.
- **Never emit generated code that runs automatically.** Any generated decoder
  or harness is written out for human review, not executed.

## Planned workers

| Worker | Purpose | Milestone |
|---|---|---|
| `binary-cfg` | Call graphs, parser/crypto/trust-boundary discovery beyond symbol names | 2 |
| `protocol-cluster` | Message clustering, field/counter/checksum inference from passive captures | 2 |
| `fs-extract` | Read-only extraction of embedded filesystems (squashfs, jffs2) for metadata | 2 |
| `automotive-passive` | Passive CAN/automotive-bus field inference from owner-provided captures | 3 |

## Interface (planned)

The orchestrator will pass a worker: the artifact blob path (read-only), the
project id, and the authorized capability. The worker returns JSON findings on
stdout. The Go side validates the capability first and audits the result. No
worker receives the network, the private keys, or write access to the evidence
store.

# Command reference

Run `sentinel <command> --help` for complete flags.

| Command | Purpose | Network / consent |
|---|---|---|
| `scan <path>` | Claude-assisted static source review | Anthropic API only |
| `guard` | Inspect agent streams against declared intent | Offline unless LLM judge enabled |
| `evaluate` | Pre-deployment agent security scenarios | Offline unless LLM judge enabled |
| `hunt` | Existing human-in-loop IDOR/BOLA differential tests | Program scope required |
| `recon <target>` | nmap, hping3, or Kali utilities | Active scope + authorization |
| `traffic <pcap-or-interface>` | Passive tshark pcap parse or guarded live capture | Scope only for `--live` |
| `test <url>` | Skipfish mapping or SQLMap validation | Scope; SQLMap also attestation |
| `exploit <target>` | Operator-authored Metasploit resource | Highest guardrail + confirmation |
| `creds <artifact>` | Offline Hashcat audit | Engagement attestation |
| `wireless <bssid-or-capture>` | Offline Aircrack analysis or live capture | Attestation; live is intrusive |
| `se <target>` | Operator-configured SET campaign | Highest guardrail + confirmation |
| `ai-redteam <url>` | Approved taxonomy suite | Scope, authorization, suite approval |
| `orchestrate <target>` | Guarded Claude/offline methodology plan | Every proposal authorized; no execution |
| `engagement` | Create/list/scope/report authorization records | Local persistence |
| `ctf` | Challenge engagements and regression scorecards | Manifest rules enforced |
| `bounty import` | Import enrolled-program policy | Automation/high-risk defaults off |
| `tools doctor` | Kali/toolchain readiness | Passive |
| `serve` | Loopback desktop web UI | Loopback only |

Every active command accepts `--scope`, `--deny-scope`, `--engagement`,
`--authorized`, `--dry-run`, `--operator`, and `--out`. External tool options
are repeatable direct argv (`--tool-arg`) and never pass through a shell.

## Typical workflow

```sh
sentinel engagement create \
  --id local-lab \
  --name "Authorized local lab" \
  --operator "$USER" \
  --authorization-ref "local-owner" \
  --attest \
  --scope http://127.0.0.1:3000

sentinel recon http://127.0.0.1:3000 \
  --engagement local-lab \
  --authorized \
  --dry-run

sentinel orchestrate http://127.0.0.1:3000 \
  --engagement local-lab \
  --authorized \
  --planner methodology \
  --dry-run

sentinel engagement report \
  --engagement local-lab \
  --format markdown \
  --out report.md
```

## Adapter examples

```sh
# Technology fingerprinting, exact plan only
sentinel recon https://127.0.0.1:3000 \
  --tool kali-utils --engagement local-lab --authorized --dry-run

# Operator-selected SQLMap parameter; no payload is embedded by Sentinel
sentinel test 'http://127.0.0.1:3000/rest/example?id=1' \
  --tool sqlmap --tool-arg=-p --tool-arg=id \
  --engagement local-lab --authorized --dry-run

# Passive pcap parsing requires no network scope
sentinel traffic owned-capture.pcap --out traffic.json

# AI test content is an operator-reviewed file
sentinel ai-redteam http://127.0.0.1:4010/v1/chat \
  --suite suite.json --approve-probes \
  --engagement local-llm --authorized --dry-run
```

Active external adapters run only in the Kali Dev Container. `tools doctor`
reports missing binaries and capability requirements.

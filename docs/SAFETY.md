# Safety and authorization

Sentinel is for systems you own, isolated labs/CTFs, or work covered by written
authorization. The controls below are executable policy, not a disclaimer.

## Enforced controls

- Active traffic requires both `--authorized` for the current invocation and
  an explicit allow-list from `--scope` or an engagement.
- Deny rules always win, including when a command adds a narrower scope.
- With no authorization and scope, active adapters refuse. Passive code review,
  pcap parsing, and similar offline work remain available.
- Metasploit, live wireless capture, and SET require a matching engagement,
  authorization reference, operator attestation, and a current
  `--confirm-intrusive`.
- SQLMap, Hashcat material, and offline wireless material require engagement
  attestation even when no packets are sent.
- Every active or attestation-sensitive action is recorded in a hash-chained
  audit log. Engagement reports verify the complete chain before rendering.
- `SENTINEL_KILL_SWITCH=1` stops all new active actions. Revocable guardrails
  stop multi-action workflows if authorization changes between proposals.
- Engagement rate/concurrency limits are stored with policy. Adapters add
  conservative tool-specific limits; dangerous hping flood modes are disabled.
- Root is never acquired automatically. Raw-packet and capture tools require
  documented Linux capabilities.

## Dry-run is still authorized

`--dry-run` stops before binary/runtime preflight and execution, then emits the
exact argv and writes an audit event. The authorization and scope gate still
runs, so dry-run cannot be used to normalize an out-of-scope plan.

## AI red-team suites

Sentinel embeds taxonomy metadata, not attack prompts. The operator supplies a
bounded JSON suite, reviews it, and passes `--approve-probes`. The runner sends
sequential HTTP requests only after scope authorization. Audit and report
records include probe ID/category but omit probe and response content.
White-box/model-weight categories are skipped for black-box targets.

## Orchestrator containment

Captured target content is scanned before planner invocation. Any deterministic
guard finding blocks the plan. Claude sees only safe identifiers and tags, not
raw content or finding prose. Its output cannot lower guardrail level, choose a
tool outside the next methodology stage, retarget the action, authorize
itself, or directly execute anything.

## Bounty hard line

Bounty mode requires a current operator-supplied policy, enrollment assertion,
and attestation. Automation defaults off. A program's deny-list and traffic
limits are enforced. Metasploit and SET default off and require a separate
written authorization reference to become eligible. Sentinel never targets
employees, scrapes program scope, or runs unattended production attacks.

Use CTFs and the loopback Compose range for automated/aggressive regression
testing. Review each public platform's current rules; the existence of a
training or bounty platform is not blanket permission.

## Sensitive data

Never commit engagement records, captures, hashes, recovered credentials,
tool output, probe suites containing sensitive text, or audit logs. The default
paths and common artifact formats are ignored. Keep cross-device state in an
encrypted channel. Sentinel redacts declared secrets from command audit argv
and never includes recovered Hashcat/Aircrack plaintext.

# Platform expansion changelog

This file tracks the phase-by-phase implementation requested in the Sentinel
platform expansion brief.

## Phase 0 — baseline and cross-device setup

- Recorded the actual pre-expansion architecture and test baseline.
- Added a Kali-based Dev Container shared by macOS and Windows hosts.
- Documented the branch/PR and Mac-to-PC handoff workflow.
- Added Make targets for bootstrap, development, build, run, test, integration
  test, lint, formatting, and knowledge retrieval.
- Added environment documentation, repository-managed Git hooks, secret
  scanning, and ignores for sensitive engagement/tool artifacts.

## Phase 1 — target architecture

- Added the central `internal/authz` guardrail with deny-first scope matching,
  passive defaults, explicit authorization, kill-switch support, and stronger
  engagement/attestation requirements for intrusive actions.
- Added portable JSON engagement records and the create/list/scope CLI.
- Added common adapter/result models, registry, methodology stages, knowledge
  catalog types, shared AI red-team taxonomy types, and orchestrator contracts.
- Added guarded command scaffolds for recon, web testing, exploitation,
  credential auditing, wireless, social engineering, AI red teaming, and tool
  diagnostics. No external active capability is enabled in this phase.

## Phase 2 — adapter contract and nmap reference

- Added a direct-argv execution sandbox with shell refusal, context timeouts,
  bounded stdout/stderr capture, exit status handling, and secret redaction.
- Extended the registry with deterministic binary discovery and install hints.
- Added hash-chained JSONL audit recording and verification.
- Implemented the guarded nmap reference adapter, including capability and
  privilege preflight, exact dry-run argv, XML parsing, normalized findings,
  mandatory audit events, and golden fixture tests.

## Phase 3 — Kali runtime

- Expanded the multi-architecture Kali Dev Container with every required
  security binary and common DNS/WhatWeb utilities.
- Kept the default user unprivileged and documented the narrow raw-packet and
  capture capabilities used by nmap, hping3, dumpcap, and Aircrack-ng.
- Added runtime detection that keeps active adapters dark outside Kali while
  leaving passive features available.
- Implemented `sentinel tools doctor` with per-binary readiness and the exact
  `make dev` recovery instruction.

## Phase 4 — complete guarded adapter set

- Added one guarded package for hping3, tshark, Skipfish, sqlmap, Metasploit,
  Hashcat, Aircrack-ng, SET, and common Kali utilities.
- Centralized forced action classification, scope/engagement authorization,
  argv construction, runtime/binary preflight, fail-closed audit, execution,
  and parsing in the reusable command adapter.
- Enforced conservative hping/Skipfish/sqlmap rates, capability checks for raw
  packet/capture modes, and Metasploit resource target validation.
- Added canned output and golden normalized-finding tests for every adapter;
  no unit test launches a live security tool.

## Phase 5 — methodology engine

- Implemented the ordered Recon → Mapping → Tactical Fuzzing → Auth/Session/
  Logic/Transport → Cloud/SSRF → Exploitation/Post state machine.
- Added atomic owner-only engagement state persistence and next-stage proposals.
- Added HUNT-style parameter-to-vulnerability hypotheses with deterministic
  unit tests and narrow validator suggestions.
- Replaced the Recon scaffold with the real guarded nmap adapter, normalized
  JSON report, audit trail, exact dry-run argv, and methodology state update.

## Phase 6 — knowledge base and shared AI red-team taxonomy

- Added a typed, fetch-on-demand SecLists catalog plus embedded HUNT-style
  parameter hypotheses and a vendor-sourced six-provider cloud metadata
  dictionary used by the methodology engine.
- Added a CC BY 4.0-attributed, prompt-free Arcanum taxonomy loader shared by
  `guard` and `ai-redteam`, including black-box/local applicability.
- Added taxonomy-derived guard detectors for forged conversation turns, tool
  poisoning/spoofing, instruction-file injection, authority impersonation,
  parameter smuggling, and ANSI concealment.
- Replaced the AI red-team scaffold with a scope-gated, audited HTTP runner
  that executes only operator-supplied and explicitly approved suite content.
- Documented adopted and skipped public sources in `docs/SOURCES.md`.

## Phase 7 — guarded orchestration

- Added a Claude planner that reuses the existing retrying analyzer client and
  accepts only strict structured plan output.
- Added a deterministic methodology planner for reproducible offline and CI
  dry-runs.
- Added a guarded orchestration engine that scans untrusted target content
  before planner invocation, exposes only safe finding metadata, forces trusted
  action classification, limits tools to the next methodology stage, and sends
  every valid proposal through the authorization gate.
- Added `sentinel orchestrate` with resumable engagement state, explicit
  planner selection, content inspection, intrusive-action confirmation, and
  hash-chained plan/decision auditing.
- Added regression tests proving injected target content never reaches the
  planner and out-of-scope planner output is refused.

## Phase 8 — isolated labs, CTF scorecards, and bounty policy

- Added a loopback-only, internal-network Compose range with pinned Juice Shop
  and WebGoat profiles, official DVWA profile, and a no-root LLM HTTP fixture.
- Added build-tagged local integration tests for the guarded AI-red-team HTTP
  runner and nmap TCP-connect reconnaissance, plus Dev Container Docker access
  and deterministic lab lifecycle Make targets.
- Added `sentinel ctf start/score`, strict operator-supplied platform rules,
  one engagement per challenge, methodology/tool coverage, solve-rate history,
  and regression scorecards.
- Added `sentinel bounty import` with strict enrollment, allow/deny scope,
  automation limits, high-risk written authorization, and fail-closed
  Metasploit/SET policy.
- Added dynamic scope revocation and tests proving a multi-proposal workflow
  stops between actions when authorization is withdrawn.
- Documented local/public lab boundaries and recorded the local LLM E2E sample.
  The Juice Shop sample slot truthfully records that Docker execution was not
  possible on the implementation host rather than inventing evidence.

## Phase 9 — reporting and release polish

- Added verified engagement reports in Markdown, JSON, and SARIF 2.1.0 with
  scope, methodology progress, audit timeline, normalized findings,
  CWE/OWASP tags, evidence artifacts, and remediation.
- Added `sentinel engagement report`; report generation verifies the complete
  audit hash chain and fails on tampering.
- Replaced the remaining Phase 1 CLI scaffolds with the real guarded Skipfish,
  SQLMap, Metasploit, Hashcat, Aircrack-ng, SET, hping3, Kali utility, and
  tshark adapters. Added explicit intrusive confirmations and a `traffic`
  command for passive/live tshark modes.
- Reworked the README and added architecture, safety, command, lab, source,
  methodology, orchestrator, development, and tool documentation.

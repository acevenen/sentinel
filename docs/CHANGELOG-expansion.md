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

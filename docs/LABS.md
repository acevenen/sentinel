# Labs, CTFs, and bounty operation

## Local automation boundary

Automated integration and aggressive tests belong only on the isolated Compose
range in `deploy/`. Every published port binds to `127.0.0.1`, and the
containers share an internal Docker network. `make test-integration` starts
only the tiny LLM fixture, waits for health, runs build-tagged tests, and tears
the lab down including disposable volumes.

The build-tagged suite runs an approved AI-red-team canary through the real HTTP
runner and nmap TCP-connect reconnaissance against the loopback-published lab
port. Normal `make test` never starts containers, security tools, or network
traffic.

## CTF mode

`sentinel ctf` does not contain public targets. The operator supplies a current
policy manifest:

```sh
sentinel ctf start \
  --manifest testdata/ctf/local-lab.yaml \
  --challenge local-echo \
  --attest-rules

sentinel ctf score \
  --manifest testdata/ctf/local-lab.yaml \
  --run testdata/ctf/local-run.yaml
```

Each challenge becomes its own engagement. Its allow and deny lists, automation
permission, request rate, concurrency, and intrusive-testing permission enter
the same authorization policy as every other Sentinel command. If automation
is forbidden, every active Sentinel action is refused.

[CTFtime](https://ctftime.org/) is useful for event history, archived tasks,
scoreboards, and reputation signals. Prefer archived, locally runnable
challenges from established events such as DEF CON CTF, PlaidCTF, Google CTF,
and HITCON. Persistent training ranges include OverTheWire, picoGym, Root-Me,
pwnable.kr/tw, Hack The Box, TryHackMe, VulnHub, and the
[PortSwigger Web Security Academy](https://portswigger.net/web-security).
Platform permission is not interchangeable: review the exact challenge rules
on every run, and encode prohibitions on scanners or brute force in the
manifest. No public range is a CI default.

The scorecard records attempts, solves, tool and methodology coverage,
wall-clock duration, and gaps. A JSONL history under `SENTINEL_STATE_DIR`
tracks solve rate without storing flags, credentials, or challenge payloads.

## Bounty mode

`sentinel bounty import` consumes a policy snapshot for a program in which the
operator is enrolled:

```sh
sentinel bounty import \
  --program program.yaml \
  --engagement program-2026 \
  --attest-policy
```

The manifest must contain the exact current allow-list, hard deny-list,
automation permission and limits, enrollment assertion, and policy URL.
Automation defaults to prohibited. Metasploit and SET remain disabled in bounty
mode unless the manifest also contains an explicit high-risk permission and a
separate written authorization reference. A command invocation's
`--authorized` flag is a per-action operator assertion; it cannot override a
program prohibition.

Sentinel never scrapes a bounty platform, guesses scope, targets employees, or
turns a bounty banner into blanket authorization. Use local labs and CTFs for
automated stress testing; use bounty mode for scope-locked, accountable,
human-directed research and report preparation.

## Resilience coverage

Unit and integration tests cover malformed parser input, missing binaries,
executor timeouts, oversized output, kill-switch and scope refusal, dynamic
scope revocation between proposals, audit failures, and prompt injection from
target content. The safe failure path is itself a tested output.

# Cross-device development

The Dev Container is Sentinel's source-of-truth development environment. macOS
and Windows hosts both build and run the same Kali image; the host needs only
Git, Docker Desktop, and either VS Code Dev Containers or the Dev Container CLI.

## First checkout

```sh
git clone https://github.com/acevenen/sentinel.git
cd sentinel
git switch feat/platform-expansion
cp .env.example .env
make dev
```

VS Code users can instead run **Dev Containers: Reopen in Container**. Container
creation runs `make bootstrap`, which downloads Go modules, installs pinned
lint/secret-scan tools, and activates the repository's pre-commit hook.

Use `make build`, `make test`, and `make lint` before pushing. Run the CLI with:

```sh
make run ARGS="--help"
```

The image installs nmap, tshark/Wireshark, Metasploit, Aircrack-ng, Hashcat,
Skipfish, sqlmap, hping3, SET, and the Kali DNS/WhatWeb utilities. Check the
current environment with:

```sh
make run ARGS="tools doctor"
```

Outside the Kali container, passive commands such as code scanning, guard
analysis, pcap parsing, and offline report work remain available. Active
adapters refuse with the exact `make dev` recovery instruction.

## Privileges

Sentinel itself runs as the unprivileged `sentinel` container user. The
container adds only the `NET_RAW` and `NET_ADMIN` bounding capabilities, and
file capabilities are assigned to the binaries that need them:

- nmap: `cap_net_raw,cap_net_admin` for SYN scans;
- hping3: `cap_net_raw`;
- dumpcap: `cap_net_raw,cap_net_admin` for live capture;
- airodump-ng/aireplay-ng: `cap_net_raw,cap_net_admin`.

The adapters still preflight the selected mode and fail clearly when a
required capability is unavailable; Sentinel never runs `sudo` or silently
elevates. Live wireless work also needs an explicitly passed-through compatible
adapter. Docker Desktop on macOS/Windows generally supports offline wireless
analysis but not direct monitor-mode hardware; use an authorized Linux host for
that case.

## Moving between Mac and PC

Work on a feature branch, commit small coherent changes, and push before
switching devices. On the other device, fetch and switch to the same branch,
then reopen the repository in the Dev Container. Never force-push `main`.

Configuration examples may be committed, but real `.env`, capture files, hash
material, tool output, audit logs, and engagement state are ignored. Move
sensitive engagement state out-of-band using an encrypted channel; Git is not
the synchronization layer for it.

## Pull requests and CI

Open pull requests into `main`. Branch protection should require CI's lint,
race-enabled unit test, and build jobs. Integration tests are opt-in through
`make test-integration` and use the `integration` build tag; they must target
only the local lab network defined by the repository.

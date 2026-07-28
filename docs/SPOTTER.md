# Sentinel Spotter

Look at a device you own. Learn what it is, how exposed it is, and what to do
about it — in seconds, hands-free, with no cloud.

Spotter is the wearable front end to Sentinel's authorization model. It answers
three questions in order, and refuses to answer the later ones until it has
honestly answered the earlier ones:

1. **What is this?** — fuse what you can see with what the network already
   tells you into one confidence-scored identity.
2. **Does it matter?** — correlate that identity to known weaknesses, scored by
   how reachable the device actually is.
3. **What do I do?** — a ranked, plain-language plan, shortest useful first.

## Try it

```sh
# A camera you own, identified from its housing and its hardware address
sentinel spot --observe logo=hikvision --observe mac-oui=44:19:B6:11:22:33 \
    --observe http-server=Hikvision-Webs --exposure internet

# The same call, emitting the contract a glasses client renders
sentinel spot --observe logo=hikvision --observe mac-oui=44-19-B6-11-22-33 \
    --exposure lan --format hud
```

`sentinel spot` performs **no network activity**. It is the offline half of
Spotter and runs air-gapped, which is why it needs no `--authorized` flag.

## Identity is fused, never asserted

Any one signal is weak. A logo can be a sticker; an OUI can be a re-used NIC; a
banner can be spoofed. Spotter accumulates evidence in **bits** (log-odds) and
constrains itself three ways:

- **Evidence classes.** Signals are grouped by the failure mode they share — a
  vendor logo and a model number are both "looked at the housing." Repetition
  inside a class decays geometrically (1, ½, ¼ …) and is capped, so a pile of
  correlated signals cannot masquerade as proof.
- **Margin, not just score.** A leader that is not clear of the runner-up is
  reported as `ambiguous`, with the runner-up shown, rather than guessed.
- **Corroboration for confidence.** `confirmed` additionally requires two
  independent evidence classes. **A single sensor can never produce a confirmed
  identity.**

| Band | Meaning |
|---|---|
| `unknown` | below the naming floor — Spotter says so instead of picking the nearest entry |
| `ambiguous` | candidates within the margin; the conflict is shown |
| `probable` | one leader, one class of evidence |
| `confirmed` | one leader, corroborated across classes |

Every candidate carries the evidence that produced it, with both the authored
and effective weight, so a score is auditable rather than a black box.

## Risk is exposure-aware, not raw CVSS

The same advisory on an internet-exposed camera and on an isolated VLAN are not
the same problem. Spotter scores what is actually true here:

```
risk = (cvss + known_exploited_weight + default_credential_weight) × exposure
```

- **Known-exploited** carries extra weight: it means working attack code is
  already circulating.
- **Exposure** scales the result — `internet` fully, `lan`/`unknown` partially,
  `isolated` least. Unknown exposure is deliberately scored pessimistically and
  is never treated as isolated.
- **Unknown firmware** downweights the match and labels it `possible`, with an
  explanation telling you to verify. A device is never asserted vulnerable on
  absent evidence.
- Device totals aggregate with diminishing returns, so a pile of medium issues
  cannot outrank certain compromise.

Firmware comparison handles real IoT schemes, which are not semver: `5.4.10` is
correctly newer than `5.4.9` (a string compare gets this backwards), `V` prefixes
and vendor build suffixes normalize, and a trailing letter run sorts as a
pre-release.

## Advice a non-expert can act on

A CVE list is useless to most people. Spotter emits ranked actions, scored by
benefit over effort, and:

- **collapses duplicates by canonical tag** — three advisories phrasing "stop
  exposing this to the internet" three ways produce one step, not three;
- **omits advice for a state you are not in** — a LAN-only camera is never told
  to delete a port-forward it never had.

## The privacy boundary

Spotter is built so that pointing it at hardware you do not own produces
nothing useful.

- A device you have **not enrolled** renders as its class only — "a camera" —
  with no vendor, model, or advisory. This is enforced in `ToHUD` and covered by
  a test that fails if the vendor name or a CVE identifier appears anywhere in
  the serialized card.
- `ScopeGuard` applies your device scope to **every** Spotter action, including
  passive ones. This closes a real gap: `authz.Policy` evaluates `Scope.Decide`
  only for `Active` actions — correct elsewhere, where a passive target is a
  local capture file, but Spotter's passive targets are real hosts, so a
  deny-listed device would otherwise still be assessable.
- Hardware addresses are normalized before comparison, because a MAC copied off
  a sticker as `AA-BB-CC-DD-EE-FF` does not match `aa:bb:cc:dd:ee:ff` under the
  existing matcher — and a silently-failing scope check pushes people to widen
  their allow-list, which is worse than the bug.

## What Spotter refuses to do

These are capability decisions, not policy toggles. The code is absent, which is
the only guarantee that survives an operator who controls the machine.

- No **exploitation**. It reports that a weakness is known; it never attempts one.
- No **credential testing**. It flags that defaults may be unchanged; it never
  tries a password.
- No **identifying people**. The corpus contains device families only.
- No **unattended operation**. There is no daemon, watch, or scheduled mode.
- No **retention of imagery or audio**. Observations enter as structured values.

## Data provenance

Two embedded corpora, both carrying their source and licence:

| Corpus | Status | Source |
|---|---|---|
| `spotter-fingerprints.json` | factual compilation | public IEEE MA-L OUI registry; vendor documentation |
| `spotter-advisories.json` | **illustrative sample** | NVD (CVE/CVSS) and CISA KEV, both public domain |

The advisory corpus references real, publicly documented advisories, but its
affected-version ranges are deliberately coarse and are **not authoritative**.
Every assessment and every HUD card carries that notice, so the data can never
be mistaken for a substitute for the vendor advisory or NVD.

## The glasses contract

`--format hud` emits `HUDCard`, a flat, pre-formatted payload the wearable
renders without business logic — the display shows state, it never decides
state:

```json
{
  "state": "confirmed",
  "line1": "Hikvision IP camera",
  "line2": "3 issues · 2 actively exploited",
  "line3": "Delete the port-forward rule for this device on…",
  "accent": "alert",
  "confidence": "confirmed",
  "risk_band": "critical",
  "concerns": 3,
  "next_action": "Delete the port-forward rule for this device on your router",
  "speech": "That is a Hikvision IP camera. 3 issues known, and 2 are already being exploited in the wild. …",
  "notice": "ILLUSTRATIVE SAMPLE — not a substitute for NVD. …"
}
```

States: `searching`, `ambiguous`, `probable`, `confirmed`, `unenrolled`,
`unauthorized`. Lines are pre-truncated for a narrow monocular display, and
`speech` is plain language that never reads CVE identifiers aloud.

A working HUD concept that renders this contract lives in the demo repo at
`spotter/index.html`.

## Roadmap

**v1 (this)** — offline identification from operator observations, exposure-aware
risk, ranked remediation, HUD contract, authorization guard.

**v2** — one authorized unicast probe to corroborate identity and read a
firmware version, gated through `internal/authz` and written to the hash-chained
audit log; device enrollment as a first-class inventory.

**v3** — fleet view: one score and one prioritized action list for every device
in the home; the glasses client as a producer of the same observation records
the CLI already consumes.

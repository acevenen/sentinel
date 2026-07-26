# Knowledge sources and provenance

Sentinel keeps large third-party datasets out of the repository. Run
`make fetch-knowledge` to make the permissively licensed sources below
available under ignored `knowledge-data/`. The typed catalog resolves those
files by purpose, never by a path embedded in an adapter.

## Adopted sources

| Source | Use in Sentinel | License and handling |
|---|---|---|
| [SecLists](https://github.com/danielmiessler/SecLists) | Typed catalog for content discovery, DNS/subdomains, API parameters, fuzzing, passwords, usernames, pattern matching, and `Ai/LLM_Testing` | MIT. Sparse-cloned on demand; not vendored. Sentinel uses the upstream repository rather than the `jhaddix/SecLists` fork. |
| [HUNT](https://github.com/bugcrowd/HUNT) | The parameter-name-to-testing-hypothesis concept used by tactical fuzzing | Apache-2.0. Fetched on demand. Sentinel's small JSON map is an adapted, reviewed data model and only prioritizes manual testing; it never claims a vulnerability. |
| [The Bug Hunter's Methodology](https://github.com/jhaddix/tbhm) | High-level phase structure informed the explicit methodology state machine | No repository license was detected on 2026-07-25. No text, diagrams, or repository content are copied or fetched. Only high-level workflow ideas were independently implemented. |
| [Cloud metadata notes](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b) and cloud-vendor documentation | Factual AWS, Google Cloud, Azure, DigitalOcean, Oracle Cloud, and Alibaba Cloud instance-metadata locations | The gist has no detected license and is not vendored. Sentinel stores only factual endpoint/header records, cites the corresponding vendor documentation per entry, and includes no SSRF bypass payloads. |
| [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) | Shared prompt-free category metadata for `guard` detection and operator-supplied AI red-team suites | CC BY 4.0. The official repository is fetched on demand. The embedded subset omits all example prompts and records Sentinel's changes. |

Required attribution: This content/methodology is based on the
[Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy/)
created by Jason Haddix of
[Arcanum Information Security](https://arcanum-sec.com/). Sentinel adapts the
taxonomy into a prompt-free metadata subset and adds implementation-specific
delivery and black-box filtering. Copyright © 2024–2026 Jason Haddix,
Arcanum Information Security; licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## jhaddix public-repository review

The GitHub public-repository API returned 78 repositories on 2026-07-25.
Sentinel reviewed the complete list by name, description, fork/archive status,
and detected SPDX license. The decision log is grouped here so future reviews
can reproduce why content was or was not ingested.

- Adopted: `HUNT`; `SecLists` through its MIT-licensed upstream.
- Methodology idea only, with no copied content because no license was
  detected: `tbhm`.
- Relevant data/notes but skipped because they were unlicensed, duplicative,
  stale, or better represented by SecLists/HUNT: `bug-bounty-reference`,
  `bugcrowd-levelup-subdomain-enumeration`, `CTFSolutionTypes`,
  `devops-attack-surface`, `KingOfBugBountyTips`, `pentest-bookmarks`,
  `research`, `scripts`, `SecurityTools`, `sus_params`,
  `www-project-top-25-parameters`, and `XSS.png`.
- Permissively licensed but not ingested because Sentinel wraps maintained
  standard tools or the material is outside the knowledge-catalog scope:
  `asnrecon`, `brutesubs`, `choo`, `CloudBrute`, `gnmapper`, `GraphRunner`,
  `gungnir`, `LinkFinder`, `meetup`, `megplus`, `msfwiki`,
  `mywebappscripts`, `NodeGoat`, `nomore403`, `nuclei-templates`,
  `OWASP-VWAD`, `parseltongue`, `pwnwiki.github.io`,
  `security-template`, and `ssl-conservatory`.
- Copyleft sources intentionally not mixed into Sentinel's MIT distribution:
  `deepdarkCTI`, `hackerone_wordlist`, `massdns`, `P4RS3LT0NGV3`,
  `RustScan`, `Smap`, and `system-prompts-and-models-of-ai-tools`.
- Active tools, exploit/post-exploitation code, legacy forks, personal sites,
  or targets that are out of scope for structured knowledge ingestion:
  `amass`, `Amass-1`, `awsScrape`, `Caduceus`,
  `can-i-take-over-xyz`, `check_mdi`, `CloudRecon`, `CSPReconGO`,
  `database`, `disclose`, `disclosure-policy`, `domain`, `dumpdecrypted`,
  `DVIA`, `InputScanner`, `Internal-Monologue`, `ios_sh`, `jhaddix`,
  `JS-Scan`, `JSParser`, `karma_v2`, `LazyFuzzer`, `lazyrecon`, `Leaked`,
  `nowafpls`, `ptcoresec-scoreboard-ctf`, `samuraiwtf`, `ScanCannon`,
  `securedorg.github.io`, `spikee`, `sslScrape`, `SubreconGPT`,
  `system_prompts_leaks`, `TTSL`, `waybackunifier`, and
  `xssHunterExtension`.

No private repositories, authenticated content, system-prompt leak collections,
or unlicensed probe/payload collections were scraped.

## Arcanum method patterns

Sentinel adopted ideas rather than prose or payloads from
[Building AI Hackbots, Part 1](https://www.arcanum-sec.com/blog/hackbots),
[Start Hacking LLMs](https://executiveoffense.beehiiv.com/p/executive-offense-issue-10-start-hacking-llms),
and Arcanum's public detection-bot catalog:

- tight scope and intentional context become the authorization boundary,
  methodology state, and guarded orchestrator;
- human-reviewed, taxonomy-classified suites and local-lab-first testing
  replace embedded or unattended attack prompts;
- normalized findings are the input to reporting and future
  detection-as-code exporters rather than copied article content;
- black-box and local/model-weight techniques are explicitly separated.

The current phase implements the shared taxonomy, local-lab runner, and
taxonomy-derived deterministic detectors. No copyrighted article text,
examples, or probe content is embedded.

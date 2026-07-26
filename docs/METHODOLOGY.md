# Methodology workflow

Sentinel persists one ordered state machine per engagement:

1. **Recon** confirms scope, discovers authorized assets, and enumerates ports,
   services, network paths, and DNS.
2. **Application mapping** crawls the application, records routes/parameters,
   fingerprints technologies, and identifies authentication boundaries.
3. **Tactical fuzzing** turns parameter names into hypotheses and proposes the
   narrowest validator. Every proposal remains operator-approved.
4. **Authentication, session, logic, and transport** is checklist-driven
   manual assistance; Sentinel records evidence but does not make business-logic
   decisions for the operator.
5. **Cloud and SSRF** selects the relevant provider endpoint dictionary and
   establishes a safe evidence boundary before testing.
6. **Exploitation and post** is reachable only for a confirmed issue under an
   intrusive, attested engagement and per-action human confirmation.

Stages cannot be skipped or reordered. Each completed stage appends normalized
findings, records the current state, and proposes the one valid next stage.
State defaults to `.sentinel-data/state/<engagement>.json`, is owner-only, and
is intentionally ignored by Git; move it between devices through an encrypted
out-of-band channel.

## Parameter guidance

The HUNT-style lookup treats names such as `id`, `user_id`, `file`, `callback`,
and `url` as prioritization signals for classes such as IDOR, SQL injection,
file inclusion, SSRF, XSS, upload, and CSRF. A name match is never a finding.
It only determines which checklist, knowledge list, or validator to propose.
SQL injection hypotheses may propose sqlmap; all such actions still pass scope,
engagement, rate, audit, and human-decision controls.

`sentinel recon` is the first wired workflow command. Its dry-run works on any
host and prints exact nmap argv. Actual execution requires the Kali runtime; a
successful engagement run persists Recon completion and proposes Application
Mapping.


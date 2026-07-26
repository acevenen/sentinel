# Tool adapters

Every adapter follows the same lifecycle: validate input, classify the action
without trusting caller flags, call `authz.Guardrail`, build direct argv, run
runtime/binary/privilege preflight, append a fail-closed audit start event,
execute with bounded output and timeout, parse normalized results, and append
the completion event. `--dry-run` stops after guarded argv construction and
records the plan.

| Adapter | Methodology use | Normalized output | Guardrail |
|---|---|---|---|
| nmap | Recon: hosts, ports, services | Open ports, service metadata, NSE observations | Active scope; SYN mode checks `cap_net_raw` |
| hping3 | Recon: path/firewall/latency | Responding endpoint, port, flags, TTL, RTT | Active scope; fixed conservative count/rate; raw-socket capability |
| tshark | Traffic analysis | Endpoint/protocol summary and redacted credential exposure | Pcap parsing passive; live capture active and capability-checked |
| Skipfish | App mapping/crawl | Web issue samples plus HTML report artifact | Active URL scope; requests capped at two/second |
| sqlmap | Tactical injection validation | Confirmed parameter/type/DBMS findings | Active URL scope plus attested engagement; one thread and delay |
| Metasploit | Operator-approved exploitation/post | Opened session metadata only | Active, intrusive, attested engagement; one operator resource file whose RHOST/RHOSTS must match scope |
| Hashcat | Offline credential audit | Cracked status with recovered plaintext redacted | Offline but attested authorized material |
| Aircrack-ng | Wireless capture/offline audit | Handshake count and redacted recovery status | Offline mode attested; live mode active, intrusive, BSSID-scoped, capability-checked |
| SET | Sanctioned awareness assessment | Aggregate campaign metrics only | Active, intrusive, attested engagement; all content operator-supplied |
| Kali utilities | DNS and technology discovery | DNS records and WhatWeb fingerprints | Active target scope |

The Kali runtime is an environment layer, not an attack adapter. `sentinel tools
doctor` checks every binary. None of the packages embeds exploit payloads,
injection strings, credential material, wireless deauthentication parameters,
or deceptive campaign content.


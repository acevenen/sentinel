import SwiftUI

/// Demonstration results — the prototype ships canned outputs so every screen shows
/// a realistic result state. In the wired app these are produced by parsing the
/// engine's `--format json|sarif|markdown` output (see SentinelEngine).
enum ResultCatalog {

    private static func c(_ t: String) -> ResultCell { ResultCell(t) }
    private static func p(_ t: String, _ k: PillKind) -> ResultCell { ResultCell(t, pill: k) }
    private static func row(_ cells: [ResultCell]) -> ResultRow { ResultRow(cells: cells) }

    private static func argvResult(_ argv: String) -> ToolResult {
        let hex = "a3f" + String(format: "%08x", UInt32.random(in: 0...UInt32.max))
        let head = Headline(kind: .info, icon: "file-scan",
                            title: "Dry-run · nothing was sent",
                            sub: "Exact argv resolved and a hash-chained audit event was written.")
        return ToolResult(headline: head,
                          argv: ArgvBlock(argv: argv, audit: "sha256:" + hex + "… chained"))
    }

    private static func planRows() -> [ResultRow] {
        func mk(_ kind: String, _ method: String, _ id: String, _ url: String, _ ok: Bool) -> ResultRow {
            row([c(kind), c(method), c(id),
                 p(ok ? "in-scope" : "OUT-OF-SCOPE", ok ? .good : .bad), c(url)])
        }
        return [
            mk("baseline", "GET", "alice", "https://api.example.com/v1/orders/1001", true),
            mk("attack", "GET", "alice", "https://api.example.com/v1/orders/2002", true),
            mk("baseline", "GET", "bob", "https://api.example.com/v1/invoices/inv-bob-1", true),
            mk("attack", "GET", "alice", "https://api.example.com/v1/invoices/inv-bob-1", true),
            mk("attack", "GET", "alice", "https://internal.example.com/v1/admin", false),
            mk("attack", "POST", "alice", "https://api.example.com/v1/orders", false)
        ]
    }

    private static func huntResult(mode: RunMode) -> ToolResult {
        if mode == .dry {
            let head = Headline(kind: .info, icon: "file-scan",
                                title: "6 requests planned · 2 refused as out of scope",
                                sub: "Nothing was sent — this is a plan only.")
            let table = ResultTable(cols: ["Kind", "Method", "As", "Scope", "URL"], rows: planRows())
            return ToolResult(headline: head, table: table)
        }
        let head = Headline(kind: .bad, icon: "octagon-alert",
                            title: "2 BOLA / IDOR findings confirmed",
                            sub: "12 authorization tests · 4 baselines · 2 out-of-scope refused")
        let findings: [Finding] = [
            Finding(sev: "CRITICAL", color: Tok.sevCritical,
                    title: "Cross-account invoice read", tag: "get-invoice",
                    loc: "GET /v1/invoices/inv-bob-1",
                    desc: "alice retrieved bob\u{2019}s invoice (HTTP 200). Body contained bob\u{2019}s billing name and card last-4."),
            Finding(sev: "HIGH", color: Tok.orange,
                    title: "Cross-account order read", tag: "get-order",
                    loc: "GET /v1/orders/2002",
                    desc: "alice retrieved bob\u{2019}s order (HTTP 200). Object owner mismatch confirmed against the baseline.")
        ]
        let report = """
        Title: IDOR — cross-account invoice read on /v1/invoices/{id}
        Severity: Critical (CVSS 8.1)
        Asset: https://api.example.com

        Steps to reproduce:
        1. Authenticate as alice.
        2. GET /v1/invoices/inv-bob-1 with alice\u{2019}s session.
        3. Response is HTTP 200 and returns bob\u{2019}s invoice.

        Impact: Any authenticated user can read another user\u{2019}s invoices by changing the ID.
        Remediation: Enforce object-level authorization: verify the invoice owner matches the session subject.
        """
        return ToolResult(headline: head, findings: findings, report: report)
    }

    private static func scanResult() -> ToolResult {
        let head = Headline(kind: .warn, icon: "file-search",
                            title: "Scan complete · 3 findings",
                            sub: "Analyzed 128 files · 342 chunks · claude-sonnet-4-5 · 24.3s")
        let findings: [Finding] = [
            Finding(sev: "CRITICAL", color: Tok.sevCritical,
                    title: "SQL injection via string concatenation", tag: "CWE-89",
                    loc: "internal/store/orders.go:142",
                    desc: "User-supplied id is concatenated into the query. Use parameterized statements."),
            Finding(sev: "HIGH", color: Tok.orange,
                    title: "Hard-coded API credential", tag: "CWE-798",
                    loc: "cmd/worker/main.go:31",
                    desc: "A bearer token is committed in source. Move it to the environment and rotate it."),
            Finding(sev: "MEDIUM", color: Tok.sevMedium,
                    title: "Reflected XSS in error template", tag: "CWE-79",
                    loc: "web/templates/error.html:18",
                    desc: "The raw query is echoed without escaping. Use context-aware output encoding.")
        ]
        return ToolResult(headline: head, findings: findings)
    }

    private static func guardResult() -> ToolResult {
        let head = Headline(kind: .bad, icon: "shield-x",
                            title: "Session blocked",
                            sub: "At least one action failed the guard — fail-closed.")
        let table = ResultTable(cols: ["#", "Event", "Detectors", "Verdict"], rows: [
            row([c("1"), c("tool_output"), c("instruction_injection, authority_impersonation"), p("FLAGGED", .warn)]),
            row([c("2"), c("action · network"), c("out_of_scope_network"), p("BLOCKED", .bad)])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func evaluateResult() -> ToolResult {
        let score = ScoreBanner(score: 78, color: Tok.orange, rec: "CONDITIONAL", recKind: .conditional,
                                note: "Permission risk 34/100 · Layer 3 judge active. Two scenarios need mitigation before deployment.")
        let table = ResultTable(cols: ["Scenario", "Category", "Outcome", "Caught by"], rows: [
            row([c("secret-exfil"), c("data-exfiltration"), p("DEFENDED", .good), c("scope-gate")]),
            row([c("scope-escape"), c("authorization"), p("DEFENDED", .good), c("authz")]),
            row([c("tool-poison"), c("prompt-injection"), p("VULNERABLE", .bad), c("—")]),
            row([c("remote-install"), c("supply-chain"), p("PARTIAL", .warn), c("drift")])
        ])
        return ToolResult(score: score, table: table)
    }

    private static func redteamResult() -> ToolResult {
        let head = Headline(kind: .warn, icon: "brain-circuit",
                            title: "Suite complete · 1 category vulnerable",
                            sub: "3 probes · black-box applicability · operator-approved content")
        let table = ResultTable(cols: ["Probe", "Category", "Applicability", "Outcome"], rows: [
            row([c("forged-turn-01"), c("forged_turn"), c("black-box"), p("DEFENDED", .good)]),
            row([c("tool-poison-03"), c("tool_poisoning"), c("black-box"), p("VULNERABLE", .bad)]),
            row([c("authority-imp-02"), c("authority_impersonation"), c("black-box"), p("DEFENDED", .good)])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func orchestrateResult() -> ToolResult {
        let head = Headline(kind: .info, icon: "workflow",
                            title: "Methodology plan · 4 stages authorized",
                            sub: "Every proposal reclassified and re-authorized · planner did not execute")
        let table = ResultTable(cols: ["Stage", "Proposed step", "Authorization"], rows: [
            row([c("recon"), c("nmap service scan (dry-run)"), p("AUTHORIZED", .good)]),
            row([c("map"), c("skipfish surface map"), p("AUTHORIZED", .good)]),
            row([c("validate"), c("sqlmap on operator param"), p("NEEDS ATTEST", .warn)]),
            row([c("report"), c("engagement report"), p("AUTHORIZED", .good)])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func trafficResult() -> ToolResult {
        let head = Headline(kind: .good, icon: "waves",
                            title: "Parsed 1,284 packets",
                            sub: "Passive tshark parse · owned capture · no network touched")
        let table = ResultTable(cols: ["Protocol", "Packets", "Bytes", "Note"], rows: [
            row([c("TLS 1.3"), c("842"), c("1.2 MB"), c("encrypted")]),
            row([c("HTTP/2"), c("221"), c("486 KB"), c("cleartext headers")]),
            row([c("DNS"), c("153"), c("22 KB"), c("12 unique hosts")]),
            row([c("mDNS"), c("68"), c("9 KB"), c("local")])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func credsResult() -> ToolResult {
        let head = Headline(kind: .good, icon: "key-round",
                            title: "Offline audit complete",
                            sub: "Local strength analysis · no network · attested engagement")
        let table = ResultTable(cols: ["Metric", "Value"], rows: [
            row([c("Hashes analyzed"), c("1,024")]),
            row([c("Weak (dictionary)"), p("142 · 13.9%", .warn)]),
            row([c("Median crack time"), c("4h 12m (est.)")])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func wirelessResult() -> ToolResult {
        let head = Headline(kind: .good, icon: "wifi",
                            title: "Offline capture analyzed",
                            sub: "Aircrack passive analysis · no frames transmitted")
        let table = ResultTable(cols: ["Field", "Value"], rows: [
            row([c("BSSID"), c("AA:BB:CC:DD:EE:FF")]),
            row([c("Handshakes"), c("1 complete (WPA2)")]),
            row([c("Recommendation"), p("Rotate PSK", .warn)])
        ])
        return ToolResult(headline: head, table: table)
    }

    private static func ctfResult() -> ToolResult {
        let score = ScoreBanner(score: 100, color: Tok.green, rec: "ALL FLAGS", recKind: .approved,
                                note: "1 / 1 flags captured · rules enforced (rate ≤ 5 rps, loopback only).")
        let table = ResultTable(cols: ["Flag", "Points", "Status"], rows: [
            row([c("flag-1"), c("100"), p("CAPTURED", .good)])
        ])
        return ToolResult(score: score, table: table)
    }

    private static func bountyResult() -> ToolResult {
        let head = Headline(kind: .info, icon: "award",
                            title: "Policy imported",
                            sub: "acme-public · automation OFF · high-risk OFF (human-directed)")
        let table = ResultTable(cols: ["Setting", "Value"], rows: [
            row([c("In scope"), c("*.acme.com")]),
            row([c("Out of scope"), c("admin.acme.com")]),
            row([c("Automation"), p("DISABLED", .warn)])
        ])
        return ToolResult(headline: head, table: table)
    }

    static func result(for screen: Screen, mode: RunMode) -> ToolResult? {
        if screen == .hunt { return huntResult(mode: mode) }
        guard let tool = ToolCatalog.tools[screen] else { return nil }

        switch tool.runKey {
        case "scan": return scanResult()
        case "guard": return guardResult()
        case "evaluate": return evaluateResult()
        case "recon": return argvResult("nmap -sV --top-ports 1000 --reason -oX - 127.0.0.1")
        case "test": return argvResult("sqlmap -u \"http://127.0.0.1:3000/rest/example?id=1\" -p id --batch --level 1")
        case "exploit": return argvResult("msfconsole -q -r /engagements/local-lab/handler.rc")
        case "se": return argvResult("setoolkit --config /engagements/local-lab/campaign.yaml --dry")
        case "redteam":
            if mode == .dry {
                return argvResult("sentinel ai-redteam http://127.0.0.1:4010/v1/chat --suite suite.json --approve-probes --dry-run")
            }
            return redteamResult()
        case "orchestrate": return orchestrateResult()
        case "traffic": return trafficResult()
        case "creds": return credsResult()
        case "wireless": return wirelessResult()
        case "ctf": return ctfResult()
        case "bounty": return bountyResult()
        default: return nil
        }
    }
}

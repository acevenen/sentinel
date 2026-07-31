import SwiftUI

// MARK: - Guided tour model

enum TourTarget { case sidebar, inputBox, boxToolbar, runButton, dock }

struct TourStep: Identifiable {
    let id = UUID()
    let target: TourTarget
    let icon: String
    let kicker: String
    let title: String
    let body: String
    let next: String
}

// MARK: - Catalog

enum ToolCatalog {
    static let groups: [SidebarGroup] = [
        SidebarGroup(label: "Get Started", items: [.welcome, .howto]),
        SidebarGroup(label: "Defense", items: [.scan, .guardRuntime, .evaluate]),
        SidebarGroup(label: "Authorized Testing", items: [.hunt, .recon, .traffic, .test]),
        SidebarGroup(label: "High Guardrail", items: [.exploit, .creds, .wireless, .se]),
        SidebarGroup(label: "AI Security", items: [.aiRedteam, .orchestrate]),
        SidebarGroup(label: "Operations", items: [.engagements, .ctf, .bounty, .doctor])
    ]

    static let meta: [Screen: ScreenMeta] = [
        .welcome: ScreenMeta(name: "Welcome", icon: "sparkles", ico: Tok.authorizedBlue, crumb: "Get Started"),
        .howto: ScreenMeta(name: "Point at a Project", icon: "compass", ico: Tok.authorizedBlue, crumb: "Get Started"),
        .engagements: ScreenMeta(name: "Engagements", icon: "file-check-2", ico: Tok.opsGrey, crumb: "Operations"),
        .doctor: ScreenMeta(name: "Tools Doctor", icon: "stethoscope", ico: Tok.opsGrey, crumb: "Operations")
    ]

    /// Resolve display name / icon / crumb / tint for any screen (tool or meta).
    static func nameFor(_ s: Screen) -> String { tools[s]?.name ?? meta[s]?.name ?? "Welcome" }
    static func iconFor(_ s: Screen) -> String { tools[s]?.icon ?? meta[s]?.icon ?? "sparkles" }
    static func crumbFor(_ s: Screen) -> String { tools[s]?.crumb ?? meta[s]?.crumb ?? "" }
    static func tintFor(_ s: Screen) -> Color { tools[s]?.ico ?? meta[s]?.ico ?? Tok.authorizedBlue }

    /// Hunt's fields depend on the active tab.
    static func huntFields(tab: String) -> [Field] {
        switch tab {
        case "import":
            return [
                Field(id: "hunt-id", kind: .text, label: "Identity (which account this capture belongs to)",
                      icon: "user-round", placeholder: "alice"),
                Field(id: "hunt-har", kind: .code, label: "HAR capture", lang: "json", sample: "hunt-har", rows: 7),
                Field(id: "hunt-merge", kind: .toggle, label: "Merge into the current manifest (second account)")
            ]
        case "manifest":
            return [
                Field(id: "hunt-prog", kind: .code, label: "Program manifest", lang: "yaml",
                      sample: "hunt-program", rows: 15, seedSample: true)
            ]
        default:
            return []
        }
    }

    static let tourSteps: [TourStep] = [
        TourStep(target: .sidebar, icon: "panel-left", kicker: "ORIENTATION",
                 title: "Every tool, one sidebar",
                 body: "The eighteen Sentinel commands are grouped by guardrail — from defensive scans to the highest-tier active tools. Each is also in the menu bar.",
                 next: "Next"),
        TourStep(target: .inputBox, icon: "file-code", kicker: "INPUTS",
                 title: "Paste anything, safely",
                 body: "Every input is a monospace box with line numbers. Load a sample to see the tool work before supplying your own.",
                 next: "Next"),
        TourStep(target: .boxToolbar, icon: "copy", kicker: "QUALITY OF LIFE",
                 title: "Copy, validate, clear",
                 body: "Each box has one-tap Copy, live JSON/YAML Validate, and a Clear-all button — plus drag-and-drop for files.",
                 next: "Next"),
        TourStep(target: .runButton, icon: "play", kicker: "ACTION",
                 title: "Dry-run, then run",
                 body: "Active tools default to a dry-run that shows the exact argv and its scope decision without sending anything. Fail-closed, always.",
                 next: "Next"),
        TourStep(target: .dock, icon: "shield-check", kicker: "YOU\u{2019}RE SET",
                 title: "Lives in your Dock",
                 body: "Sentinel runs like any native app — pin it, launch it, ship reports. That\u{2019}s the tour. Happy hunting.",
                 next: "Done")
    ]

    // MARK: Tool specs
    //
    // Each spec is its own explicitly-typed constant. A single 14-entry
    // [Screen: ToolSpec] dictionary literal is pathological for Swift's type
    // checker (minutes per file); these are instant.

    static let scanSpec: ToolSpec = ToolSpec(
        screen: .scan, name: "Scan Code", icon: "file-search", ico: Tok.defenseGreen,
        tier: .defense, consent: "Anthropic API only", crumb: "Defense",
        sub: "Static security review of a codebase with Claude — SQL injection, XSS, hard-coded secrets, unsafe deserialization and more, each tagged with CWE and severity.",
        banner: "Scanning sends source files to the Anthropic API. Your ANTHROPIC_API_KEY is read from the environment only and is never stored.",
        bannerIcon: "sparkles", bannerColor: Tok.defenseGreen,
        fields: [
            Field(id: "scan-path", kind: .drop, label: "Target directory", icon: "folder-code",
                  placeholder: "Drop a project folder here", note: "~/code/acme-api  ·  respects .gitignore"),
            Field(id: "scan-sev", kind: .select, label: "Minimum severity",
                  options: ["critical", "high", "medium", "low"]),
            Field(id: "scan-fmt", kind: .select, label: "Report format",
                  options: ["sarif", "markdown", "json", "terminal"])
        ],
        primary: PrimaryAction(label: "Scan", icon: "scan-search", key: "⌘⏎"),
        runKey: "scan", foot: "source never leaves your key")

    static let guardSpec: ToolSpec = ToolSpec(
        screen: .guardRuntime, name: "Guard Runtime", icon: "shield-check", ico: Tok.defenseGreen,
        tier: .defense, consent: "Offline unless judge on", crumb: "Defense",
        sub: "Verify a running agent\u{2019}s tool outputs and actions against a declared intent — deterministic taxonomy detectors plus four verification layers.",
        fields: [
            Field(id: "guard-intent", kind: .code, label: "Declared intent", lang: "json",
                  sample: "guard-intent", rows: 6, seedSample: true),
            Field(id: "guard-stream", kind: .code, label: "Session stream (one event per line)", lang: "jsonl",
                  sample: "guard-stream", rows: 6, seedSample: true)
        ],
        primary: PrimaryAction(label: "Guard session", icon: "shield-check", key: "⌘⏎"),
        runKey: "guard", foot: "runs locally · fail-closed")

    static let evaluateSpec: ToolSpec = ToolSpec(
        screen: .evaluate, name: "Evaluate Agent", icon: "gauge", ico: Tok.defenseGreen,
        tier: .defense, consent: "Offline unless judge on", crumb: "Defense",
        sub: "Score an AI agent before deployment. Runs a library of attacks against its declared authority and returns an Agent Security Score.",
        fields: [
            Field(id: "eval-agent", kind: .code, label: "Agent manifest", lang: "yaml",
                  sample: "evaluate-agent", rows: 15, seedSample: true)
        ],
        primary: PrimaryAction(label: "Evaluate", icon: "gauge", key: "⌘⏎"),
        runKey: "evaluate", foot: "no network required")

    static let huntSpec: ToolSpec = ToolSpec(
        screen: .hunt, name: "Hunt · IDOR / BOLA", icon: "target", ico: Tok.authorizedBlue,
        tier: .authorized, consent: "Program scope required", crumb: "Authorized testing",
        sub: "Broken object-level authorization testing for authorized bug-bounty targets. Scope-enforced, read-only, HackerOne-ready reports.",
        tabs: ["import", "manifest", "run"],
        primary: PrimaryAction(label: "Continue to run", icon: "arrow-right", key: "⌘⏎"),
        runKey: "hunt", foot: "read-only · scope-gated")

    static let reconSpec: ToolSpec = ToolSpec(
        screen: .recon, name: "Recon", icon: "radar", ico: Tok.authorizedBlue,
        tier: .authorized, consent: "Active scope + authorization", crumb: "Authorized testing",
        sub: "nmap, hping3, or Kali utilities against an authorized target. Dry-run prints the exact argv and writes a hash-chained audit event — no packet is sent.",
        fields: [
            Field(id: "recon-target", kind: .text, label: "Target", icon: "globe",
                  seedText: "https://127.0.0.1:3000", placeholder: "https://127.0.0.1:3000", mono: true),
            Field(id: "recon-eng", kind: .select, label: "Engagement",
                  options: ["local-lab", "acme-web", "— none —"]),
            Field(id: "recon-tool", kind: .select, label: "Adapter",
                  options: ["nmap", "hping3", "kali-utils"]),
            Field(id: "recon-args", kind: .text, label: "Tool args", icon: "terminal",
                  seedText: "--top-ports 1000 -sV", placeholder: "--top-ports 1000 -sV", mono: true)
        ],
        primary: PrimaryAction(label: "Run", icon: "play", key: "⌘⏎"),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "recon", dry: "argv", foot: "active · scope enforced")

    static let trafficSpec: ToolSpec = ToolSpec(
        screen: .traffic, name: "Traffic", icon: "waves", ico: Tok.authorizedBlue,
        tier: .authorized, consent: "Scope only for live", crumb: "Authorized testing",
        sub: "Passive tshark parsing of a capture you already own, or guarded live capture on an interface (scope required for live).",
        fields: [
            Field(id: "traffic-cap", kind: .drop, label: "Capture", icon: "file-audio",
                  placeholder: "Drop a .pcap you own", note: "passive parse needs no network scope"),
            Field(id: "traffic-live", kind: .toggle,
                  label: "Live capture on an interface (requires scope + authorization)")
        ],
        primary: PrimaryAction(label: "Parse capture", icon: "waves", key: "⌘⏎"),
        runKey: "traffic", foot: "passive by default")

    static let testSpec: ToolSpec = ToolSpec(
        screen: .test, name: "Test", icon: "flask-conical", ico: Tok.authorizedBlue,
        tier: .authorized, consent: "Scope; SQLMap attests", crumb: "Authorized testing",
        sub: "Skipfish mapping or SQLMap validation against an authorized URL. Sentinel embeds no payloads — parameters are operator-selected.",
        banner: "SQLMap additionally requires an attested engagement. Sentinel never invokes a shell and never passes payloads it authored.",
        bannerIcon: "triangle-alert", bannerColor: Tok.orange,
        fields: [
            Field(id: "test-url", kind: .text, label: "Target URL", icon: "globe",
                  seedText: "http://127.0.0.1:3000/rest/example?id=1",
                  placeholder: "http://127.0.0.1:3000/rest/example?id=1", mono: true),
            Field(id: "test-tool", kind: .select, label: "Adapter", options: ["skipfish", "sqlmap"]),
            Field(id: "test-args", kind: .text, label: "Tool args", icon: "terminal",
                  seedText: "-p id", placeholder: "-p id", mono: true)
        ],
        primary: PrimaryAction(label: "Run", icon: "play", key: "⌘⏎"),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "test", dry: "argv", foot: "scope + attestation")

    static let exploitSpec: ToolSpec = ToolSpec(
        screen: .exploit, name: "Exploit", icon: "crosshair", ico: Tok.highRed,
        tier: .high, consent: "Highest guardrail + confirm", crumb: "High guardrail",
        sub: "Run an operator-authored Metasploit resource. Highest guardrail: every action needs a confirmed, in-scope, attested engagement.",
        banner: "Sentinel authors no exploit content. This runs only your own reviewed resource file, only inside the Kali Dev Container, with per-action confirmation.",
        bannerIcon: "shield-alert", bannerColor: Tok.highRed,
        fields: [
            Field(id: "exp-target", kind: .text, label: "Target", icon: "globe",
                  seedText: "127.0.0.1", placeholder: "127.0.0.1", mono: true),
            Field(id: "exp-rc", kind: .code, label: "Metasploit resource (operator-authored)", lang: "msf-rc",
                  sample: "exploit-rc", rows: 7, seedSample: true),
            Field(id: "exp-eng", kind: .select, label: "Engagement", options: ["local-lab", "— none —"])
        ],
        primary: PrimaryAction(label: "Authorize & run", icon: "shield-check", key: "⌘⏎", danger: true),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "exploit", dry: "argv", foot: "confirm required", confirm: true)

    static let credsSpec: ToolSpec = ToolSpec(
        screen: .creds, name: "Creds", icon: "key-round", ico: Tok.highRed,
        tier: .high, consent: "Engagement attestation", crumb: "High guardrail",
        sub: "Offline Hashcat audit of a captured artifact you are authorized to test. No network — purely local strength analysis.",
        banner: "Requires an attested engagement. The artifact is analyzed offline and never leaves this Mac.",
        bannerIcon: "shield-alert", bannerColor: Tok.highRed,
        fields: [
            Field(id: "creds-art", kind: .drop, label: "Captured artifact", icon: "file-key-2",
                  placeholder: "Drop a hash file (offline)", note: "analyzed locally · no network"),
            Field(id: "creds-mode", kind: .select, label: "Attack mode",
                  options: ["dictionary", "mask", "straight"]),
            Field(id: "creds-list", kind: .text, label: "Wordlist", icon: "list",
                  seedText: "rockyou.txt", placeholder: "rockyou.txt", mono: true)
        ],
        primary: PrimaryAction(label: "Audit offline", icon: "key-round", key: "⌘⏎"),
        runKey: "creds", foot: "offline · attested")

    static let wirelessSpec: ToolSpec = ToolSpec(
        screen: .wireless, name: "Wireless", icon: "wifi", ico: Tok.highRed,
        tier: .high, consent: "Attestation; live intrusive", crumb: "High guardrail",
        sub: "Offline Aircrack analysis of a capture, or live capture. Live capture is intrusive and requires attestation and confirmation.",
        banner: "Offline analysis is passive. Live capture is intrusive — it needs an attested engagement and per-action confirmation.",
        bannerIcon: "shield-alert", bannerColor: Tok.highRed,
        fields: [
            Field(id: "wl-cap", kind: .drop, label: "Handshake capture", icon: "file-audio",
                  placeholder: "Drop a .cap for offline analysis", note: "offline analysis needs no scope"),
            Field(id: "wl-bssid", kind: .text, label: "BSSID", icon: "router",
                  placeholder: "AA:BB:CC:DD:EE:FF", mono: true)
        ],
        primary: PrimaryAction(label: "Analyze offline", icon: "wifi", key: "⌘⏎"),
        runKey: "wireless", foot: "offline · attested")

    static let seSpec: ToolSpec = ToolSpec(
        screen: .se, name: "Social Engineering", icon: "message-square-warning", ico: Tok.highRed,
        tier: .high, consent: "Highest guardrail + confirm", crumb: "High guardrail",
        sub: "Operator-configured SET campaign. Highest guardrail: content is operator-authored and every action is confirmed and scoped.",
        banner: "Sentinel embeds no lures or pretexts. Campaign content is entirely operator-authored, reviewed, and confirmed per action.",
        bannerIcon: "shield-alert", bannerColor: Tok.highRed,
        fields: [
            Field(id: "se-target", kind: .text, label: "Target", icon: "globe",
                  placeholder: "authorized-domain.test", mono: true),
            Field(id: "se-cfg", kind: .code, label: "Campaign config (operator-authored)", lang: "yaml", rows: 6)
        ],
        primary: PrimaryAction(label: "Authorize & run", icon: "shield-check", key: "⌘⏎", danger: true),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "se", dry: "argv", foot: "confirm required", confirm: true)

    static let redteamSpec: ToolSpec = ToolSpec(
        screen: .aiRedteam, name: "AI Red Team", icon: "brain-circuit", ico: Tok.aiViolet,
        tier: .ai, consent: "Scope + suite approval", crumb: "AI security",
        sub: "Run an approved taxonomy suite against an AI endpoint. Probe content is operator-supplied and reviewed; Sentinel embeds taxonomy metadata, not attack strings.",
        banner: "Probe content is operator-supplied and must be explicitly approved. Sentinel ships the Arcanum taxonomy structure, never the attack payloads.",
        bannerIcon: "brain-circuit", bannerColor: Tok.aiViolet,
        fields: [
            Field(id: "rt-url", kind: .text, label: "Endpoint", icon: "globe",
                  seedText: "http://127.0.0.1:4010/v1/chat",
                  placeholder: "http://127.0.0.1:4010/v1/chat", mono: true),
            Field(id: "rt-suite", kind: .code, label: "Approved probe suite", lang: "json",
                  sample: "redteam-suite", rows: 9, seedSample: true),
            Field(id: "rt-approve", kind: .toggle,
                  label: "I approve this probe content for an authorized target")
        ],
        primary: PrimaryAction(label: "Run suite", icon: "brain-circuit", key: "⌘⏎"),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "redteam", dry: "argv", foot: "suite approved · scoped")

    static let orchestrateSpec: ToolSpec = ToolSpec(
        screen: .orchestrate, name: "Orchestrate", icon: "workflow", ico: Tok.aiViolet,
        tier: .ai, consent: "Every proposal authorized", crumb: "AI security",
        sub: "Guarded Claude/offline methodology plan. Every proposal is reclassified, constrained to the next stage, and re-authorized — the planner never executes.",
        banner: "Claude may only propose the next methodology stage. Raw findings are excluded from its prompt, and trusted code re-authorizes every step. No action is executed here.",
        bannerIcon: "workflow", bannerColor: Tok.aiViolet,
        fields: [
            Field(id: "orch-target", kind: .text, label: "Target", icon: "globe",
                  seedText: "http://127.0.0.1:3000", placeholder: "http://127.0.0.1:3000", mono: true),
            Field(id: "orch-eng", kind: .select, label: "Engagement", options: ["local-lab", "acme-web"]),
            Field(id: "orch-planner", kind: .select, label: "Planner", options: ["methodology", "claude"])
        ],
        primary: PrimaryAction(label: "Plan", icon: "workflow", key: "⌘⏎"),
        secondary: SecondaryAction(label: "Dry-run", icon: "file-scan", key: "⌘D"),
        runKey: "orchestrate", dry: "plan", foot: "plan only · no execution")

    static let ctfSpec: ToolSpec = ToolSpec(
        screen: .ctf, name: "CTF", icon: "flag", ico: Tok.opsGrey,
        tier: .ops, consent: "Manifest rules enforced", crumb: "Operations",
        sub: "Challenge engagements and regression scorecards. Manifest rules — scope, rate limits, automation — are enforced by trusted code.",
        fields: [
            Field(id: "ctf-man", kind: .code, label: "Challenge manifest", lang: "yaml",
                  sample: "ctf-manifest", rows: 11, seedSample: true)
        ],
        primary: PrimaryAction(label: "Score run", icon: "flag", key: "⌘⏎"),
        runKey: "ctf", foot: "rules enforced")

    static let bountySpec: ToolSpec = ToolSpec(
        screen: .bounty, name: "Bounty", icon: "award", ico: Tok.opsGrey,
        tier: .ops, consent: "Automation off by default", crumb: "Operations",
        sub: "Import an enrolled-program policy. Automation and high-risk defaults are off — public bounty work stays human-directed.",
        fields: [
            Field(id: "bounty-pol", kind: .code, label: "Enrolled-program policy", lang: "yaml",
                  sample: "bounty-policy", rows: 9, seedSample: true)
        ],
        primary: PrimaryAction(label: "Import policy", icon: "award", key: "⌘⏎"),
        runKey: "bounty", foot: "human-directed")

    static let all: [ToolSpec] = [
        scanSpec, guardSpec, evaluateSpec,
        huntSpec, reconSpec, trafficSpec, testSpec,
        exploitSpec, credsSpec, wirelessSpec, seSpec,
        redteamSpec, orchestrateSpec,
        ctfSpec, bountySpec
    ]

    static let tools: [Screen: ToolSpec] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.screen, $0) })
}

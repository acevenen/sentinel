import SwiftUI

/// Every navigable screen. `guard` is a Swift keyword, so its case is `guardRuntime`.
enum Screen: String, Identifiable, Hashable, CaseIterable {
    case welcome, howto
    case scan
    case guardRuntime = "guard"
    case evaluate
    case hunt, recon, traffic, test
    case exploit, creds, wireless, se
    case aiRedteam = "ai-redteam"
    case orchestrate
    case engagements, ctf, bounty, doctor

    var id: String { rawValue }
    var isTool: Bool { ToolCatalog.tools[self] != nil }
}

enum GuardTier: String {
    case defense, authorized, high, ai, ops
    var label: String {
        switch self {
        case .defense: return "Defensive"
        case .authorized: return "Authorized · active scope"
        case .high: return "Highest guardrail"
        case .ai: return "AI security"
        case .ops: return "Operations"
        }
    }
    var color: Color {
        switch self {
        case .defense: return Tok.defenseGreen
        case .authorized: return Tok.authorizedBlue
        case .high: return Tok.highRed
        case .ai: return Tok.aiViolet
        case .ops: return Tok.opsGrey
        }
    }
}

enum FieldKind { case code, text, select, toggle, drop }

struct Field: Identifiable {
    // NOTE: field order matches the memberwise-init call sites in ToolCatalog.
    let id: String
    let kind: FieldKind
    let label: String
    var lang: String? = nil            // JSON / YAML / JSONL / msf-rc (uppercased tag)
    var sample: String? = nil          // key into Samples
    var rows: Int = 6
    var seedSample: Bool = false       // pre-fill from `sample`
    var icon: String? = nil
    var seedText: String? = nil        // pre-fill with literal text
    var placeholder: String = ""
    var note: String = ""
    var options: [String] = []
    var mono: Bool = false

    var hasSample: Bool { sample != nil }

    /// The prototype seeds a code/text box either from a named sample or a literal.
    func initialText() -> String {
        if seedSample, let s = sample { return Samples.map[s] ?? "" }
        return seedText ?? ""
    }
    var minHeight: CGFloat { CGFloat(rows) * 20 + 24 }
}

struct PrimaryAction {
    let label: String
    let icon: String
    let key: String
    var danger: Bool = false
}

struct SecondaryAction {
    let label: String
    let icon: String
    let key: String
}

struct ToolSpec {
    let screen: Screen
    let name: String
    let icon: String
    let ico: Color                     // category tint
    let tier: GuardTier
    let consent: String
    let crumb: String
    let sub: String
    var banner: String? = nil
    var bannerIcon: String? = nil
    var bannerColor: Color? = nil
    var tabs: [String]? = nil
    var fields: [Field] = []
    var primary: PrimaryAction
    var secondary: SecondaryAction? = nil
    var runKey: String
    var dry: String? = nil             // "argv" | "plan"
    var foot: String
    var confirm: Bool = false
}

/// Non-tool screens (Welcome, Point-at-a-Project, Engagements, Tools Doctor).
struct ScreenMeta {
    let name: String
    let icon: String
    let ico: Color
    let crumb: String
}

struct SidebarGroup: Identifiable {
    let label: String
    let items: [Screen]
    var id: String { label }
}

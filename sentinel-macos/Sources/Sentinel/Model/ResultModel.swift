import SwiftUI

enum RecKind {
    case approved, conditional, rejected
    var fg: Color { switch self { case .approved: return Tok.goodFg; case .conditional: return Tok.warnFg; case .rejected: return Tok.badFg } }
    var bg: Color {
        switch self {
        case .approved: return Color.rgba(47, 180, 87, 0.16)
        case .conditional: return Color.rgba(255, 143, 14, 0.18)
        case .rejected: return Color.rgba(255, 59, 48, 0.16)
        }
    }
}

/// Headline strip uses slightly softer bg/border than the inline pills.
extension PillKind {
    var stripBg: Color {
        switch self { case .good: return .rgba(47,180,87,0.10); case .bad: return .rgba(255,59,48,0.10); case .warn: return .rgba(255,143,14,0.11); case .info: return .rgba(10,132,255,0.09) }
    }
    var stripBorder: Color {
        switch self { case .good: return .rgba(47,180,87,0.30); case .bad: return .rgba(255,59,48,0.30); case .warn: return .rgba(255,143,14,0.32); case .info: return .rgba(10,132,255,0.28) }
    }
}

struct ResultCell: Identifiable {
    let id = UUID()
    let text: String
    let pill: PillKind?
    init(_ text: String, pill: PillKind? = nil) { self.text = text; self.pill = pill }
}

struct ResultRow: Identifiable {
    let id = UUID()
    let cells: [ResultCell]
}

struct ResultTable {
    let cols: [String]
    let rows: [ResultRow]

    /// Fixed widths from the prototype's cols() map; unmatched → 140, last col flexes.
    static func width(for label: String) -> CGFloat? {
        switch label {
        case "#": return 46
        case "Scope": return 110
        case "Method": return 78
        case "As": return 70
        case "Points": return 80
        case "Packets": return 90
        case "Bytes": return 90
        case "URL": return nil
        default: return 140
        }
    }
}

struct Finding: Identifiable {
    let id = UUID()
    let sev: String        // CRITICAL / HIGH / MEDIUM
    let color: Color       // left border
    let title: String
    let tag: String
    let loc: String
    let desc: String

    var sevKind: PillKind {
        switch sev { case "CRITICAL": return .bad; case "HIGH": return .warn; default: return .warn }
    }
}

struct ScoreBanner {
    let score: Int
    let color: Color
    let rec: String
    let recKind: RecKind
    let note: String
}

struct Headline {
    let kind: PillKind
    let icon: String
    let title: String
    let sub: String
}

struct ArgvBlock {
    let argv: String
    let audit: String
}

/// A run's result — any subset of blocks, rendered top-to-bottom in fixed order.
struct ToolResult {
    var score: ScoreBanner? = nil
    var headline: Headline? = nil
    var table: ResultTable? = nil
    var findings: [Finding]? = nil
    var argv: ArgvBlock? = nil
    var report: String? = nil
}

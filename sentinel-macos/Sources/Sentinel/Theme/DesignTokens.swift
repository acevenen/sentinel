import SwiftUI

// MARK: - Color helpers

extension Color {
    /// Hex like "#FA243C" or "FA243C".
    init(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") { s.removeFirst() }
        var v: UInt64 = 0
        Scanner(string: s).scanHexInt64(&v)
        let r, g, b, a: Double
        switch s.count {
        case 8: // RRGGBBAA
            r = Double((v >> 24) & 0xFF) / 255
            g = Double((v >> 16) & 0xFF) / 255
            b = Double((v >> 8) & 0xFF) / 255
            a = Double(v & 0xFF) / 255
        default: // RRGGBB
            r = Double((v >> 16) & 0xFF) / 255
            g = Double((v >> 8) & 0xFF) / 255
            b = Double(v & 0xFF) / 255
            a = 1
        }
        self = Color(.sRGB, red: r, green: g, blue: b, opacity: a)
    }

    /// sRGB with explicit alpha — mirrors the prototype's rgba(...) values.
    static func rgba(_ r: Double, _ g: Double, _ b: Double, _ a: Double) -> Color {
        Color(.sRGB, red: r / 255, green: g / 255, blue: b / 255, opacity: a)
    }
}

// MARK: - Design tokens (values transcribed verbatim from the handoff)

enum Tok {
    // Neutrals
    static let label = Color(hex: "#1D1D1F")
    static let secondary = Color.rgba(60, 60, 67, 0.6)
    static let tertiary = Color.rgba(60, 60, 67, 0.34)
    static let separator = Color.rgba(0, 0, 0, 0.08)
    static let content = Color(hex: "#FFFFFF")
    static let grouped = Color(hex: "#F2F2F4")
    static let fieldBg = Color(hex: "#FBFBFD")

    // Semantic / category colors (independent of accent — carry meaning)
    static let defenseGreen = Color(hex: "#2FB457")
    static let authorizedBlue = Color(hex: "#0A84FF")
    static let highRed = Color(hex: "#FF3B30")
    static let aiViolet = Color(hex: "#A458DE")
    static let opsGrey = Color(hex: "#8E8E93")

    // Base semantic (from the prototype's :root vars)
    static let green = Color(hex: "#2FB457")
    static let orange = Color(hex: "#FF8F0E")
    static let red = Color(hex: "#FF3B30")
    static let purple = Color(hex: "#A458DE")

    // Result pill foreground / background pairs
    static let goodFg = Color(hex: "#1C7C3A")
    static let goodBg = Color.rgba(47, 180, 87, 0.14)
    static let warnFg = Color(hex: "#B56400")
    static let warnBg = Color.rgba(255, 143, 14, 0.16)
    static let badFg = Color(hex: "#C62A20")
    static let badBg = Color.rgba(255, 59, 48, 0.14)
    static let infoFg = Color(hex: "#0A5FCE")
    static let infoBg = Color.rgba(10, 132, 255, 0.12)

    // Severity
    static let sevCritical = Color(hex: "#FF3B30")
    static let sevHigh = Color(hex: "#FF9500")
    static let sevMedium = Color(hex: "#FFCC00")

    // Dark terminal panel
    static let terminalBg = Color(hex: "#1C1C1E")
    static let terminalFg = Color(hex: "#E6E6EA")

    // Radii
    static let rWindow: CGFloat = 13
    static let rCard: CGFloat = 15
    static let rCardLg: CGFloat = 16
    static let rField: CGFloat = 12
    static let rButton: CGFloat = 9
    static let rButtonSm: CGFloat = 8
    static let rPill: CGFloat = 7
    static let rChip: CGFloat = 6
    static let rSquircle: CGFloat = 22

    // Fonts
    static let mono = Font.system(.body, design: .monospaced)
    static func monoFont(_ size: CGFloat) -> Font {
        .system(size: size, weight: .regular, design: .monospaced)
    }

    /// Map the prototype's numeric weights (450–740) to the nearest SwiftUI weight.
    static func weight(_ n: Int) -> Font.Weight {
        switch n {
        case ..<430: return .light
        case 430..<500: return .regular
        case 500..<560: return .medium
        case 560..<710: return .semibold
        default: return .bold
        }
    }

    static func font(_ size: CGFloat, _ w: Int = 430) -> Font {
        .system(size: size, weight: weight(w))
    }
}

// MARK: - Accent

enum AccentChoice: String, CaseIterable, Identifiable {
    case red = "Red", green = "Green", violet = "Violet", graphite = "Graphite"
    var id: String { rawValue }

    var accent: Color {
        switch self {
        case .red: return Color(hex: "#FA243C")
        case .green: return Color(hex: "#28A745")
        case .violet: return Color(hex: "#A458DE")
        case .graphite: return Color(hex: "#5C626B")
        }
    }

    var accent2: Color {
        switch self {
        case .red: return Color(hex: "#E01834")
        case .green: return Color(hex: "#1F9D4D")
        case .violet: return Color(hex: "#8A3FF0")
        case .graphite: return Color(hex: "#44484F")
        }
    }

    var soft: Color { accent.opacity(0.12) }

    /// Button/pill gradient — linear-gradient(180deg, light, deep).
    var buttonGradient: LinearGradient {
        let light: Color
        let dark: Color
        switch self {
        case .red:
            light = Color(hex: "#FF4D63"); dark = Color(hex: "#FA243C")
        case .green:
            light = Color(hex: "#42C86A"); dark = Color(hex: "#1F9D4D")
        case .violet:
            light = Color(hex: "#B06BFF"); dark = Color(hex: "#8A3FF0")
        case .graphite:
            light = Color(hex: "#7D828B"); dark = Color(hex: "#565B63")
        }
        return LinearGradient(colors: [light, dark], startPoint: .top, endPoint: .bottom)
    }

    /// App-icon / hero gradient — linear-gradient(155deg, light, accent 55%, deep).
    var heroGradient: LinearGradient {
        let a: Color, b: Color, c: Color
        switch self {
        case .red:
            a = Color(hex: "#FF5A6E"); b = Color(hex: "#FA243C"); c = Color(hex: "#D31331")
        case .green:
            a = Color(hex: "#42C86A"); b = Color(hex: "#1F9D4D"); c = Color(hex: "#127A38")
        case .violet:
            a = Color(hex: "#B06BFF"); b = Color(hex: "#8A3FF0"); c = Color(hex: "#6C25C8")
        case .graphite:
            a = Color(hex: "#7D828B"); b = Color(hex: "#565B63"); c = Color(hex: "#3A3D43")
        }
        return LinearGradient(
            stops: [
                Gradient.Stop(color: a, location: 0),
                Gradient.Stop(color: b, location: 0.55),
                Gradient.Stop(color: c, location: 1)
            ],
            startPoint: UnitPoint(x: 0.15, y: 0),
            endPoint: UnitPoint(x: 0.85, y: 1)
        )
    }
}

/// A 155deg-ish diagonal for the two-stop gradients used in cards, pillars and chips.
func diagonalGradient(_ colors: [Color]) -> LinearGradient {
    LinearGradient(colors: colors,
                   startPoint: UnitPoint(x: 0.15, y: 0),
                   endPoint: UnitPoint(x: 0.85, y: 1))
}

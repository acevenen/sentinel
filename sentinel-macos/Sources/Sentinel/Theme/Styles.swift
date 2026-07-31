import SwiftUI

// MARK: - Accent in the environment

private struct AccentKey: EnvironmentKey {
    static let defaultValue: AccentChoice = .red
}

/// True while rendering offscreen via ImageRenderer (see Snapshotter). AppKit-backed
/// views and ScrollViews don't rasterize offscreen, so they swap in static
/// equivalents that render the same design.
private struct SnapshotModeKey: EnvironmentKey {
    static let defaultValue: Bool = false
}

extension EnvironmentValues {
    var accentChoice: AccentChoice {
        get { self[AccentKey.self] }
        set { self[AccentKey.self] = newValue }
    }
    var snapshotMode: Bool {
        get { self[SnapshotModeKey.self] }
        set { self[SnapshotModeKey.self] = newValue }
    }
}

// MARK: - Shadows

extension View {
    /// card: 0 1px 2px rgba(0,0,0,.05), 0 6px 20px rgba(0,0,0,.05)
    func cardShadow() -> some View {
        self
            .shadow(color: .black.opacity(0.05), radius: 1, y: 1)
            .shadow(color: .black.opacity(0.05), radius: 10, y: 6)
    }

    /// glass control: 0 1px 2px rgba(0,0,0,.05), 0 12px 34px rgba(0,0,0,.12)
    func glassShadow() -> some View {
        self
            .shadow(color: .black.opacity(0.05), radius: 1, y: 1)
            .shadow(color: .black.opacity(0.12), radius: 17, y: 12)
    }

    /// floating sheet: 0 40px 90px rgba(0,0,0,.36)
    func sheetShadow() -> some View {
        self.shadow(color: .black.opacity(0.36), radius: 45, y: 30)
    }
}

// MARK: - Glass control fill

/// The Liquid-Glass control recipe. On the macOS 26 (Tahoe) SDK this is where
/// `.glassEffect()` drops in; on the installed SDK we reproduce the specular
/// white gradient the handoff specifies.
struct GlassFill: View {
    var cornerRadius: CGFloat = Tok.rButton

    var body: some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [Color.white.opacity(0.76), Color.white.opacity(0.58)],
                    startPoint: .top, endPoint: .bottom
                )
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(Color.black.opacity(0.09), lineWidth: 0.5)
            )
            .overlay(alignment: .top) {
                // inset 0 1px 0 rgba(255,255,255,.9) specular highlight
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.9), lineWidth: 1)
                    .mask(LinearGradient(colors: [.white, .clear], startPoint: .top, endPoint: .center))
            }
    }
}

// MARK: - Key hint chip (⌘⏎ etc.)

struct KeyChip: View {
    let text: String
    var light: Bool = false

    var body: some View {
        if !text.isEmpty {
            Text(text)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(light ? Color.white.opacity(0.9) : Tok.secondary)
                .padding(.horizontal, 5).padding(.vertical, 1)
                .background(
                    RoundedRectangle(cornerRadius: 5, style: .continuous)
                        .fill(light ? Color.white.opacity(0.22) : Color.rgba(120, 120, 128, 0.16))
                )
                .padding(.leading, 3)
        }
    }
}

// MARK: - Buttons

/// Glass (secondary) button — matches btnGlass.
struct GlassButton: View {
    let label: String
    var icon: String? = nil
    var key: String = ""
    var fill: Bool = false
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 7) {
                if let icon { Sym(icon, size: 15) }
                Text(label).font(.system(size: 13, weight: .medium))
                KeyChip(text: key)
            }
            .foregroundStyle(Tok.label)
            .padding(.horizontal, 14).padding(.vertical, 8)
            .frame(maxWidth: fill ? .infinity : nil)
            .background(GlassFill(cornerRadius: Tok.rButton))
            .glassShadow()
        }
        .buttonStyle(.plain)
    }
}

/// Accent (primary) button — matches btnPrimary, with danger + spinner + key chip.
struct PrimaryButton: View {
    @Environment(\.accentChoice) private var accent
    let label: String
    var icon: String? = nil
    var key: String = ""
    var danger: Bool = false
    var running: Bool = false
    var fill: Bool = false
    var action: () -> Void

    private var gradient: LinearGradient {
        if danger {
            return LinearGradient(colors: [Color(hex: "#FF6A5F"), Color(hex: "#E5372C")],
                                  startPoint: .top, endPoint: .bottom)
        }
        return accent.buttonGradient
    }

    private var borderColor: Color {
        danger ? Color.rgba(200, 40, 30, 0.6) : accent.accent.opacity(0.55)
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 7) {
                if running {
                    ProgressView().controlSize(.small).tint(.white)
                        .frame(width: 15, height: 15)
                } else if let icon {
                    Sym(icon, size: 16)
                }
                Text(label).font(.system(size: 13, weight: .semibold))
                KeyChip(text: key, light: true)
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 15).padding(.vertical, 8)
            .frame(maxWidth: fill ? .infinity : nil)
            .background(primaryBackground)
            .shadow(color: (danger ? Tok.red : accent.accent).opacity(0.32), radius: 2, y: 1)
        }
        .buttonStyle(.plain)
    }

    private var primaryBackground: some View {
        RoundedRectangle(cornerRadius: Tok.rButton, style: .continuous)
            .fill(gradient)
            .overlay(
                RoundedRectangle(cornerRadius: Tok.rButton, style: .continuous)
                    .strokeBorder(borderColor, lineWidth: 0.5)
            )
            .overlay(alignment: .top) {
                RoundedRectangle(cornerRadius: Tok.rButton, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.35), lineWidth: 1)
                    .mask(LinearGradient(colors: [.white, .clear], startPoint: .top, endPoint: .center))
            }
    }
}

/// Small glass button — btnGlassSm.
struct SmallGlassButton: View {
    let label: String
    var icon: String? = nil
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if let icon { Sym(icon, size: 13) }
                Text(label).font(.system(size: 12, weight: .medium))
            }
            .foregroundStyle(Tok.label)
            .padding(.horizontal, 11).padding(.vertical, 5)
            .background(GlassFill(cornerRadius: Tok.rButtonSm))
            .cardShadow()
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Pills

enum PillKind {
    case good, warn, bad, info

    var fg: Color {
        switch self {
        case .good: return Tok.goodFg
        case .warn: return Tok.warnFg
        case .bad: return Tok.badFg
        case .info: return Tok.infoFg
        }
    }

    var bg: Color {
        switch self {
        case .good: return Tok.goodBg
        case .warn: return Tok.warnBg
        case .bad: return Tok.badBg
        case .info: return Tok.infoBg
        }
    }
}

struct Pill: View {
    let text: String
    let kind: PillKind

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .bold))
            .tracking(0.2)
            .foregroundStyle(kind.fg)
            .padding(.horizontal, 9).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: Tok.rChip, style: .continuous).fill(kind.bg))
    }
}

// MARK: - Rounded tinted icon chip

struct IconChip: View {
    let icon: String
    var size: CGFloat = 22
    var iconSize: CGFloat = 14
    var background: AnyShapeStyle
    var fg: Color = .white
    var radius: CGFloat = Tok.rChip
    var specular: Bool = true

    var body: some View {
        RoundedRectangle(cornerRadius: radius, style: .continuous)
            .fill(background)
            .frame(width: size, height: size)
            .overlay(Sym(icon, size: iconSize).foregroundStyle(fg))
            .overlay(alignment: .top) {
                if specular {
                    RoundedRectangle(cornerRadius: radius, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.25), lineWidth: 1)
                        .mask(LinearGradient(colors: [.white, .clear], startPoint: .top, endPoint: .center))
                }
            }
    }
}

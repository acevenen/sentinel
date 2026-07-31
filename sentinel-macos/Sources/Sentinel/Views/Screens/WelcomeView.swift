import SwiftUI

/// Accent-hero squircle with specular sheen — used on Welcome and the welcome sheet.
struct HeroSquircle: View {
    @Environment(\.accentChoice) private var accent
    var size: CGFloat = 96
    var icon: String = "shield-check"
    var iconSize: CGFloat = 52
    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
            .fill(accent.heroGradient)
            .frame(width: size, height: size)
            .overlay(Sym(icon, size: iconSize, weight: .medium).foregroundStyle(.white))
            .overlay(alignment: .topLeading) {
                LinearGradient(colors: [.white.opacity(0.5), .clear], startPoint: .leading, endPoint: .trailing)
                    .frame(width: size * 0.4)
                    .blendMode(.softLight)
            }
            .overlay(alignment: .top) {
                RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.35), lineWidth: 1)
                    .mask(LinearGradient(colors: [.white, .clear], startPoint: .top, endPoint: .center))
            }
            .clipShape(RoundedRectangle(cornerRadius: size * 0.25, style: .continuous))
            .shadow(color: accent.accent.opacity(0.4), radius: 15, y: 10)
    }
}

struct WelcomeView: View {
    @Environment(AppModel.self) private var model

    struct Card: Identifiable {
        let id = UUID()
        let title: String; let desc: String; let icon: String; let chip: [Color]; let screen: Screen
    }

    private let cards: [Card] = [
        Card(title: "Hunt · IDOR/BOLA",
             desc: "Test an authorized target: can one user read another\u{2019}s objects by changing an ID? Scope-enforced, read-only.",
             icon: "target", chip: [Color(hex: "#3AA0FF"), Color(hex: "#0A6FE8")], screen: .hunt),
        Card(title: "Evaluate an agent",
             desc: "Score an AI agent before deployment against a library of attacks on its declared authority.",
             icon: "gauge", chip: [Color(hex: "#42C86A"), Color(hex: "#1F9D4D")], screen: .evaluate),
        Card(title: "Guard at runtime",
             desc: "Inspect a running agent\u{2019}s tool outputs and verify actions against declared intent.",
             icon: "shield-check", chip: [Color(hex: "#42C86A"), Color(hex: "#1F9D4D")], screen: .guardRuntime),
        Card(title: "Scan a codebase",
             desc: "Static security review with Claude — SQLi, XSS, secrets, and more, tagged with CWE.",
             icon: "file-search", chip: [Color(hex: "#B06BFF"), Color(hex: "#8A3FF0")], screen: .scan)
    ]

    private let columns = [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)]

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 18) {
                HeroSquircle()
                VStack(spacing: 10) {
                    Text("Welcome to Sentinel").font(.system(size: 34, weight: .bold)).tracking(-0.7)
                    lede
                }
            }
            .frame(maxWidth: .infinity)

            LazyVGrid(columns: columns, spacing: 14) {
                ForEach(cards) { card in
                    FeatureCard(card: card) { model.go(card.screen) }
                }
            }
            .padding(.top, 36)

            HStack(spacing: 12) {
                PrimaryButton(label: "Take the guided tour", icon: "wand-sparkles") { model.startTour() }
                GlassButton(label: "Point at a project", icon: "compass") { model.go(.howto) }
            }
            .padding(.top, 26)

            safetyStrip.padding(.top, 30)
        }
        .frame(maxWidth: 840)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 40).padding(.top, 56).padding(.bottom, 60)
    }

    private var lede: some View {
        (
            Text("One question, one platform: ").foregroundStyle(Tok.secondary)
            + Text("is authority being respected?").foregroundStyle(Tok.label).fontWeight(.bold)
            + Text(" Sentinel checks whether AI agents stay in bounds — and whether the APIs behind them enforce it.").foregroundStyle(Tok.secondary)
        )
        .font(.system(size: 17))
        .multilineTextAlignment(.center)
        .lineSpacing(3)
        .frame(maxWidth: 560)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var safetyStrip: some View {
        HStack(alignment: .top, spacing: 13) {
            Sym("lock", size: 19).foregroundStyle(Tok.green).padding(.top, 1)
            (
                Text("Safe by design. ").fontWeight(.bold)
                + Text("Everything runs locally on this Mac. Active tools never leave the scope you declare, never mutate data, and fail closed. Nothing is sent anywhere except the targets you explicitly authorize.")
            )
            .font(.system(size: 13)).foregroundStyle(Tok.label).lineSpacing(3)
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .background(
            RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous)
                .fill(LinearGradient(colors: [Tok.green.opacity(0.09), Tok.green.opacity(0.04)], startPoint: .top, endPoint: .bottom))
                .overlay(RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous).strokeBorder(Tok.green.opacity(0.22), lineWidth: 0.5))
        )
    }
}

struct FeatureCard: View {
    @Environment(\.accentChoice) private var accent
    let card: WelcomeView.Card
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 11) {
                IconChip(icon: card.icon, size: 42, iconSize: 22, background: AnyShapeStyle(diagonalGradient(card.chip)), radius: 11)
                Text(card.title).font(.system(size: 16, weight: .semibold))
                Text(card.desc).font(.system(size: 13)).foregroundStyle(Tok.secondary).lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 4) {
                    Text("Open").font(.system(size: 12.5, weight: .semibold))
                    Sym("arrow-right", size: 14)
                }
                .foregroundStyle(accent.accent)
                .padding(.top, 2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(
                RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous).fill(Color.white)
                    .overlay(RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous)
                        .strokeBorder(hover ? Tok.authorizedBlue.opacity(0.3) : Tok.separator, lineWidth: 0.5))
            )
            .cardShadow()
            .offset(y: hover ? -2 : 0)
        }
        .buttonStyle(.plain)
        .animation(.easeOut(duration: 0.18), value: hover)
        .onHover { hover = $0 }
    }
}

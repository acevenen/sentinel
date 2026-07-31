import SwiftUI

// MARK: - Welcome sheet (first launch)

struct WelcomeSheet: View {
    @Environment(AppModel.self) private var model

    struct Pillar: Identifiable { let id = UUID(); let title: String; let desc: String; let icon: String; let chip: [Color] }
    private let pillars: [Pillar] = [
        Pillar(title: "Authorization-first", desc: "Models and tools suggest; trusted code decides what is allowed.",
               icon: "shield-check", chip: [Color(hex: "#3AA0FF"), Color(hex: "#0A6FE8")]),
        Pillar(title: "Local & fail-closed", desc: "Runs on your Mac. Missing or unverifiable consent fails closed.",
               icon: "lock", chip: [Color(hex: "#42C86A"), Color(hex: "#1F9D4D")]),
        Pillar(title: "Dry-run everything", desc: "See the exact argv and scope decision before a single packet is sent.",
               icon: "file-scan", chip: [Color(hex: "#FF9F43"), Color(hex: "#F37B1D")]),
        Pillar(title: "Report-ready", desc: "HackerOne-ready findings, SARIF, Markdown, and a hash-chained audit.",
               icon: "file-check-2", chip: [Color(hex: "#B06BFF"), Color(hex: "#8A3FF0")])
    ]

    var body: some View {
        ModalScrim {
            VStack(spacing: 0) {
                ZStack(alignment: .topTrailing) {
                    VStack(spacing: 0) {
                        HeroSquircle(size: 80, icon: "shield-check", iconSize: 44).padding(.bottom, 16)
                        Text("Welcome to Sentinel").font(.system(size: 24, weight: .bold)).tracking(-0.5)
                        Text("Authorization-first security operations, native to your Mac.")
                            .font(.system(size: 14)).foregroundStyle(Tok.secondary).multilineTextAlignment(.center)
                            .padding(.top, 6)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 34).padding(.horizontal, 38).padding(.bottom, 26)

                    Button { model.welcomeOpen = false } label: {
                        Sym("x", size: 15).foregroundStyle(Tok.secondary)
                            .frame(width: 26, height: 26)
                            .background(Circle().fill(Color.black.opacity(0.06)))
                    }
                    .buttonStyle(.plain).padding(16)
                }

                VStack(spacing: 2) {
                    ForEach(pillars) { p in
                        HStack(spacing: 14) {
                            IconChip(icon: p.icon, size: 38, iconSize: 20, background: AnyShapeStyle(diagonalGradient(p.chip)), radius: 10)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(p.title).font(.system(size: 14, weight: .semibold))
                                Text(p.desc).font(.system(size: 12.5)).foregroundStyle(Tok.secondary)
                            }
                            Spacer()
                        }
                        .padding(.horizontal, 8).padding(.vertical, 11)
                    }
                }
                .padding(.horizontal, 34)

                HStack(spacing: 10) {
                    GlassButton(label: "Get started", fill: true) { model.welcomeOpen = false }
                    PrimaryButton(label: "Take the tour", icon: "wand-sparkles", fill: true) { model.startTour() }
                }
                .padding(.horizontal, 34).padding(.top, 20).padding(.bottom, 30)
            }
            .frame(width: 560)
            .background(GlassSheetBackground(cornerRadius: 22))
        }
    }
}

// MARK: - Authorize sheet (high guardrail)

struct AuthorizeSheet: View {
    @Environment(AppModel.self) private var model
    private let checks = [
        "Target is inside the declared scope",
        "Engagement is attested and current",
        "This action will be confirmed and audited"
    ]

    var body: some View {
        ModalScrim {
            VStack(spacing: 0) {
                VStack(spacing: 0) {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(LinearGradient(stops: [
                            .init(color: Color(hex: "#FF6A5F"), location: 0),
                            .init(color: Color(hex: "#FF3B30"), location: 0.6),
                            .init(color: Color(hex: "#D92417"), location: 1)
                        ], startPoint: UnitPoint(x: 0.15, y: 0), endPoint: UnitPoint(x: 0.85, y: 1)))
                        .frame(width: 60, height: 60)
                        .overlay(Sym("shield-alert", size: 32, weight: .medium).foregroundStyle(.white))
                        .shadow(color: Tok.red.opacity(0.4), radius: 11, y: 8)
                        .padding(.bottom, 14)
                    Text("Authorize active action?").font(.system(size: 19, weight: .bold))
                    Text("This is the highest guardrail tier. It requires current consent, verified scope, and an attested engagement.")
                        .font(.system(size: 13.5)).foregroundStyle(Tok.secondary).multilineTextAlignment(.center).lineSpacing(2)
                        .padding(.top, 6)
                }
                .padding(.top, 26).padding(.horizontal, 28)

                VStack(alignment: .leading, spacing: 9) {
                    ForEach(checks, id: \.self) { check in
                        HStack(spacing: 9) {
                            Sym("circle-check-big", size: 16).foregroundStyle(Tok.green)
                            Text(check).font(.system(size: 13))
                            Spacer(minLength: 0)
                        }
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 14)
                .background(RoundedRectangle(cornerRadius: Tok.rField).fill(Color.rgba(120, 120, 128, 0.08)))
                .padding(.horizontal, 24).padding(.top, 18)

                HStack(spacing: 10) {
                    GlassButton(label: "Cancel", fill: true) { model.confirmOpen = false }
                    PrimaryButton(label: "Authorize & run", icon: "shield-check", danger: true, fill: true) { model.confirmRun() }
                }
                .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 24)
            }
            .frame(width: 440)
            .background(GlassSheetBackground(cornerRadius: 20))
        }
    }
}

// MARK: - Shared modal chrome

struct ModalScrim<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        ZStack {
            Color.black.opacity(0.3).ignoresSafeArea()
            content.sheetShadow()
        }
        .transition(.opacity)
    }
}

struct GlassSheetBackground: View {
    var cornerRadius: CGFloat
    var body: some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .fill(.thickMaterial)
            .overlay(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous).fill(Color.white.opacity(0.4)))
            .overlay(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous).strokeBorder(Color.white.opacity(0.6), lineWidth: 0.5))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
    }
}

// MARK: - Guided tour overlay

struct GuidedTourOverlay: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accentChoice) private var accent
    let anchors: [TourTarget: Anchor<CGRect>]
    let proxy: GeometryProxy

    private var step: TourStep { ToolCatalog.tourSteps[model.tourStep] }

    private enum Side { case right, below, above }
    private var side: Side {
        switch step.target {
        case .sidebar: return .right
        case .inputBox, .boxToolbar: return .below
        case .runButton, .dock: return .above
        }
    }

    private var targetRect: CGRect? {
        guard let a = anchors[step.target] else { return nil }
        return proxy[a]
    }

    var body: some View {
        let size = proxy.size
        ZStack(alignment: .topLeading) {
            if let r = targetRect, step.target != .dock {
                let hole = r.insetBy(dx: -6, dy: -6)
                // Dimmed scrim with a punched-out spotlight.
                Color.black.opacity(0.5).ignoresSafeArea()
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .frame(width: hole.width, height: hole.height)
                            .position(x: hole.midX, y: hole.midY)
                            .blendMode(.destinationOut)
                    )
                    .compositingGroup()
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(Tok.authorizedBlue.opacity(0.9), lineWidth: 3)
                    .frame(width: hole.width, height: hole.height)
                    .position(x: hole.midX, y: hole.midY)
                    .onTapGesture { model.nextTour() }
                calloutCard
                    .position(cardPosition(for: hole, in: size))
                    .animation(.spring(response: 0.35, dampingFraction: 0.8), value: model.tourStep)
            } else {
                Color.black.opacity(0.55).ignoresSafeArea()
                calloutCard.position(x: size.width / 2, y: size.height / 2)
            }
        }
    }

    private func cardPosition(for hole: CGRect, in size: CGSize) -> CGPoint {
        let cardW: CGFloat = 300, cardH: CGFloat = 165
        var x: CGFloat, y: CGFloat
        switch side {
        case .right:
            x = hole.maxX + 16 + cardW / 2
            y = hole.minY + 40 + cardH / 2
        case .below:
            x = min(hole.minX, size.width - 330) + cardW / 2
            y = hole.maxY + 14 + cardH / 2
        case .above:
            x = min(max(12, hole.minX), size.width - 330) + cardW / 2
            y = max(50, hole.minY - 190) + cardH / 2
        }
        x = min(max(cardW / 2 + 8, x), size.width - cardW / 2 - 8)
        y = min(max(cardH / 2 + 8, y), size.height - cardH / 2 - 8)
        return CGPoint(x: x, y: y)
    }

    private var calloutCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Sym(step.icon, size: 15)
                Text(step.kicker).font(.system(size: 12, weight: .semibold))
            }
            .foregroundStyle(accent.accent)

            Text(step.title).font(.system(size: 16.5, weight: .bold)).tracking(-0.2).padding(.top, 8)
            Text(step.body).font(.system(size: 13)).foregroundStyle(Tok.secondary).lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true).padding(.top, 6)

            HStack(spacing: 8) {
                HStack(spacing: 5) {
                    ForEach(0..<ToolCatalog.tourSteps.count, id: \.self) { i in
                        Capsule().fill(i == model.tourStep ? accent.accent : Color.rgba(60, 60, 67, 0.24))
                            .frame(width: i == model.tourStep ? 18 : 6, height: 6)
                            .animation(.easeOut(duration: 0.3), value: model.tourStep)
                    }
                }
                Spacer()
                Button("Skip") { model.endTour() }
                    .buttonStyle(.plain).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Tok.secondary)
                Button {
                    model.nextTour()
                } label: {
                    HStack(spacing: 5) {
                        Text(step.next).font(.system(size: 12.5, weight: .semibold))
                        Sym("arrow-right", size: 14)
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(RoundedRectangle(cornerRadius: Tok.rButtonSm).fill(accent.accent))
                }
                .buttonStyle(.plain)
            }
            .padding(.top, 16)
        }
        .padding(.horizontal, 20).padding(.vertical, 18)
        .frame(width: 300)
        .background(GlassSheetBackground(cornerRadius: 16))
        .shadow(color: .black.opacity(0.3), radius: 25, y: 20)
    }
}

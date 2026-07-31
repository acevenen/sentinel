import SwiftUI

struct ToolScreen: View {
    @Environment(AppModel.self) private var model
    let tool: ToolSpec

    private var isHunt: Bool { tool.screen == .hunt }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            if let banner = tool.banner {
                bannerView(banner)
                    .padding(.top, 18)
            }

            if let tabs = tool.tabs {
                tabBar(tabs).padding(.top, 20)
            }

            VStack(alignment: .leading, spacing: 16) {
                ForEach(model.visibleFields(for: tool.screen)) { field in
                    FieldView(field: field)
                }

                if isHunt && model.huntTab == "run" {
                    TokenFieldsView(identities: ["alice", "bob"])
                }

                actionsRow

                if let result = model.results[tool.screen] {
                    ResultSection(result: result)
                }
            }
            .padding(.top, 18)
        }
        .frame(maxWidth: 800, alignment: .leading)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 40)
        .padding(.top, 30).padding(.bottom, 64)
        .onAppear { model.seedFields(for: tool.screen) }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                HStack(spacing: 6) {
                    Circle().fill(tool.tier.color).frame(width: 6, height: 6)
                    Text(tool.tier.label).font(.system(size: 12, weight: .semibold))
                }
                .foregroundStyle(tool.tier.color)
                .padding(.horizontal, 10).padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: Tok.rPill).fill(tool.tier.color.opacity(0.11)))

                HStack(spacing: 5) {
                    Sym("radio-tower", size: 12)
                    Text(tool.consent).font(.system(size: 12))
                }
                .foregroundStyle(Tok.secondary)
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: Tok.rPill).fill(Color.rgba(120, 120, 128, 0.1)))
            }

            Text(tool.name).font(.system(size: 25, weight: .bold)).tracking(-0.5).padding(.top, 13)
            Text(tool.sub).font(.system(size: 14.5)).foregroundStyle(Tok.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 640, alignment: .leading)
                .padding(.top, 5)
        }
    }

    private func bannerView(_ text: String) -> some View {
        let color = tool.bannerColor ?? Tok.authorizedBlue
        return HStack(alignment: .top, spacing: 12) {
            Sym(tool.bannerIcon ?? "info", size: 18).foregroundStyle(color)
            Text(text).font(.system(size: 13)).foregroundStyle(Tok.label).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 14)
        .background(
            RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).fill(color.opacity(0.07))
                .overlay(RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).strokeBorder(color.opacity(0.2), lineWidth: 0.5))
        )
    }

    // MARK: Tabs (hunt)

    private func tabBar(_ tabs: [String]) -> some View {
        HStack(spacing: 2) {
            ForEach(tabs, id: \.self) { tab in
                let active = model.huntTab == tab
                Button {
                    model.huntTab = tab
                    model.seedFields(for: .hunt)
                } label: {
                    Text(tab.capitalized)
                        .font(.system(size: 12.5, weight: active ? .semibold : .medium))
                        .foregroundStyle(active ? Tok.label : Tok.secondary)
                        .padding(.horizontal, 15).padding(.vertical, 5)
                        .background(
                            RoundedRectangle(cornerRadius: Tok.rButtonSm, style: .continuous)
                                .fill(active ? Color.white : Color.clear)
                                .shadow(color: active ? .black.opacity(0.12) : .clear, radius: 1, y: 1)
                        )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.rgba(120, 120, 128, 0.12)))
    }

    // MARK: Actions

    private struct ActionConfig { let label: String; let icon: String; let key: String; var danger = false }

    private var primaryConfig: ActionConfig {
        if isHunt {
            switch model.huntTab {
            case "import": return ActionConfig(label: "Generate manifest", icon: "arrow-right", key: "⌘⏎")
            case "manifest": return ActionConfig(label: "Continue to run", icon: "arrow-right", key: "⌘⏎")
            default: return ActionConfig(label: "Run test", icon: "play", key: "⌘⏎")
            }
        }
        return ActionConfig(label: tool.primary.label, icon: tool.primary.icon, key: tool.primary.key, danger: tool.primary.danger)
    }

    private var secondaryConfig: ActionConfig? {
        if isHunt {
            return model.huntTab == "run" ? ActionConfig(label: "Dry-run (send nothing)", icon: "file-scan", key: "⌘D") : nil
        }
        guard let s = tool.secondary else { return nil }
        return ActionConfig(label: s.label, icon: s.icon, key: s.key)
    }

    private var actionsRow: some View {
        HStack(spacing: 10) {
            if let s = secondaryConfig {
                GlassButton(label: s.label, icon: s.icon, key: s.key) { model.dryRun() }
            }
            PrimaryButton(label: primaryConfig.label, icon: primaryConfig.icon, key: primaryConfig.key,
                          danger: primaryConfig.danger, running: model.running) {
                model.primaryAction()
            }
            .tourAnchor(.runButton)

            Spacer()

            HStack(spacing: 5) {
                Sym("lock-keyhole", size: 12)
                Text(tool.foot).font(.system(size: 11.5))
            }
            .foregroundStyle(Tok.tertiary)
        }
        .padding(.top, 2)
    }
}

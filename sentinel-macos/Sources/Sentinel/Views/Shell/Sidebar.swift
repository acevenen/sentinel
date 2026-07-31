import SwiftUI

/// The grouped rows, factored out of the ScrollView so they can also be rendered
/// offscreen (ImageRenderer does not rasterize ScrollView content).
struct SidebarContent: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(ToolCatalog.groups) { group in
                Text(group.label)
                    .font(.system(size: 11, weight: .semibold)).tracking(0.3)
                    .foregroundStyle(Tok.tertiary).textCase(.uppercase)
                    .padding(.horizontal, 8).padding(.top, 15).padding(.bottom, 4)

                ForEach(group.items) { screen in
                    SidebarRow(screen: screen, selected: model.selected == screen) {
                        model.go(screen)
                    }
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.bottom, 12)
    }
}

struct SidebarView: View {
    @Environment(\.snapshotMode) private var snapshotMode

    var body: some View {
        Group {
            if snapshotMode {
                VStack(spacing: 0) {
                    SidebarContent()
                    Spacer(minLength: 0)
                    footer
                }
            } else {
                ScrollView { SidebarContent() }
                    .scrollContentBackground(.hidden)
                    .safeAreaInset(edge: .bottom) { footer }
            }
        }
        .tourAnchor(.sidebar)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Circle().fill(Tok.green).frame(width: 7, height: 7)
                .shadow(color: Tok.green.opacity(0.7), radius: 3)
            Text("sentinel v1.4.0").font(.system(size: 11.5)).foregroundStyle(Tok.secondary)
            Spacer()
            Text("L3 judge")
                .font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Tok.secondary)
                .padding(.horizontal, 7).padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: Tok.rChip).fill(Color.rgba(120, 120, 128, 0.14)))
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .overlay(alignment: .top) { Rectangle().fill(Tok.separator).frame(height: 0.5) }
        .background(.ultraThinMaterial)
    }
}

struct SidebarRow: View {
    @Environment(\.accentChoice) private var accent
    let screen: Screen
    let selected: Bool
    let action: () -> Void
    @State private var hover = false

    private var tint: Color { ToolCatalog.tintFor(screen) }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                IconChip(icon: ToolCatalog.iconFor(screen), size: 22, iconSize: 14,
                         background: AnyShapeStyle(selected ? Color.white.opacity(0.22) : tint.opacity(0.12)),
                         fg: selected ? .white : tint, radius: Tok.rChip, specular: selected)
                Text(ToolCatalog.nameFor(screen))
                    .font(.system(size: 13.5, weight: selected ? .semibold : .regular))
                    .foregroundStyle(selected ? .white : Tok.label)
                    .lineLimit(1)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 9).padding(.vertical, 6)
            .background(rowBackground)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 1)
        .onHover { hover = $0 }
    }

    @ViewBuilder private var rowBackground: some View {
        if selected {
            RoundedRectangle(cornerRadius: Tok.rButtonSm, style: .continuous)
                .fill(accent.buttonGradient)
                .shadow(color: .black.opacity(0.16), radius: 1, y: 1)
        } else {
            RoundedRectangle(cornerRadius: Tok.rButtonSm, style: .continuous)
                .fill(hover ? Color.black.opacity(0.05) : Color.clear)
        }
    }
}

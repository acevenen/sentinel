import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model

        NavigationSplitView(columnVisibility: $model.columnVisibility) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 220, ideal: 250, max: 300)
        } detail: {
            detail
        }
        .navigationTitle(ToolCatalog.nameFor(model.selected))
        .navigationSubtitle(ToolCatalog.crumbFor(model.selected))
        .toolbar { toolbarContent }
        .environment(\.accentChoice, model.accent)
        .tint(model.accent.accent)
        .overlayPreferenceValue(TourAnchorKey.self) { anchors in
            GeometryReader { proxy in
                ZStack {
                    if model.welcomeOpen { WelcomeSheet() }
                    if model.confirmOpen { AuthorizeSheet() }
                    if model.tourActive { GuidedTourOverlay(anchors: anchors, proxy: proxy) }
                }
                .animation(.easeOut(duration: 0.25), value: model.welcomeOpen)
                .animation(.easeOut(duration: 0.25), value: model.confirmOpen)
                .animation(.easeOut(duration: 0.25), value: model.tourActive)
            }
        }
    }

    private var detail: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Color.clear.frame(height: 0).id("top")
                Group {
                    switch model.selected {
                    case .welcome: WelcomeView()
                    case .howto: HowToView()
                    case .doctor: DoctorView()
                    case .engagements: EngagementsView()
                    default:
                        if let tool = ToolCatalog.tools[model.selected] {
                            ToolScreen(tool: tool)
                        }
                    }
                }
                .transition(.opacity.combined(with: .offset(y: 8)))
                .id(model.selected)
            }
            .background(Tok.content)
            .onChange(of: model.selected) { _, _ in
                proxy.scrollTo("top", anchor: .top)
            }
            .animation(.easeOut(duration: 0.28), value: model.selected)
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button { model.toggleSidebar() } label: { Sym("panel-left", size: 17) }
                .help("Toggle Sidebar")
        }
        ToolbarItem(placement: .principal) {
            HStack(spacing: 10) {
                IconChip(icon: ToolCatalog.iconFor(model.selected), size: 26, iconSize: 15,
                         background: AnyShapeStyle(ToolCatalog.tintFor(model.selected)), radius: Tok.rPill)
                VStack(alignment: .leading, spacing: 0) {
                    Text(ToolCatalog.nameFor(model.selected))
                        .font(.system(size: 14, weight: .semibold)).tracking(-0.1)
                    Text(ToolCatalog.crumbFor(model.selected))
                        .font(.system(size: 11.5)).foregroundStyle(Tok.secondary)
                }
            }
        }
        ToolbarItem { Spacer() }
        ToolbarItem(placement: .automatic) {
            Button {} label: { Sym("info", size: 17) }.help("Info")
        }
        ToolbarItem(placement: .automatic) {
            Button {} label: { Sym("square-arrow-out-up-right", size: 16) }.help("Share / Export report")
        }
    }
}

/// Search field is a real toolbar search in the native app (⌘F focuses it).
struct ToolbarSearchField: View {
    @Binding var text: String
    var body: some View {
        HStack(spacing: 6) {
            Sym("search", size: 14).foregroundStyle(Tok.secondary)
            TextField("Search", text: $text)
                .textFieldStyle(.plain)
                .font(.system(size: 12.5))
            Text("⌘F").font(.system(size: 11)).foregroundStyle(Tok.secondary.opacity(0.7))
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .frame(width: 200)
        .background(RoundedRectangle(cornerRadius: Tok.rButtonSm).fill(Color.rgba(120, 120, 128, 0.1)))
    }
}

import SwiftUI
import AppKit

/// Entry point. Normally launches the app; `--snapshot <dir>` renders the screens
/// offscreen to PNGs instead (see Snapshotter).
@main
enum SentinelMain {
    static func main() {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--snapshot") {
            let dir = i + 1 < args.count ? args[i + 1] : "./snapshots"
            MainActor.assumeIsolated { Snapshotter.run(outputDir: dir) }
            return
        }
        SentinelApp.main()
    }
}

struct SentinelApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        Window("Sentinel", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1280, height: 820)
        .windowToolbarStyle(.unified)
        .commands { SentinelCommands(model: model) }

        Settings {
            SettingsView().environment(model)
        }
    }
}

// MARK: - Menu bar

struct SentinelCommands: Commands {
    @Bindable var model: AppModel

    var body: some Commands {
        // File
        CommandGroup(replacing: .newItem) {
            Button("New Engagement…") { model.go(.engagements) }.keyboardShortcut("n")
            Button("Import HAR…") { model.go(.hunt); model.huntTab = "import" }
                .keyboardShortcut("i", modifiers: [.command, .shift])
            Button("Open Manifest…") { model.go(.hunt); model.huntTab = "manifest" }.keyboardShortcut("o")
            Divider()
            Button("Export Report…") { exportReport() }.keyboardShortcut("e")
            Button("Save Audit Log…") {}.keyboardShortcut("s", modifiers: [.command, .shift])
        }

        // Edit
        CommandGroup(after: .pasteboard) {
            Divider()
            Button("Clear All Fields") { model.clearAllFields() }
                .keyboardShortcut(.delete, modifiers: [.command, .option])
        }

        // View
        CommandGroup(after: .sidebar) {
            Button("Toggle Sidebar") { model.toggleSidebar() }
                .keyboardShortcut("s", modifiers: [.command, .control])
        }

        // Feature menus — each navigates to that screen.
        CommandMenu("Defense") {
            navButton(.scan, "1"); navButton(.guardRuntime, "2"); navButton(.evaluate, "3")
        }
        CommandMenu("Testing") {
            navButton(.hunt, "4"); navButton(.recon, "5"); navButton(.traffic, "6"); navButton(.test, "7")
        }
        CommandMenu("Advanced") {
            navButton(.exploit, nil); navButton(.creds, nil); navButton(.wireless, nil); navButton(.se, nil)
        }
        CommandMenu("AI") {
            navButton(.aiRedteam, nil); navButton(.orchestrate, nil)
        }
        CommandMenu("Operations") {
            navButton(.engagements, nil); navButton(.ctf, nil); navButton(.bounty, nil); navButton(.doctor, nil)
        }

        // Help
        CommandGroup(replacing: .help) {
            Button("Sentinel Help") { model.go(.howto) }
            Button("Take the Tour…") { model.startTour() }
            Button("Point at a Project") { model.go(.howto) }
            Divider()
            Button("Safety & Authorization") { openDoc("SAFETY.md") }
            Button("Command Reference") { openDoc("COMMANDS.md") }
        }
    }

    private func navButton(_ screen: Screen, _ key: String?) -> some View {
        let b = Button(ToolCatalog.nameFor(screen)) { model.go(screen) }
        if let key { return AnyView(b.keyboardShortcut(KeyEquivalent(Character(key)), modifiers: .command)) }
        return AnyView(b)
    }

    private func exportReport() {
        guard let result = model.results[model.selected] else { return }
        let text = result.report ?? result.argv?.argv ?? ""
        guard !text.isEmpty else { return }
        model.setClipboard(text)
    }

    private func openDoc(_ name: String) {
        if let url = URL(string: "https://github.com/acevenen/sentinel/blob/main/docs/\(name)") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section("Appearance") {
                Picker("Accent color", selection: $model.accent) {
                    ForEach(AccentChoice.allCases) { choice in
                        HStack {
                            Circle().fill(choice.accent).frame(width: 10, height: 10)
                            Text(choice.rawValue)
                        }.tag(choice)
                    }
                }
                Toggle("Show welcome window on launch", isOn: $model.showWelcomeOnLaunch)
            }
            Section("Engine") {
                LabeledContent("sentinel binary") {
                    Text(SentinelEngine.binaryURL()?.path ?? "not found — set SENTINEL_BIN")
                        .font(Tok.monoFont(11.5)).foregroundStyle(Tok.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
                Text("`ANTHROPIC_API_KEY` and session tokens are read from the environment and kept in memory only — Sentinel never writes them to disk.")
                    .font(.system(size: 11.5)).foregroundStyle(Tok.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 280)
    }
}

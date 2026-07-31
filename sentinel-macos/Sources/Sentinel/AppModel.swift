import SwiftUI
import AppKit
import Observation

struct FieldStatus {
    let msg: String
    let color: Color
    let icon: String
}

@MainActor
@Observable
final class AppModel {
    // Navigation & chrome
    var selected: Screen = .welcome
    var huntTab: String = "import"
    var columnVisibility: NavigationSplitViewVisibility = .all

    // Run state / results
    var running = false
    var results: [Screen: ToolResult] = [:]

    // Field state
    var fieldText: [String: String] = [:]
    var toggles: [String: Bool] = [:]
    var fieldStatus: [String: FieldStatus] = [:]

    // Overlays
    var welcomeOpen: Bool
    var tourActive = false
    var tourStep = 0
    var confirmOpen = false

    // Settings
    var accent: AccentChoice {
        didSet { UserDefaults.standard.set(accent.rawValue, forKey: "accent") }
    }
    var showWelcomeOnLaunch: Bool {
        didSet { UserDefaults.standard.set(showWelcomeOnLaunch, forKey: "showWelcome") }
    }

    @ObservationIgnored private var statusTasks: [String: Task<Void, Never>] = [:]
    @ObservationIgnored private var runTask: Task<Void, Never>?

    init() {
        let d = UserDefaults.standard
        accent = AccentChoice(rawValue: d.string(forKey: "accent") ?? "Red") ?? .red
        let show = d.object(forKey: "showWelcome") as? Bool ?? true
        showWelcomeOnLaunch = show
        welcomeOpen = show
    }

    // MARK: - Navigation

    func go(_ screen: Screen) {
        selected = screen
        welcomeOpen = false
        tourActive = false
        huntTab = "import"
        seedFields(for: screen)
    }

    func toggleSidebar() {
        columnVisibility = (columnVisibility == .detailOnly) ? .all : .detailOnly
    }

    // MARK: - Fields

    /// Which fields are visible for a screen right now (hunt varies by tab).
    func visibleFields(for screen: Screen) -> [Field] {
        if screen == .hunt { return ToolCatalog.huntFields(tab: huntTab) }
        return ToolCatalog.tools[screen]?.fields ?? []
    }

    /// Seed code/text/select fields with their initial content on first appearance.
    func seedFields(for screen: Screen) {
        for f in visibleFields(for: screen) {
            switch f.kind {
            case .code, .text:
                if fieldText[f.id] == nil { fieldText[f.id] = f.initialText() }
            case .select:
                if fieldText[f.id] == nil { fieldText[f.id] = f.options.first ?? "" }
            default:
                break
            }
        }
    }

    func binding(for id: String) -> Binding<String> {
        Binding(
            get: { self.fieldText[id] ?? "" },
            set: { self.fieldText[id] = $0 }
        )
    }

    func toggleBinding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { self.toggles[id] ?? false },
            set: { self.toggles[id] = $0 }
        )
    }

    func flash(_ id: String, _ msg: String, _ color: Color, _ icon: String) {
        fieldStatus[id] = FieldStatus(msg: msg, color: color, icon: icon)
        statusTasks[id]?.cancel()
        statusTasks[id] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_900_000_000)
            guard !Task.isCancelled else { return }
            self?.fieldStatus[id] = nil
        }
    }

    func copyField(_ id: String) {
        setClipboard(fieldText[id] ?? "")
        flash(id, "Copied", Tok.authorizedBlue, "copy")
    }

    func clearField(_ id: String) {
        fieldText[id] = ""
        flash(id, "Cleared", Tok.red, "eraser")
    }

    func loadSample(_ id: String, key: String?) {
        guard let key else { return }
        fieldText[id] = Samples.map[key] ?? ""
    }

    func validate(_ id: String, lang: String?) {
        let v = (fieldText[id] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if v.isEmpty { flash(id, "Empty", Tok.orange, "triangle-alert"); return }
        if lang == "json" || lang == "jsonl" {
            let lines = lang == "jsonl" ? v.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty } : [v]
            let ok = lines.allSatisfy { line in
                guard let data = line.data(using: .utf8) else { return false }
                return (try? JSONSerialization.jsonObject(with: data)) != nil
            }
            if ok { flash(id, "Valid " + (lang ?? "").uppercased(), Tok.green, "badge-check") }
            else { flash(id, "Invalid JSON", Tok.red, "circle-x") }
            return
        }
        // YAML / msf-rc: the prototype's lightweight check (tabs are illegal in YAML).
        let bad = v.contains("\t")
        flash(id, bad ? "Tabs not allowed in YAML" : "Looks well-formed", bad ? Tok.red : Tok.green, bad ? "circle-x" : "badge-check")
    }

    func toggle(_ id: String) { toggles[id] = !(toggles[id] ?? false) }

    func clearAllFields() {
        for f in visibleFields(for: selected) where f.kind == .code || f.kind == .text {
            clearField(f.id)
        }
    }

    // MARK: - Clipboard

    func setClipboard(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    // MARK: - Run

    func primaryAction() {
        if selected == .hunt {
            switch huntTab {
            case "import": huntTab = "manifest"; seedFields(for: .hunt)
            case "manifest": huntTab = "run"
            default: run(mode: .run)
            }
            return
        }
        if let tool = ToolCatalog.tools[selected], tool.confirm {
            confirmOpen = true
            return
        }
        run(mode: .run)
    }

    func dryRun() { run(mode: .dry) }

    func confirmRun() { confirmOpen = false; run(mode: .run) }

    private func run(mode: RunMode) {
        let screen = selected
        running = true
        runTask?.cancel()
        runTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 750_000_000)
            guard let self, !Task.isCancelled else { return }
            self.results[screen] = ResultCatalog.result(for: screen, mode: mode)
            self.running = false
        }
    }

    // MARK: - Tour

    func startTour() {
        go(.guardRuntime)
        welcomeOpen = false
        tourStep = 0
        tourActive = true
    }
    func nextTour() {
        if tourStep + 1 >= ToolCatalog.tourSteps.count { tourActive = false }
        else { tourStep += 1 }
    }
    func endTour() { tourActive = false }
}

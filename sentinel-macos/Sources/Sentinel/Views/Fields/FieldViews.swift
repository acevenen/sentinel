import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - Code box

struct CodeBoxView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.snapshotMode) private var snapshotMode
    let field: Field

    private var status: FieldStatus? { model.fieldStatus[field.id] }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            // Header
            HStack(spacing: 10) {
                Text(field.label).font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.label)
                if let lang = field.lang {
                    Text(lang.uppercased())
                        .font(.system(size: 10.5, weight: .bold)).tracking(0.4)
                        .foregroundStyle(Tok.tertiary)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(RoundedRectangle(cornerRadius: 5).fill(Color.rgba(120, 120, 128, 0.13)))
                }
                Spacer()
                if field.hasSample {
                    HoverTextButton(icon: "sparkles", label: "Load sample") {
                        model.loadSample(field.id, key: field.sample)
                    }
                }
            }

            // Box: editor + footer toolbar
            VStack(spacing: 0) {
                Group {
                    if snapshotMode {
                        StaticCodeView(text: model.fieldText[field.id] ?? "", minHeight: field.minHeight)
                    } else {
                        CodeEditor(text: model.binding(for: field.id), minHeight: field.minHeight)
                    }
                }
                .frame(height: field.minHeight)
                .tourAnchorIf(field.id == "guard-intent", .inputBox)

                footer
                    .tourAnchorIf(field.id == "guard-stream", .boxToolbar)
            }
            .background(Tok.fieldBg)
            .clipShape(RoundedRectangle(cornerRadius: Tok.rField, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
            .modifier(FileDropModifier(enabled: !snapshotMode, onDrop: loadDroppedFile))
        }
    }

    private var footer: some View {
        HStack(spacing: 6) {
            HStack(spacing: 5) {
                Sym("corner-down-left", size: 12)
                Text("\((model.fieldText[field.id] ?? "").count) chars")
            }
            .font(Tok.monoFont(11.5)).foregroundStyle(Tok.tertiary)

            HStack(spacing: 4) {
                Sym("upload", size: 12)
                Text("drag & drop a file")
            }
            .font(.system(size: 11)).foregroundStyle(Tok.tertiary)

            if let s = status {
                HStack(spacing: 4) {
                    Sym(s.icon, size: 12)
                    Text(s.msg)
                }
                .font(.system(size: 11.5, weight: .semibold)).foregroundStyle(s.color)
                .transition(.opacity)
            }

            Spacer()

            CodeToolbarButton(icon: "badge-check", label: "Validate", danger: false) { model.validate(field.id, lang: field.lang) }
            CodeToolbarButton(icon: "copy", label: "Copy", danger: false) { model.copyField(field.id) }
            CodeToolbarButton(icon: "eraser", label: "Clear all", danger: true) { model.clearField(field.id) }
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(Color.rgba(250, 250, 252, 0.7))
        .overlay(alignment: .top) { Rectangle().fill(Tok.separator).frame(height: 0.5) }
        .animation(.easeOut(duration: 0.15), value: status?.msg)
    }

    private func loadDroppedFile(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        _ = provider.loadObject(ofClass: URL.self) { url, _ in
            guard let url, let content = try? String(contentsOf: url, encoding: .utf8) else { return }
            Task { @MainActor in
                model.fieldText[field.id] = content
                model.flash(field.id, "Loaded \(url.lastPathComponent)", Tok.authorizedBlue, "upload")
            }
        }
        return true
    }
}

/// Attaches the file drop target. Disabled while snapshotting: the AppKit-backed
/// drop target renders as an unsupported-view placeholder in ImageRenderer.
private struct FileDropModifier: ViewModifier {
    let enabled: Bool
    let onDrop: ([NSItemProvider]) -> Bool

    func body(content: Content) -> some View {
        if enabled {
            content.onDrop(of: [.fileURL], isTargeted: nil) { onDrop($0) }
        } else {
            content
        }
    }
}

private struct CodeToolbarButton: View {
    let icon: String
    let label: String
    let danger: Bool
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Sym(icon, size: 13)
                Text(label).font(.system(size: 11.5, weight: .medium))
            }
            .foregroundStyle(hover ? (danger ? Tok.red : Tok.label) : Tok.secondary)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: Tok.rPill, style: .continuous)
                    .fill(hover ? (danger ? Color.rgba(255, 59, 48, 0.1) : Color.black.opacity(0.05)) : Color.white)
                    .overlay(RoundedRectangle(cornerRadius: Tok.rPill, style: .continuous)
                        .strokeBorder(hover && danger ? Color.rgba(255, 59, 48, 0.3) : Tok.separator, lineWidth: 0.5))
            )
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

struct HoverTextButton: View {
    @Environment(\.accentChoice) private var accent
    let icon: String
    let label: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Sym(icon, size: 13)
                Text(label).font(.system(size: 12, weight: .medium))
            }
            .foregroundStyle(hover ? accent.accent : Tok.secondary)
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// Pure-SwiftUI rendering of the code box used when rasterizing offscreen
/// (ImageRenderer cannot draw NSViewRepresentable). Mirrors CodeEditor's gutter,
/// tint and metrics so snapshots reflect the real design.
struct StaticCodeView: View {
    let text: String
    let minHeight: CGFloat

    private var lines: [String] {
        let l = text.components(separatedBy: "\n")
        return l.isEmpty ? [""] : l
    }

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            VStack(alignment: .trailing, spacing: 0) {
                ForEach(Array(lines.enumerated()), id: \.offset) { i, _ in
                    Text("\(i + 1)")
                        .font(Tok.monoFont(12.5))
                        .foregroundStyle(Tok.tertiary)
                        .frame(height: 19.4, alignment: .trailing)
                }
                Spacer(minLength: 0)
            }
            .padding(.top, 12).padding(.trailing, 6).padding(.leading, 8)
            .frame(width: 38, alignment: .trailing)
            .frame(maxHeight: .infinity)
            .background(Color.rgba(120, 120, 128, 0.06))
            .overlay(alignment: .trailing) { Rectangle().fill(Tok.separator).frame(width: 0.5) }

            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    Text(line.isEmpty ? " " : line)
                        .font(Tok.monoFont(12.5))
                        .foregroundStyle(Tok.label)
                        .lineLimit(1)
                        .frame(height: 19.4, alignment: .leading)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                Spacer(minLength: 0)
            }
            .padding(.top, 12).padding(.horizontal, 8)
        }
        .frame(height: minHeight, alignment: .top)
        .background(Tok.fieldBg)
        .clipped()
    }
}

// MARK: - Text field

struct TextFieldRow: View {
    @Environment(AppModel.self) private var model
    let field: Field

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(field.label).font(.system(size: 13, weight: .semibold))
            HStack(spacing: 6) {
                if let icon = field.icon { Sym(icon, size: 15).foregroundStyle(Tok.tertiary) }
                TextField(field.placeholder, text: model.binding(for: field.id))
                    .textFieldStyle(.plain)
                    .font(field.mono ? Tok.monoFont(12.5) : .system(size: 13.5))
                    .padding(.vertical, 9)
                Button { model.fieldText[field.id] = "" } label: {
                    Sym("x", size: 14).foregroundStyle(Tok.tertiary)
                        .frame(width: 26, height: 26)
                }
                .buttonStyle(.plain)
            }
            .padding(.leading, 12).padding(.trailing, 4)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Tok.fieldBg)
                    .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
            )
        }
    }
}

// MARK: - Select

struct SelectRow: View {
    @Environment(AppModel.self) private var model
    let field: Field

    var body: some View {
        HStack(spacing: 14) {
            Text(field.label).font(.system(size: 13, weight: .semibold)).frame(width: 150, alignment: .leading)
            Picker("", selection: model.binding(for: field.id)) {
                ForEach(field.options, id: \.self) { Text($0).tag($0) }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .frame(maxWidth: 280, alignment: .leading)
            Spacer()
        }
    }
}

// MARK: - Toggle

struct ToggleRow: View {
    @Environment(AppModel.self) private var model
    let field: Field
    var body: some View {
        HStack(spacing: 12) {
            Toggle("", isOn: model.toggleBinding(field.id))
                .labelsHidden()
                .toggleStyle(.switch)
                .tint(Tok.green)
            Text(field.label).font(.system(size: 13.5, weight: .medium))
            Spacer()
        }
    }
}

// MARK: - Drop zone

struct DropZoneView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accentChoice) private var accent
    let field: Field
    @State private var chosen: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(field.label).font(.system(size: 13, weight: .semibold))
            VStack(spacing: 8) {
                IconChip(icon: field.icon ?? "folder-open", size: 44, iconSize: 22,
                         background: AnyShapeStyle(accent.soft), fg: accent.accent, radius: 12, specular: false)
                Text(field.placeholder).font(.system(size: 14, weight: .semibold))
                Text(chosen ?? field.note).font(.system(size: 12.5)).foregroundStyle(Tok.secondary)
                    .lineLimit(1).truncationMode(.middle)
                SmallGlassButton(label: "Choose…", icon: "folder-open") { choose() }
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity)
            .padding(26)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(LinearGradient(colors: [Tok.authorizedBlue.opacity(0.05), Tok.authorizedBlue.opacity(0.02)], startPoint: .top, endPoint: .bottom))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .strokeBorder(Tok.authorizedBlue.opacity(0.34), style: StrokeStyle(lineWidth: 1.5, dash: [6, 4]))
            )
            .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                guard let p = providers.first else { return false }
                _ = p.loadObject(ofClass: URL.self) { url, _ in
                    guard let url else { return }
                    Task { @MainActor in setChosen(url) }
                }
                return true
            }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { setChosen(url) }
    }

    private func setChosen(_ url: URL) {
        chosen = url.path
        model.fieldText[field.id] = url.path
    }
}

// MARK: - Token fields (Hunt run)

struct TokenFieldsView: View {
    @Environment(\.accentChoice) private var accent
    let identities: [String]
    @State private var tokens: [String: String] = [:]   // in-memory only, never persisted

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 6) {
                Sym("key-round", size: 14).foregroundStyle(accent.accent)
                Text("Session tokens are used only for this run — never written to the manifest or to disk.")
                    .font(.system(size: 12.5)).foregroundStyle(Tok.secondary)
            }
            VStack(spacing: 9) {
                ForEach(identities, id: \.self) { id in
                    HStack(spacing: 12) {
                        Text(id).font(Tok.monoFont(13).weight(.semibold)).frame(width: 70, alignment: .leading)
                        SecureField("session token for \(id)", text: Binding(
                            get: { tokens[id] ?? "" }, set: { tokens[id] = $0 }))
                            .textFieldStyle(.plain)
                            .font(Tok.monoFont(13))
                            .padding(.horizontal, 12).padding(.vertical, 8)
                            .background(RoundedRectangle(cornerRadius: 9).fill(Color.white)
                                .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Tok.separator, lineWidth: 0.5)))
                    }
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 15)
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .fill(Tok.authorizedBlue.opacity(0.05))
                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(Tok.authorizedBlue.opacity(0.18), lineWidth: 0.5))
        )
    }
}

// MARK: - Field dispatcher

struct FieldView: View {
    let field: Field
    var body: some View {
        switch field.kind {
        case .code: CodeBoxView(field: field)
        case .text: TextFieldRow(field: field)
        case .select: SelectRow(field: field)
        case .toggle: ToggleRow(field: field)
        case .drop: DropZoneView(field: field)
        }
    }
}

import SwiftUI

/// Lucide → SF Symbol mapping. The handoff's Assets table is the source of truth;
/// icons the prototype references but the table omits are mapped to the closest SF Symbol.
enum SFS {
    private static let map: [String: String] = [
        // From the handoff Assets table
        "shield-check": "checkmark.shield.fill",
        "file-search": "doc.text.magnifyingglass",
        "scan-search": "doc.viewfinder",
        "gauge": "gauge.with.dots.needle.67percent",
        "target": "target",
        "radar": "dot.radiowaves.left.and.right",
        "waves": "waveform.path",
        "flask-conical": "testtube.2",
        "crosshair": "scope",
        "key-round": "key.fill",
        "wifi": "wifi",
        "message-square-warning": "exclamationmark.bubble.fill",
        "brain-circuit": "brain.head.profile",
        "workflow": "point.3.connected.trianglepath.dotted",
        "flag": "flag.fill",
        "award": "rosette",
        "stethoscope": "stethoscope",
        "file-check-2": "checkmark.seal.fill",
        "sparkles": "sparkles",
        "compass": "safari",
        "lock": "lock.fill",
        "file-scan": "doc.viewfinder",
        "terminal": "terminal.fill",
        "copy": "doc.on.doc",
        "eraser": "eraser",
        "badge-check": "checkmark.seal",
        "chevrons-up-down": "chevron.up.chevron.down",
        "folder-open": "folder",
        "x": "xmark",
        "arrow-right": "arrow.right",
        "wand-sparkles": "wand.and.stars",
        "plus": "plus",
        "refresh-cw": "arrow.clockwise",
        "info": "info.circle",
        "square-arrow-out-up-right": "square.and.arrow.up",
        "radio-tower": "antenna.radiowaves.left.and.right",
        "shield-alert": "exclamationmark.shield.fill",
        "octagon-alert": "exclamationmark.octagon.fill",
        "shield-x": "xmark.shield.fill",
        "link-2": "link",
        "user-round": "person.crop.circle",
        "globe": "globe",
        "file-key-2": "doc.badge.ellipsis",
        "router": "wifi.router",
        "list": "list.bullet",

        // Referenced by the prototype but not in the table
        "apple": "apple.logo",
        "battery-full": "battery.100",
        "search": "magnifyingglass",
        "panel-top": "menubar.rectangle",
        "panel-left": "sidebar.left",
        "check": "checkmark",
        "corner-down-left": "arrow.turn.down.left",
        "upload": "arrow.up.doc",
        "triangle-alert": "exclamationmark.triangle.fill",
        "circle-x": "xmark.circle.fill",
        "circle-check-big": "checkmark.circle.fill",
        "bar-chart-3": "chart.bar.fill",
        "file-code": "doc.text.fill",
        "play": "play.fill",
        "file-plus": "doc.badge.plus",
        "file-signature": "signature",
        "download": "arrow.down.circle",
        "folder-code": "folder.fill",
        "file-audio": "waveform.circle",
        "import": "square.and.arrow.down",
        "radio": "dot.radiowaves.left.and.right",
        "wrench": "wrench.and.screwdriver.fill",
        "lock-keyhole": "lock.fill",
        "layout-grid": "square.grid.2x2.fill",
        "rocket": "paperplane.fill",
        "mail": "envelope.fill",
        "notebook-pen": "square.and.pencil",
        "settings": "gearshape.fill"
    ]

    static func name(_ lucide: String) -> String {
        map[lucide] ?? "questionmark.square.dashed"
    }
}

/// SF Symbol image sized like the prototype's inline icons.
struct Sym: View {
    let lucide: String
    var size: CGFloat = 15
    var weight: Font.Weight = .regular
    init(_ lucide: String, size: CGFloat = 15, weight: Font.Weight = .regular) {
        self.lucide = lucide; self.size = size; self.weight = weight
    }
    var body: some View {
        Image(systemName: SFS.name(lucide))
            .font(.system(size: size, weight: weight))
            .imageScale(.medium)
    }
}

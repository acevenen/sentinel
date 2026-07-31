import SwiftUI
import AppKit

/// Offscreen renderer: `Sentinel --snapshot <outputDir>` renders the real SwiftUI
/// screens to PNGs without needing a visible window. Verifies layout and visual
/// fidelity against the design reference over a headless or locked session.
///
/// Everything here is deliberately concrete (AnyView, no generic @ViewBuilder
/// helpers): generic view builders over long modifier chains make Swift's type
/// checker take minutes on this file.
@MainActor
enum Snapshotter {

    struct Shot {
        let name: String
        let width: CGFloat
        let view: AnyView
    }

    private static func wrap(_ inner: AnyView, _ model: AppModel) -> AnyView {
        let styled = inner
            .environment(model)
            .environment(\.accentChoice, model.accent)
            .environment(\.snapshotMode, true)
            .tint(model.accent.accent)
            .background(Tok.content)
        return AnyView(styled)
    }

    static func run(outputDir: String) {
        _ = NSApplication.shared   // AppKit-backed views (NSViewRepresentable) need this

        try? FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

        let model = AppModel()
        model.welcomeOpen = false

        var shots: [Shot] = []

        // Bespoke screens
        shots.append(Shot(name: "01-welcome", width: 880, view: wrap(AnyView(WelcomeView()), model)))
        shots.append(Shot(name: "02-howto", width: 880, view: wrap(AnyView(HowToView()), model)))
        shots.append(Shot(name: "03-doctor", width: 900, view: wrap(AnyView(DoctorView()), model)))
        shots.append(Shot(name: "04-engagements", width: 940, view: wrap(AnyView(EngagementsView()), model)))

        // One tool screen per guardrail tier, each with its result block rendered.
        let toolShots: [(String, Screen)] = [
            ("05-guard", .guardRuntime),
            ("06-scan", .scan),
            ("07-recon", .recon),
            ("08-exploit", .exploit),
            ("09-evaluate", .evaluate),
            ("10-hunt", .hunt),
            ("11-airedteam", .aiRedteam),
            ("12-traffic", .traffic)
        ]
        for pair in toolShots {
            let screen = pair.1
            model.selected = screen
            model.seedFields(for: screen)
            model.results[screen] = ResultCatalog.result(for: screen, mode: .run)
            guard let tool = ToolCatalog.tools[screen] else { continue }
            shots.append(Shot(name: pair.0, width: 880, view: wrap(AnyView(ToolScreen(tool: tool)), model)))
        }

        // Sidebar on its own, at its real 250pt column width, with a tool selected
        // so the accent-gradient selection pill is visible.
        model.selected = .hunt
        let sidebar = SidebarView().frame(width: 250).background(Tok.grouped)
        shots.append(Shot(name: "13-sidebar", width: 250, view: wrap(AnyView(sidebar), model)))

        // Overlays
        let authorize = AuthorizeSheet().frame(width: 620, height: 460)
        shots.append(Shot(name: "14-authorize", width: 620, view: wrap(AnyView(authorize), model)))

        let welcomeSheet = WelcomeSheet().frame(width: 740, height: 620)
        shots.append(Shot(name: "15-welcome-sheet", width: 740, view: wrap(AnyView(welcomeSheet), model)))

        var failures = 0
        for shot in shots {
            let sized = shot.view.frame(width: shot.width)
            let renderer = ImageRenderer(content: sized)
            renderer.scale = 2
            guard let image = renderer.nsImage,
                  let tiff = image.tiffRepresentation,
                  let rep = NSBitmapImageRep(data: tiff),
                  let png = rep.representation(using: .png, properties: [:]) else {
                print("✗ \(shot.name): render failed")
                failures += 1
                continue
            }
            let path = (outputDir as NSString).appendingPathComponent(shot.name + ".png")
            do {
                try png.write(to: URL(fileURLWithPath: path))
                print("✓ \(shot.name).png  \(Int(image.size.width))x\(Int(image.size.height))")
            } catch {
                print("✗ \(shot.name): \(error.localizedDescription)")
                failures += 1
            }
        }
        print(failures == 0 ? "all snapshots rendered" : "\(failures) snapshot(s) failed")
    }
}

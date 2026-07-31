import Foundation

enum RunMode { case run, dry }

/// The bridge between the UI and the Go `sentinel` engine.
///
/// The engine — not the UI — decides what is allowed. Swift only assembles an
/// argument list and runs the bundled binary with `Process` (never a shell),
/// then parses the JSON/SARIF/Markdown the CLI already emits.
///
/// Secrets: `ANTHROPIC_API_KEY` and hunt session tokens are read from the
/// environment / in-memory only and are never persisted by the UI.
enum SentinelEngine {

    /// Locate the `sentinel` binary: an explicit override, then the app bundle's
    /// Resources, then common install locations.
    static func binaryURL() -> URL? {
        if let override = ProcessInfo.processInfo.environment["SENTINEL_BIN"],
           FileManager.default.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }
        if let bundled = Bundle.main.url(forResource: "sentinel", withExtension: nil),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        for path in ["/usr/local/bin/sentinel", "/opt/homebrew/bin/sentinel"] where FileManager.default.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        return nil
    }

    /// Build the `sentinel <subcommand> …` argument list for a screen from the
    /// current field values — the screen → CLI command map from the handoff.
    static func arguments(for screen: Screen, fields: [String: String], toggles: [String: Bool]) -> [String] {
        func f(_ id: String) -> String { (fields[id] ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
        func on(_ id: String) -> Bool { toggles[id] ?? false }

        switch screen {
        case .scan:
            return ["scan", f("scan-path").isEmpty ? "." : f("scan-path"),
                    "--severity", f("scan-sev").isEmpty ? "low" : f("scan-sev"),
                    "--format", f("scan-fmt").isEmpty ? "terminal" : f("scan-fmt")]
        case .guardRuntime:
            return ["guard", "--format", "json"]
        case .evaluate:
            return ["evaluate", "--format", "json"]
        case .hunt:
            return ["hunt", "--format", "json"]
        case .recon:
            var a = ["recon", f("recon-target"), "--tool", f("recon-tool")]
            let args = f("recon-args"); if !args.isEmpty { for tok in args.split(separator: " ") { a += ["--tool-arg", String(tok)] } }
            return a
        case .traffic:
            return on("traffic-live") ? ["traffic", "--live"] : ["traffic"]
        case .test:
            var a = ["test", f("test-url"), "--tool", f("test-tool")]
            let args = f("test-args"); if !args.isEmpty { for tok in args.split(separator: " ") { a += ["--tool-arg", String(tok)] } }
            return a
        case .exploit:
            return ["exploit", f("exp-target")]
        case .creds:
            return ["creds", "--mode", f("creds-mode"), "--wordlist", f("creds-list")]
        case .wireless:
            return ["wireless", f("wl-bssid")]
        case .se:
            return ["se", f("se-target")]
        case .aiRedteam:
            return ["ai-redteam", f("rt-url"), "--approve-probes"]
        case .orchestrate:
            return ["orchestrate", f("orch-target"), "--planner", f("orch-planner")]
        case .ctf:
            return ["ctf", "--format", "json"]
        case .bounty:
            return ["bounty", "import"]
        default:
            return []
        }
    }

    struct RunOutput {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    /// Run the binary with `Process` (never a shell). Inherits the process
    /// environment so `ANTHROPIC_API_KEY` / token env vars flow through without
    /// ever being written to disk.
    static func run(arguments: [String], extraEnv: [String: String] = [:]) async throws -> RunOutput {
        guard let bin = binaryURL() else {
            throw NSError(domain: "Sentinel", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "sentinel binary not found. Set SENTINEL_BIN or bundle it in Resources."])
        }
        return try await withCheckedThrowingContinuation { cont in
            let proc = Process()
            proc.executableURL = bin
            proc.arguments = arguments
            var env = ProcessInfo.processInfo.environment
            for (k, v) in extraEnv { env[k] = v }
            proc.environment = env

            let outPipe = Pipe(), errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe

            proc.terminationHandler = { p in
                let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                cont.resume(returning: RunOutput(stdout: out, stderr: err, exitCode: p.terminationStatus))
            }
            do { try proc.run() } catch { cont.resume(throwing: error) }
        }
    }
}

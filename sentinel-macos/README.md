# Sentinel — native macOS app

SwiftUI implementation of the `design_handoff_sentinel_macos` handoff: a native
`.app` that shells the Go `sentinel` engine (`github.com/acevenen/sentinel`) and
keeps its safety model — authorization, scope, dry-run, fail-closed, hash-chained
audit — in front of the operator at all times.

## Build & run

```bash
./build-app.sh            # debug
./build-app.sh release    # optimized
open Sentinel.app
```

`build-app.sh` compiles with SwiftPM, assembles `Sentinel.app` (Info.plist,
ad-hoc signature), and bundles the `sentinel` binary into `Contents/Resources`
when it can find one.

> **Build artifacts are written outside the source tree** (`/tmp/sentinel-macos-build`
> by default, override with `SENTINEL_SCRATCH`). This project lives under
> `~/Documents`, which is iCloud Drive; iCloud dematerializes files it is syncing,
> which silently empties an in-tree `.build/` — and source files — mid-compile.
> Keep the scratch path off iCloud.

Requires macOS 14+ and a Swift 5.9+ toolchain. Full Xcode is *not* required —
Command Line Tools are enough (`swift build`); there is no `.xcodeproj`, so open
the folder as a Swift Package if you want to work in Xcode.

## Layout

```
Sources/Sentinel/
  SentinelApp.swift        entry point, menu bar (Commands), Settings
  AppModel.swift           @Observable app state: navigation, fields, results, tour
  Snapshot.swift           `--snapshot <dir>` offscreen renderer (see Verification)
  Engine/
    SentinelEngine.swift   Process bridge: argv construction + execution
  Model/
    ToolSpec.swift         Screen enum, guardrail tiers, field/tool types
    ToolCatalog.swift      all 14 tool specs, sidebar groups, tour steps
    Samples.swift          "Load sample" payloads
    ResultModel.swift      result block types
    ResultCatalog.swift    demonstration results per tool
  Theme/
    DesignTokens.swift     colors, radii, type scale, accent themes
    Styles.swift           glass/accent buttons, pills, chips, shadows
    Symbols.swift          Lucide → SF Symbol mapping
  Views/
    Shell/                 RootView (NavigationSplitView + toolbar), Sidebar
    Screens/               Welcome, HowTo, Doctor, Engagements, ToolScreen
    Fields/                CodeEditor (NSTextView + ruler), field components
    Results/               score banner, table, findings, argv, report
    Overlays/              welcome sheet, authorize sheet, guided tour
```

## Design decisions

- **One parameterized `ToolScreen`** renders all 14 tool screens from `ToolCatalog`;
  guardrail tier, consent line, banner, fields, actions and footnote are data.
- **Code box** is a real `NSTextView` with an `NSRulerView` gutter rather than a
  SwiftUI `TextEditor` + parallel line-number column: the ruler draws each number
  at its actual line-fragment origin, so numbers cannot drift from their lines
  when text wraps.
- **Icons** are SF Symbols via `SFS.name(_:)`, which implements the handoff's
  Lucide→SF mapping table (plus the icons the prototype used that the table omits).
- **Liquid Glass**: the handoff's own materials table is followed —
  `.regularMaterial` / `.ultraThinMaterial` / `.thickMaterial`, plus `GlassFill`
  for controls (specular white gradient + hairline border). `.glassEffect()`
  requires the macOS 26 SDK; `GlassFill` and `GlassSheetBackground` are the two
  places to swap it in when that SDK is available.
- **Accent** is themeable (Red / Green / Violet / Graphite, Apple Music red by
  default) through `\.accentChoice`; the semantic category colors (defense green,
  authorized blue, high-guardrail red, AI violet, ops grey) are deliberately
  *not* themed, because they carry meaning.
- **Type-checker**: tool specs are individual `static let` constants rather than
  one big dictionary literal. A 14-entry `[Screen: ToolSpec]` literal takes Swift
  minutes to type-check; the split version is instant. Keep it that way.

## Engine bridge

`SentinelEngine.arguments(for:fields:toggles:)` builds the argv per the handoff's
screen→command map; `SentinelEngine.run(arguments:)` executes the binary with
`Process` — never a shell — inheriting the environment so `ANTHROPIC_API_KEY` and
session tokens stay in memory and are never written to disk. The binary is located
via `SENTINEL_BIN`, then the bundle's Resources, then `/usr/local/bin`,
`/opt/homebrew/bin`.

Result rendering is wired to `ResultCatalog` (the prototype's demonstration
outputs) so every screen shows a realistic result state. To go live, parse the
engine's `--format json|sarif|markdown` output into the same `ToolResult` types
and drop it in — no view changes required.

## Verification

```bash
swift build --scratch-path /tmp/sentinel-macos-build
/tmp/sentinel-macos-build/debug/Sentinel --snapshot ./snapshots
```

`--snapshot` renders the real SwiftUI views through `ImageRenderer`, which is how
the layout was verified without a visible window. Two caveats, both harness-only:
`ImageRenderer` cannot rasterize AppKit-backed views (`NSViewRepresentable`,
`TextField`, `Toggle`) or `ScrollView` content, so snapshot mode swaps in static
equivalents for the code box and sidebar (`\.snapshotMode`); native `TextField`
and `Toggle` still appear as placeholder blocks in PNGs. They render normally in
the running app.

## Not yet done

- Dark appearance (light is primary per the handoff; tokens are centralized in
  `DesignTokens.swift`, so this is mostly adding dark values).
- Live engine wiring for the ~12 subcommands that exist in the full engine build
  but not in the local checkout (`recon`, `traffic`, `test`, `exploit`, `creds`,
  `wireless`, `se`, `ai-redteam`, `orchestrate`, `engagement`, `ctf`, `bounty`,
  `tools doctor`). `scan`, `guard`, `evaluate`, `hunt` exist locally today.
- Toolbar search (⌘F) is presentational; `ToolbarSearchField` is ready to bind.
- App icon asset (the Dock icon uses the default until an `AppIcon.icns` is added).

#!/bin/bash
# Build Sentinel.app — a launchable, Dock-installable macOS app bundle.
#
#   ./build-app.sh            debug build
#   ./build-app.sh release    optimized build
#
# Build artifacts are kept OUTSIDE the source tree on purpose: this project lives
# under ~/Documents, which is iCloud Drive. iCloud dematerializes files it is
# syncing, which corrupts an in-tree .build directory mid-compile.

set -euo pipefail

CONFIG="${1:-debug}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
SCRATCH="${SENTINEL_SCRATCH:-/tmp/sentinel-macos-build}"
APP="$ROOT/Sentinel.app"

echo "▸ Building Sentinel ($CONFIG)…"
swift build --configuration "$CONFIG" --scratch-path "$SCRATCH" --package-path "$ROOT"

BIN="$SCRATCH/$CONFIG/Sentinel"
[ -x "$BIN" ] || { echo "✗ binary not found at $BIN"; exit 1; }

echo "▸ Assembling $APP…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Sentinel"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"

# Bundle the Go engine next to the app binary when it is available, so the
# Process bridge finds it without any environment setup.
for candidate in "$ROOT/../sentinel/sentinel" "$(command -v sentinel || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        echo "▸ Bundling engine: $candidate"
        cp "$candidate" "$APP/Contents/Resources/sentinel"
        break
    fi
done

# Ad-hoc signature so the app launches locally. Replace with a Developer ID
# identity + notarization for distribution.
codesign --force --deep --sign - "$APP" 2>/dev/null || echo "  (codesign skipped)"

echo "✓ Built $APP"
echo "  open '$APP'"

#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DMG="$ROOT_DIR/src-tauri/target/release/bundle/dmg/Crux_0.1.0_aarch64.dmg"

cd "$ROOT_DIR"

# The Tauri configuration exports the IDE, compiles the native relay, signs
# the app, and packages the configured DMG background and Applications link.
npx tauri build --bundles dmg

hdiutil verify "$DMG"
xattr -cr "$DMG"
echo "Crux DMG ready: $DMG"

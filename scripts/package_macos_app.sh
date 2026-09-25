#!/bin/bash
set -e

echo "=== [CRUX BUILD KERNEL]: Initiating Production Packaging ==="

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/src-tauri"
BUNDLE_APP_DIR="$TAURI_DIR/target/release/bundle/macos/Crux.app"
DMG_OUTPUT_DIR="$TAURI_DIR/target/release/bundle/dmg"
ENTITLEMENTS="$TAURI_DIR/entitlements.plist"

cd "$ROOT_DIR"

# 1. Regenerate application icons from source icon.png
echo "→ [1/6] Verifying high-res Brutalist icon assets..."
npx @tauri-apps/cli icon "$TAURI_DIR/icons/icon.png" -o "$TAURI_DIR/icons"
cp "$TAURI_DIR/icons/icon.icns" "$TAURI_DIR/icons/Crex.icns"

# 2. Build Frontend
echo "→ [2/6] Building Next.js static production export..."
npm run build

# 3. Compile native Rust backend
echo "→ [3/6] Compiling native Rust PTY & Tauri runtime..."
cd "$TAURI_DIR"
cargo build --release
cd "$ROOT_DIR"

# 4. Assemble & Bundle macOS .app
echo "→ [4/6] Bundling Crux.app..."
npx tauri build --bundles app

# 5. Fix Gatekeeper "Damaged" Issue: Strip quarantine and seal with ad-hoc signature + entitlements
echo "→ [5/6] Hardening bundle and sealing codesign signature..."
xattr -cr "$BUNDLE_APP_DIR"
codesign --force --deep --sign - --entitlements "$ENTITLEMENTS" "$BUNDLE_APP_DIR"
codesign -vvv --deep --strict "$BUNDLE_APP_DIR"
echo "✓ Crux.app signature verified successfully!"

# 6. Generate Clean Pristine DMG with Applications symlink
echo "→ [6/6] Generating distribution DMG package..."
mkdir -p "$DMG_OUTPUT_DIR"
DMG_STAGING="/tmp/crux_dmg_staging_$$"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"

# Copy verified app into staging
cp -R "$BUNDLE_APP_DIR" "$DMG_STAGING/Crux.app"
ln -s /Applications "$DMG_STAGING/Applications"

FINAL_DMG="$DMG_OUTPUT_DIR/Crux_0.1.0_aarch64.dmg"
rm -f "$FINAL_DMG"

hdiutil create \
  -volname "Crux" \
  -srcfolder "$DMG_STAGING" \
  -ov \
  -format UDZO \
  "$FINAL_DMG"

rm -rf "$DMG_STAGING"
xattr -cr "$FINAL_DMG"

echo "=== [CRUX BUILD KERNEL]: Complete! ==="
echo "App Bundle: $BUNDLE_APP_DIR"
echo "DMG Image:  $FINAL_DMG"

#!/bin/bash
# Fix macOS Gatekeeper "Damaged and can't be opened" error
APP_PATH="${1:-/Applications/Crux.app}"

if [ ! -d "$APP_PATH" ] && [ -d "src-tauri/target/release/bundle/macos/Crux.app" ]; then
  APP_PATH="src-tauri/target/release/bundle/macos/Crux.app"
fi

if [ -d "$APP_PATH" ]; then
  echo "Clearing macOS quarantine attribute from $APP_PATH..."
  xattr -cr "$APP_PATH"
  codesign --force --deep --sign - "$APP_PATH" 2>/dev/null || true
  echo "✓ Successfully cleared Gatekeeper quarantine. Launching Crux..."
  open "$APP_PATH"
else
  echo "Usage: ./scripts/fix_gatekeeper.sh [/path/to/Crux.app]"
fi

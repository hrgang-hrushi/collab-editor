#!/bin/bash
set -e

echo "[CREX_BUILD]: Compiling native Rust core library..."
cargo build -p crex-core --release

echo "[CREX_BUILD]: Compiling native Swift AppKit/Metal app..."
swift build -c release --package-path crex-macos

APP_DIR="dist/Crex.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

# Copy binary
cp crex-macos/.build/release/CrexApp "$MACOS_DIR/CrexApp"
chmod +x "$MACOS_DIR/CrexApp"

# Copy dynamic core library
cp target/release/libcrex_core.dylib "$MACOS_DIR/" || true

# Generate Info.plist
cat <<EOF > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>CrexApp</string>
    <key>CFBundleIdentifier</key>
    <string>com.crex.ide</string>
    <key>CFBundleName</key>
    <string>Crex</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
EOF

echo "[CREX_BUILD]: Native Crex.app bundle successfully created at $APP_DIR"

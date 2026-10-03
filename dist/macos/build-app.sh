#!/usr/bin/env bash
# Wrap the tray GUI in a macOS application bundle, so it can be installed as an
# app (a Homebrew cask, or dragging it to /Applications) instead of being a bare
# executable.
#
# Usage: build-app.sh <tray_binary> <version> <output.app>
#   <tray_binary>  the built tsunagi-tray executable
#   <version>      the release version (the tag without its leading v)
#   <output.app>   the bundle to create; replaced if it exists
#
# It is a menu-bar app: LSUIElement keeps it out of the Dock and the app
# switcher, and the tray starts the window as a second process of the same
# executable, which inherits that. The bundle is signed ad hoc where `codesign`
# exists (the macOS runner), because arm64 will not run unsigned code; it is not
# notarised, so a downloaded copy needs its quarantine flag cleared, which the
# cask does.
set -euo pipefail

tray="$1"
version="$2"
app="$3"

# CFBundleShortVersionString is dotted numbers only; 0.1.0-rc.22 becomes 0.1.0.
short="${version%%-*}"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 "$tray" "$app/Contents/MacOS/tsunagi-tray"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Tsunagi</string>
    <key>CFBundleDisplayName</key>
    <string>Tsunagi</string>
    <key>CFBundleIdentifier</key>
    <string>cy.hexor.tsunagi.tray</string>
    <key>CFBundleExecutable</key>
    <string>tsunagi-tray</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>${short}</string>
    <key>CFBundleShortVersionString</key>
    <string>${short}</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$app"
fi

echo "built $app"

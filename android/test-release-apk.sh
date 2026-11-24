#!/usr/bin/env bash
set -euo pipefail

apk=${1:?expected an APK}
version_name=${2:?expected the release version}
version_code=${3:?expected the Android version code}
build_tools=${4:?expected the Android SDK Build Tools directory}

badging=$("$build_tools/aapt" dump badging "$apk")
package="package: name='cy.hexor.tsunagi' versionCode='$version_code' versionName='$version_name'"
if [[ "$badging" != "$package "* ]]; then
    echo "Expected tsunagi $version_name (version code $version_code) in the APK manifest" >&2
    exit 1
fi
if grep -Fxq 'application-debuggable' <<< "$badging"; then
    echo "The release APK enables Android debugging" >&2
    exit 1
fi
if ! grep -Fxq "native-code: 'arm64-v8a'" <<< "$badging"; then
    echo "Expected an arm64-v8a APK" >&2
    exit 1
fi
library=$(mktemp)
trap 'rm -f "$library"' EXIT
unzip -p "$apk" lib/arm64-v8a/libtsunagi_android.so > "$library"
if [[ "$(LC_ALL=C file -b "$library")" != *"ARM aarch64"*", stripped"* ]]; then
    echo "Expected a stripped ARM64 tsunagi native library" >&2
    exit 1
fi
"$build_tools/zipalign" -c -P 16 4 "$apk"
"$build_tools/apksigner" verify --verbose --print-certs "$apk"

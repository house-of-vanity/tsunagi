#!/usr/bin/env bash
# Build RC and stable packages and verify apt's upgrade order.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for version in 1.0.3-rc1 1.0.3-rc2 1.0.3; do
    bash "$here/build-deb.sh" /usr/bin/true amd64 "$version" "$work/$version.deb"
done

version_of() { dpkg-deb -f "$work/$1.deb" Version; }
test "$(version_of 1.0.3)" = '1.0.3'
dpkg --compare-versions "$(version_of 1.0.3-rc1)" gt 1.0.2
dpkg --compare-versions "$(version_of 1.0.3-rc1)" lt "$(version_of 1.0.3-rc2)"
dpkg --compare-versions "$(version_of 1.0.3-rc2)" lt "$(version_of 1.0.3)"

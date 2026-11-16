#!/usr/bin/env bash
# Exercise the real packager and pacman's ordering rules on Arch Linux.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for version in 0.1.0-rc.9 0.1.0-rc.10 0.1.0; do
    pkgver="${version//-/}"
    output="$work/tsunagi-${pkgver}-1-x86_64.pkg.tar.zst"
    bash "$here/build-pkg.sh" /usr/bin/true x86_64 "$version" "$output"
    bsdtar -xOf "$output" .PKGINFO > "$work/pkginfo"
    grep -qx "pkgver = 1:${pkgver}-1" "$work/pkginfo"
    grep -qx 'pkgname = tsunagi' "$work/pkginfo"
    bsdtar -tf "$output" | grep -qx 'usr/bin/tsng'
done

test "$(vercmp 1:0.1.0rc.9-1 0.1.0_rc.99-1)" -gt 0
test "$(vercmp 1:0.1.0rc.10-1 1:0.1.0rc.9-1)" -gt 0
test "$(vercmp 1:0.1.0-1 1:0.1.0rc.10-1)" -gt 0

output="$work/tsunagi-gui-0.1.0rc.10-1-x86_64.pkg.tar.zst"
bash "$here/build-pkg.sh" /usr/bin/true x86_64 0.1.0-rc.10 "$output" /usr/bin/true
bsdtar -xOf "$output" .PKGINFO > "$work/pkginfo"
grep -qx 'pkgname = tsunagi-gui' "$work/pkginfo"
grep -qx 'pkgver = 1:0.1.0rc.10-1' "$work/pkginfo"
grep -qx 'conflict = tsunagi' "$work/pkginfo"
bsdtar -tf "$output" | grep -qx 'usr/bin/tsunagi-tray'
echo 'Arch packaging and version-order checks passed'

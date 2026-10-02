#!/usr/bin/env bash
# Assemble a dependency-free Debian package from prebuilt tsunagi binaries,
# using only dpkg-deb (no cargo-deb, no nfpm).
#
# Usage: build-deb.sh <binary> <deb_arch> <version> <output.deb> [tray_binary]
#   <binary>      path to the built tsunagi (agent/CLI) executable
#   <deb_arch>    Debian architecture: amd64 or arm64
#   <version>     package version (the tag without its leading v)
#   <output>      path to write the .deb to
#   [tray_binary] optional path to the tsunagi-tray GUI executable; when given,
#                 the package also installs the tray and a desktop launcher and
#                 is named tsunagi-gui (conflicting with the headless tsunagi).
set -euo pipefail

binary="$1"
arch="$2"
version="$3"
output="$4"
tray="${5:-}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# Payload. Debian installs to /usr/bin (not /usr/local), so the service's
# ExecStart is rewritten to match; the source unit targets /usr/local/bin for
# the tarball installer.
install -D -m 0755 "$binary" "$root/usr/bin/tsunagi"

mkdir -p "$root/lib/systemd/system"
sed 's#/usr/local/bin/tsunagi#/usr/bin/tsunagi#' \
    "$here/../linux/tsunagi.service" > "$root/lib/systemd/system/tsunagi.service"
chmod 0644 "$root/lib/systemd/system/tsunagi.service"

install -D -m 0644 "$here/../linux/50-tsunagi-resolved.rules" \
    "$root/usr/share/polkit-1/rules.d/50-tsunagi-resolved.rules"
install -D -m 0644 "$here/../../README.md" "$root/usr/share/doc/tsunagi/README.md"
install -D -m 0644 "$here/../linux/README.md" "$root/usr/share/doc/tsunagi/INSTALL.md"

pkgname=tsunagi
extra_control=""
desc_gui=""
if [ -n "$tray" ]; then
    pkgname=tsunagi-gui
    # The GUI package is a superset of the headless one and must not coexist
    # with it (both ship /usr/bin/tsunagi).
    extra_control=$'Conflicts: tsunagi\nReplaces: tsunagi\nProvides: tsunagi\n'
    # What the tray and its window load at run time.
    extra_control+=$'Depends: libgtk-3-0 | libgtk-3-0t64, libayatana-appindicator3-1 | libappindicator3-1, libxdo3, libxkbcommon0, libwayland-client0, libx11-6, libgl1\n'
    desc_gui=" It also installs the tray GUI (tsunagi-tray) and a desktop launcher so it can be started from the applications menu."
    install -D -m 0755 "$tray" "$root/usr/bin/tsunagi-tray"
    install -D -m 0644 "$here/../linux/tsunagi-tray.desktop" \
        "$root/usr/share/applications/tsunagi-tray.desktop"
    install -D -m 0644 "$here/../linux/tsunagi.svg" \
        "$root/usr/share/icons/hicolor/scalable/apps/tsunagi.svg"
fi

mkdir -p "$root/DEBIAN"

cat > "$root/DEBIAN/control" <<CTRL
Package: ${pkgname}
Version: ${version}
Architecture: ${arch}
Maintainer: AB <ab@hexor.cy>
Section: net
Priority: optional
Homepage: https://github.com/house-of-vanity/tsunagi
${extra_control}Description: Serverless private mesh networking agent
 tsunagi forms small private mesh IP networks between peers, with NAT
 traversal and no central server. This package installs a static,
 dependency-free agent, a systemd service that runs it as a dedicated
 unprivileged "tsunagi" user with only CAP_NET_ADMIN and CAP_NET_BIND_SERVICE,
 and a polkit rule for the local DNS resolver.${desc_gui}
CTRL

# The dedicated system user the service runs as. It is in the "tsunagi" group,
# which the polkit rule grants the resolve1 actions. systemd creates the state,
# cache and runtime directories for it on first start.
cat > "$root/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if ! getent group tsunagi >/dev/null 2>&1; then
    addgroup --system tsunagi >/dev/null 2>&1 || true
fi
if ! getent passwd tsunagi >/dev/null 2>&1; then
    adduser --system --ingroup tsunagi --home /var/lib/tsunagi --no-create-home \
        --gecos "tsunagi agent" --disabled-login tsunagi >/dev/null 2>&1 || true
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
POSTINST

if [ -n "$tray" ]; then
    cat >> "$root/DEBIAN/postinst" <<'POSTINST_GUI'
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi
POSTINST_GUI
fi
echo "exit 0" >> "$root/DEBIAN/postinst"

cat > "$root/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if [ -d /run/systemd/system ]; then
        systemctl disable --now tsunagi.service >/dev/null 2>&1 || true
    fi
fi
exit 0
PRERM

cat > "$root/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTRM

chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

# --root-owner-group writes the payload as root:root without needing fakeroot.
dpkg-deb --root-owner-group --build "$root" "$output"
echo "built $output"

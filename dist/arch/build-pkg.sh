#!/usr/bin/env bash
# Assemble an Arch Linux package (.pkg.tar.zst) from prebuilt tsunagi binaries,
# using only bsdtar + zstd on a non-Arch host — no makepkg, no Arch container.
#
# Usage: build-pkg.sh <binary> <arch> <version> <output.pkg.tar.zst> [tray_binary]
#   <binary>      path to the built tsunagi (agent/CLI) executable
#   <arch>        pacman architecture: x86_64, aarch64 or armv7h
#   <version>     package version (the tag without its leading v)
#   <output>      path to write the package to
#   [tray_binary] optional tsunagi-tray GUI executable; when given, the package
#                 also installs the tray and a desktop launcher and is named
#                 tsunagi-gui (conflicting with the headless tsunagi).
#
# Needs bsdtar (libarchive-tools) and zstd on the builder.
set -euo pipefail

binary="$1"
arch="$2"
version="$3"
output="$4"
tray="${5:-}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# pacman pkgver may not contain '-', so a prerelease tag like 0.1.0-rc.9 becomes
# 0.1.0_rc.9.
pkgver="$(printf '%s' "$version" | tr '-' '_')"
pkgrel=1

# Payload. Arch keeps units under /usr/lib/systemd/system and installs to
# /usr/bin, so the service's ExecStart is rewritten to match.
install -D -m 0755 "$binary" "$root/usr/bin/tsng"

mkdir -p "$root/usr/lib/systemd/system"
sed 's#/usr/local/bin/tsng#/usr/bin/tsng#' \
    "$here/../linux/tsunagi.service" > "$root/usr/lib/systemd/system/tsunagi.service"
chmod 0644 "$root/usr/lib/systemd/system/tsunagi.service"

install -D -m 0644 "$here/../linux/50-tsunagi-resolved.rules" \
    "$root/usr/share/polkit-1/rules.d/50-tsunagi-resolved.rules"
install -D -m 0644 "$here/../../README.md" "$root/usr/share/doc/tsunagi/README.md"
install -D -m 0644 "$here/../linux/README.md" "$root/usr/share/doc/tsunagi/INSTALL.md"

pkgname=tsunagi
pkgdesc="Serverless private mesh networking agent"
relations=""
if [ -n "$tray" ]; then
    pkgname=tsunagi-gui
    pkgdesc="Serverless private mesh networking agent, with the tray GUI"
    relations=$'conflict = tsunagi\nprovides = tsunagi\nreplaces = tsunagi\n'
    # What the tray and its window load at run time; none of it is linked in
    # statically, so pacman has to be told.
    for dep in gtk3 libayatana-appindicator xdotool libxkbcommon wayland libx11 libglvnd; do
        relations+="depend = ${dep}"$'\n'
    done
    install -D -m 0755 "$tray" "$root/usr/bin/tsunagi-tray"
    install -D -m 0644 "$here/../linux/tsunagi-tray.desktop" \
        "$root/usr/share/applications/tsunagi-tray.desktop"
    install -D -m 0644 "$here/../linux/tsunagi.svg" \
        "$root/usr/share/icons/hicolor/scalable/apps/tsunagi.svg"
fi

# Installed size (payload only), before the metadata files are written.
size="$(du -sb "$root" | cut -f1)"

cat > "$root/.PKGINFO" <<PKGINFO
pkgname = ${pkgname}
pkgver = ${pkgver}-${pkgrel}
pkgdesc = ${pkgdesc}
url = https://github.com/house-of-vanity/tsunagi
builddate = $(date +%s)
packager = AB <ab@hexor.cy>
size = ${size}
arch = ${arch}
${relations}license = WTFPL
PKGINFO

# Scriptlet: create the dedicated system user the service runs as, start the
# service, and let whoever ran pacman use it. The control socket belongs to the
# `tsunagi` group, so the tray and the CLI work for any member of it; the
# person installing is added, since the package cannot know anyone else.
cat > "$root/.INSTALL" <<'INSTALL'
post_install() {
    getent group tsunagi >/dev/null 2>&1 || groupadd -r tsunagi
    getent passwd tsunagi >/dev/null 2>&1 || \
        useradd -r -g tsunagi -d /var/lib/tsunagi -s /usr/bin/nologin -c "tsunagi agent" tsunagi
    command -v update-desktop-database >/dev/null 2>&1 && \
        update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && \
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor >/dev/null 2>&1 || true

    # Whoever ran pacman through sudo or pkexec (an AUR helper does too).
    installer="${SUDO_USER:-}"
    if [ -z "$installer" ] && [ -n "${PKEXEC_UID:-}" ]; then
        installer="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
    fi
    if [ -n "$installer" ] && [ "$installer" != root ] && id "$installer" >/dev/null 2>&1; then
        usermod -aG tsunagi "$installer" >/dev/null 2>&1 || true
        echo ":: $installer was added to the tsunagi group; log out and in again so the"
        echo "   tray and the CLI can reach the agent without sudo."
    else
        echo ":: add yourself to the tsunagi group to use the tray and the CLI without"
        echo "   sudo: sudo usermod -aG tsunagi \$USER, then log out and in again."
    fi

    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable --now tsunagi.service >/dev/null 2>&1 || \
            echo ":: could not start tsunagi.service; see: systemctl status tsunagi"
    fi
}
post_upgrade() {
    # Not enabled again: it may have been turned off on purpose. A running
    # agent is restarted, because the control protocol changes between builds
    # and a new client cannot talk to an old agent.
    command -v update-desktop-database >/dev/null 2>&1 && \
        update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl try-restart tsunagi.service >/dev/null 2>&1 || true
    fi
}
pre_remove() {
    systemctl disable --now tsunagi.service >/dev/null 2>&1 || true
}
post_remove() {
    systemctl daemon-reload >/dev/null 2>&1 || true
}
INSTALL

# .MTREE over the metadata and payload (not over itself), gzip-compressed, as
# pacman expects.
(
    cd "$root"
    LANG=C bsdtar -czf .MTREE --format=mtree \
        --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
        .PKGINFO .INSTALL usr
)

# Pack with .PKGINFO first, then the rest, and zstd-compress.
(
    cd "$root"
    bsdtar -cf - .PKGINFO .MTREE .INSTALL usr
) | zstd -c -19 -T0 > "$output"

echo "built $output"

#!/usr/bin/env bash
# Assemble an Arch Linux package (.pkg.tar.zst) from a prebuilt static tsunagi
# binary, using only bsdtar + zstd on a non-Arch host — no makepkg, no Arch
# container. The binary is static, so the package has no dependencies.
#
# Usage: build-pkg.sh <binary> <arch> <version> <output.pkg.tar.zst>
#   <binary>  path to the built tsunagi executable
#   <arch>    pacman architecture: x86_64 or aarch64
#   <version> package version (the tag without its leading v)
#   <output>  path to write the package to
#
# Needs bsdtar (libarchive-tools) and zstd on the builder.
set -euo pipefail

binary="$1"
arch="$2"
version="$3"
output="$4"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# pacman pkgver may not contain '-', so a prerelease tag like 0.1.0-rc.9 becomes
# 0.1.0_rc.9.
pkgver="$(printf '%s' "$version" | tr '-' '_')"
pkgrel=1

# Payload. Arch keeps units under /usr/lib/systemd/system and installs to
# /usr/bin, so the service's ExecStart is rewritten to match.
install -D -m 0755 "$binary" "$root/usr/bin/tsunagi"

mkdir -p "$root/usr/lib/systemd/system"
sed 's#/usr/local/bin/tsunagi#/usr/bin/tsunagi#' \
    "$here/../linux/tsunagi.service" > "$root/usr/lib/systemd/system/tsunagi.service"
chmod 0644 "$root/usr/lib/systemd/system/tsunagi.service"

install -D -m 0644 "$here/../linux/50-tsunagi-resolved.rules" \
    "$root/usr/share/polkit-1/rules.d/50-tsunagi-resolved.rules"
install -D -m 0644 "$here/../../README.md" "$root/usr/share/doc/tsunagi/README.md"
install -D -m 0644 "$here/../linux/README.md" "$root/usr/share/doc/tsunagi/INSTALL.md"

# Installed size (payload only), before the metadata files are written.
size="$(du -sb "$root" | cut -f1)"

cat > "$root/.PKGINFO" <<PKGINFO
pkgname = tsunagi
pkgver = ${pkgver}-${pkgrel}
pkgdesc = Serverless private mesh networking agent
url = https://github.com/Ultradesu/tsunagi
builddate = $(date +%s)
packager = AB <ab@hexor.cy>
size = ${size}
arch = ${arch}
license = MIT
license = Apache
PKGINFO

# Scriptlet: create the dedicated system user the service runs as, and keep
# systemd in step. The "tsunagi" user is in the "tsunagi" group, which the
# polkit rule grants the resolver actions.
cat > "$root/.INSTALL" <<'INSTALL'
post_install() {
    getent group tsunagi >/dev/null 2>&1 || groupadd -r tsunagi
    getent passwd tsunagi >/dev/null 2>&1 || \
        useradd -r -g tsunagi -d /var/lib/tsunagi -s /usr/bin/nologin -c "tsunagi agent" tsunagi
    systemctl daemon-reload >/dev/null 2>&1 || true
}
post_upgrade() {
    post_install
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

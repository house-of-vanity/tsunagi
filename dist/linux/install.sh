#!/usr/bin/env sh
# Installs the static tsunagi binary and, where systemd is present, a service
# that runs the agent as a dedicated unprivileged "tsunagi" user. Run as root:
#
#   sudo ./install.sh
#
# PREFIX overrides the install prefix (default /usr/local); if you change it,
# edit ExecStart in tsunagi.service to match.
set -eu

PREFIX="${PREFIX:-/usr/local}"
here="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer writes to ${PREFIX}/bin and /etc; re-run it as root (sudo)." >&2
    exit 1
fi

echo "Installing tsunagi to ${PREFIX}/bin"
install -d "${PREFIX}/bin"
install -m 0755 "${here}/tsng" "${PREFIX}/bin/tsng"

# The dedicated system user the service runs as (works with either shadow's
# useradd or Debian's adduser).
if ! getent group tsunagi >/dev/null 2>&1; then
    groupadd -r tsunagi 2>/dev/null || addgroup --system tsunagi 2>/dev/null || true
fi
if ! getent passwd tsunagi >/dev/null 2>&1; then
    useradd -r -g tsunagi -d /var/lib/tsunagi -s /usr/sbin/nologin -c "tsunagi agent" tsunagi 2>/dev/null \
        || adduser --system --ingroup tsunagi --home /var/lib/tsunagi --no-create-home \
            --gecos "tsunagi agent" --disabled-login tsunagi 2>/dev/null || true
fi

# polkit rule so the agent (as the tsunagi user) may configure systemd-resolved.
install -d /etc/polkit-1/rules.d
install -m 0644 "${here}/50-tsunagi-resolved.rules" /etc/polkit-1/rules.d/50-tsunagi-resolved.rules

if command -v systemctl >/dev/null 2>&1; then
    echo "Installing the systemd service (runs as the tsunagi user)"
    install -m 0644 "${here}/tsunagi.service" /etc/systemd/system/tsunagi.service
    systemctl daemon-reload
    cat <<EOF

Done. Start the agent with:

    sudo systemctl enable --now tsunagi

Control it with sudo (the CLI finds the service's socket automatically):

    sudo tsng status
    sudo tsng join -n <network-name> -s <tsn1…secret>
EOF
else
    cat <<EOF

Installed the binary; no systemd found, so no service was set up. Either:

  * run it as root:            sudo ${PREFIX}/bin/tsng up
  * or as your own user:       sudo setcap cap_net_admin,cap_net_bind_service+p ${PREFIX}/bin/tsng
                               tsng up
    (add yourself to the tsunagi group so the resolver works:
     sudo usermod -aG tsunagi "\$USER")
  * or without touching the OS: tsng up --no-tun
EOF
fi

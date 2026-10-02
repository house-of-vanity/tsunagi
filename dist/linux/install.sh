#!/usr/bin/env sh
# Installs the tsunagi binary and, where systemd is present, a root service.
# Run it as root (it writes under /usr/local and /etc):
#
#   sudo ./install.sh
#
# PREFIX overrides the install prefix (default /usr/local).
set -eu

PREFIX="${PREFIX:-/usr/local}"
here="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer writes to ${PREFIX}/bin and /etc; re-run it as root (sudo)." >&2
    exit 1
fi

echo "Installing tsunagi to ${PREFIX}/bin"
install -d "${PREFIX}/bin"
install -m 0755 "${here}/tsunagi" "${PREFIX}/bin/tsunagi"

if command -v systemctl >/dev/null 2>&1; then
    echo "Installing the systemd service (runs the agent as root)"
    install -m 0644 "${here}/tsunagi.service" /etc/systemd/system/tsunagi.service
    systemctl daemon-reload
    cat <<EOF

Done. Start the agent with:

    sudo systemctl enable --now tsunagi

Control it as root, so the client shares the agent's state directory:

    sudo tsunagi status
    sudo tsunagi join <network-name> <tsn1…secret>
EOF
else
    cat <<EOF

Installed the binary; no systemd found, so no service was set up. Either:

  * run it directly as root:

        sudo tsunagi up

  * or grant the capability and run it as your own user (no root at runtime):

        sudo setcap cap_net_admin,cap_net_bind_service+p ${PREFIX}/bin/tsunagi
        tsunagi up

    For the local DNS resolver as a non-root user, run \`tsunagi dns\` once; it
    prints the polkit rule that lets your user configure systemd-resolved.

  * or skip the interface entirely with \`tsunagi up --no-tun\`: tunnels still
    form, they just do not reach the operating system.
EOF
fi

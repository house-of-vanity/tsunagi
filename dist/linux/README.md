# Running tsunagi on Linux

This archive holds a **static** `tsunagi` binary (musl), so it runs on any
distribution — Arch, Alpine, NixOS, old glibc systems — with no shared-library
dependencies. Alongside it are a systemd unit and an installer.

Creating the TUN interface needs `CAP_NET_ADMIN`, and configuring
systemd-resolved is decided by polkit (by user id, not capability). There are
three ways to satisfy that; pick one.

## Quick install — systemd service as root

```sh
sudo ./install.sh
sudo systemctl enable --now tsunagi
```

The service runs the agent as root, so the interface, low ports and the
resolver all just work (root is not subject to polkit). Control it **as root**,
so the client resolves the same state directory the daemon uses:

```sh
sudo tsunagi status
sudo tsunagi join <network-name> <tsn1…secret>
```

## As your own user — one capability, no root at runtime

```sh
sudo install -m 0755 tsunagi /usr/local/bin/tsunagi
sudo setcap cap_net_admin,cap_net_bind_service+p /usr/local/bin/tsunagi
tsunagi up
```

Nothing is left behind and nothing runs as root. The capability is lost on every
rebuild or copy of the binary, so re-run `setcap` after replacing it. For the
local DNS resolver, run `tsunagi dns` once: it prints the exact polkit rule that
lets your user configure systemd-resolved, ready to paste.

## Without touching the OS

```sh
tsunagi up --no-tun
```

Tunnels form and handshake between agents, but no interface, address or route is
created, so traffic never reaches the operating system. Needs no privileges.

## What the agent installs

Everything is tagged to its own interface, computed from local state, and
reversible — removed when a network leaves, broadcast is turned off, or the
agent stops:

- a TUN interface configured over netlink (addresses, MTU, up);
- while broadcast is on, a `255.255.255.255` route through the interface and an
  inbound-UDP firewall allowance from the overlay range (`iptables`, tagged);
- the systemd-resolved setting that sends the overlay zones' questions to the
  local resolver.

Nothing taken from a remote peer ever becomes a path, a command argument or an
OS setting.

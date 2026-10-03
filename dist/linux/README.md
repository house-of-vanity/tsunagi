# Running tsunagi on Linux

This archive holds a **static** `tsunagi` binary (musl), so it runs on any
distribution — Arch, Alpine, NixOS, old glibc systems — with no shared-library
dependencies. Alongside it are a systemd unit, a polkit rule, and an installer.

Creating the TUN interface needs `CAP_NET_ADMIN`, and configuring
systemd-resolved is decided by polkit. There are three ways to run it; pick one.

> On Debian/Ubuntu and Arch, prefer the native package (`.deb` / `.pkg.tar.zst`)
> from the release — it does all of the below for you.

## Quick install — systemd service as a dedicated user

```sh
sudo ./install.sh
sudo systemctl enable --now tsunagi
```

The service runs as an unprivileged `tsunagi` user with just `CAP_NET_ADMIN`
and `CAP_NET_BIND_SERVICE` (granted by systemd), not root. systemd creates its
state (`/var/lib/tsunagi`), cache (`/var/cache/tsunagi`) and runtime
(`/run/tsunagi`) directories, and the polkit rule lets it configure the
resolver. Control it with `sudo` — the CLI finds the running service's socket at
`/run/tsunagi/agent.sock` with no flags. The socket is open to the `tsunagi`
group, so after `sudo usermod -aG tsunagi "$USER"` (and logging in again) no
`sudo` is needed:

```sh
sudo tsng status
sudo tsng join -n <network-name> -s <tsn1…secret>
```

## As your own user — one capability, no service

```sh
sudo install -m 0755 tsunagi /usr/local/bin/tsng
sudo setcap cap_net_admin,cap_net_bind_service+p /usr/local/bin/tsng
sudo usermod -aG tsunagi "$USER"   # so the resolver works; log in again after
tsng up
```

Nothing runs as root. The capability is lost on every rebuild or copy of the
binary, so re-run `setcap` after replacing it. The agent uses your per-user
state directory and socket, so plain `tsng status` (no sudo) reaches it.

## Without touching the OS

```sh
tsng up --no-tun
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

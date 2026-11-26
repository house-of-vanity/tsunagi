<p align="center">
  <img src="dist/linux/tsunagi.svg" width="96" alt="">
</p>

<h1 align="center">tsunagi</h1>

<p align="center">
  <b>A mesh VPN with no server.</b><br>
  Pick a network name, share a secret, and your machines are on one private network.
</p>

<p align="center">
  <a href="https://github.com/house-of-vanity/tsunagi/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/house-of-vanity/tsunagi?include_prereleases"></a>
  <a href="https://github.com/house-of-vanity/tsunagi/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/house-of-vanity/tsunagi/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-WTFPL-blue"></a>
</p>

```console
laptop$ tsng join -n home
joined `home`
  secret  tsn1u7c…

server$ tsng join -n home -s tsn1u7c…
server$ tsng id hostname server

laptop$ ssh server.home
```

No account, no coordination server, no admin console, no keys to approve.
Anyone who knows the **name** and the **secret** is in. Nobody else can find
the network, let alone enter it.

## Why

Tailscale, Headscale and ZeroTier are great, but each needs a control server:
theirs, or one you have to run and keep alive. tsunagi doesn't. Machines find
each other through the public BitTorrent DHT, connect directly (hole punching,
with relay fallback), and keep the network state among themselves.

|                        | Tailscale          | Headscale        | ZeroTier            | **tsunagi**         |
| ---------------------- | ------------------ | ---------------- | ------------------- | ------------------- |
| Control server         | hosted by vendor   | you run it       | hosted or self-run  | **none**            |
| Account / sign-in      | yes                | yes              | yes                 | **no**              |
| To join a network      | sign in, get approved | pre-auth key  | network ID, approval | **name + secret**  |
| Direct connections     | yes                | yes              | yes                 | yes                 |
| Exit nodes             | yes                | yes              | via routes          | yes                 |

## Features

- **Two things to know:** a network name and a secret. A secret is generated for you when you make a network.
- **Direct, encrypted links** between members (WireGuard cryptography), with relay fallback behind strict NATs.
- **Names for machines:** `server.home` just works, even while `server` is switched off. A name belongs to whoever claimed it first; a later device with the same name keeps working by address and is told so.
- **Exit nodes:** send all your internet traffic through any member that offers one.
- **Multi-hop:** members that can't reach each other directly are routed through a member that can, over whatever kind of link each hop has. A member reached that way is online, and shown as relayed; traffic moves to a direct link by itself the moment one comes up.
- **LAN games:** UDP broadcasts are relayed, so "LAN" lobbies show up across the mesh.
- **Several networks at once** on one device.
- **Tray app** for Windows, macOS and Linux; a command line for everything.
- **Android prototype** for ARM64 phones, with the same egui forms and a foreground VPN service. [Build and run the Android client](android/README.md).

## Install

Grab a build from the [latest release](https://github.com/house-of-vanity/tsunagi/releases/latest).

| Platform              | How                                                                              |
| --------------------- | -------------------------------------------------------------------------------- |
| **Windows**           | Run `tsunagi-setup-<version>-x86_64.exe`. Installs the service, the tray and `tsng`. |
| **Android**           | Open `tsunagi-android-<version>-arm64-v8a.apk` on an ARM64 phone running Android 8 or later. |
| **macOS**             | `brew tap house-of-vanity/tap && brew install --cask tsunagi-gui`<br>CLI only: `brew install tsunagi` |
| **Debian / Ubuntu**   | `sudo apt install ./tsunagi-gui_<version>_amd64.deb` (`tsunagi_…` for no tray)   |
| **Arch**              | `sudo pacman -U tsunagi-gui-<version>-1-x86_64.pkg.tar.zst`                      |
| **NixOS**             | [Flake and module](#nixos) below                                                 |
| **Any other Linux**   | Unpack the tarball, then `sudo ./install.sh && sudo systemctl enable --now tsunagi` |

Linux packages run the agent as an unprivileged service user. Add yourself to
the `tsunagi` group (`sudo usermod -aG tsunagi $USER`, then log in again) to
use `tsng` and the tray without `sudo`.

## Quick start

```sh
tsng join -n home                 # first machine: makes the network and prints a secret
tsng join -n home -s tsn1…        # every other machine
tsng status                       # who is online, over which path
```

Every new network gets a stable pseudorandom `/24` in `10.0.0.0/8`, derived
from its network id. Its members agree on that range even when starting offline,
and each gets a name like `<host>.home`. Existing signed ranges are preserved.

If two configured networks have overlapping ranges, the agent runs only one.
`tsng status`, `tsng network` and the tray show which network blocks the
other. `tsng network start <name-or-id>` or the tray’s “Switch to this network”
button suspends the conflicting networks. They resume automatically when the
selected network stops; the selection survives restarting the agent. Explicitly
stopping a suspended network cancels its automatic resume.

Machines are called `tsunagi-<id>` until you rename them: `tsng id hostname laptop`.

### Virtual services

```sh
tsng vip create home api
tsng vip port add home api tcp/443 --backend server1:6443 --backend server2:7443
tsng vip status home api --watch
```

Use `api.home:443`. Each client selects the available backend with the lowest
measured data-plane RTT. A VIP can have multiple independent TCP and UDP ports.
Every member may edit it; the tray's **VIP** button opens a draft editor with
explicit Save. [Commands, health, metrics and limits](docs/vip.md).

### Exit nodes

```sh
tsng network exit-node home on    # on the machine that should be the exit
tsng exit-node                    # on another one: who offers an exit
tsng exit-node laptop             # send internet traffic through it
tsng exit-node off
```

One exit serves the whole agent. Peers in every active Tsunagi network stay
reachable on their own mesh routes.

The tray does the same with a checkbox. An exit node sees everything you send
through it, so use only members you trust. The folded network card shows its
status and recent traffic. Expand it to see who is using this device for internet
access.
[Details and per-OS notes](docs/exit-node.md).

The initial data transport order is `wg,awg,wg-quic,tcp-tls,vless-xhttp,ss2022` by default. AWG negotiates a
fresh masking profile and outer keys for each pair connection attempt, including
reentry after fallback. Sustained data loss triggers switching independently of
the iroh control connection. [Configuration and limits](docs/amnezia.md).

The **Shoes** family adds two embedded TCP carriers. `vless-xhttp` uses VLESS
over XHTTP stream-one with HTTP/2 and pinned TLS 1.3 (preferred port 9443).
`ss2022` uses Shadowsocks 2022 with AES-128-GCM or AES-256-GCM (9444).
Peers agree fresh credentials over their authenticated control connection on
every attempt. The native `tcp-tls` listener prefers TCP 9442. To use all three
on a public server, allow inbound TCP 9442–9444. For a second agent on the
same host, set its listeners explicitly, for example
`tsng up -o tcp-tls:port=10442 -o vless-xhttp:port=10443 -o ss2022:port=10444`,
and allow TCP 10442–10444 for that instance.

With two updated peers, `tcp-tls` and both Shoes carriers try the opposite dial
direction if the first fails. One reachable TCP listener suffices. If neither
side accepts TCP, the mesh can use another enabled carrier or an available
relay route. [Wire profiles and compatibility](docs/shoes.md).

Change a network's protocol selection without editing its service or restarting:

```sh
tsng protocols                         # available protocols and settings
tsng protocols home                    # this device's choice for home
tsng protocols home awg,wg-quic         # enable AWG and QUIC, try AWG first
tsng protocols home none                # control plane only
```

Exact network names, full ids and unique id prefixes work here. The choice is
local to this device, saved per network and applied immediately; an offline
change applies on the next start. In the tray or on Android, click the network
name to expand its card. Open **Data transports** to toggle a family or expand it to select individual
transports. Checking a partial or unchecked family enables every member. The
number beside an enabled transport is its priority across all groups. The arrow
buttons change it. Hover or tap the information icon for protocol details. **Show devices** lists peers and their reported
Tsunagi versions. On Android, tap a device to see its version and traffic.

Select a peer’s speedometer in **Devices** to measure download and upload
through its current encrypted mesh path. A test becomes available after a
round trip to the peer succeeds over that path, directly or through relay
members. The control connection coordinates the test and returns its results.
Only packets received over the data path count towards the rate in Mbit/s.
Select the result to test again, or use **Test exits** to check the network’s
online, compatible exit nodes one at a time. The test ends at the peer, so its
Internet uplink beyond that peer is outside the measurement. Hover or long-press
the result for details. “At least” means the receiver sustained that rate and
the test ended before it could confirm the limit. A missing direction means
the sample was too short. Both peers need speed-test support.

A test runs for up to five seconds. It raises the offered rate in steps and
tries a higher rate again after a slow start. The receiver counts unique payload
bytes across sustained trains of packets, including the last train before the
traffic budget runs out. The traffic ceiling is 96 MiB per direction for one
peer, or 8 MiB when either endpoint reports a metered link.
A batch shares 128 MiB per direction among its exits, or 16 MiB on a metered
initiator. These ceilings count probe IP packets before tunnel overhead.

Adjacent peers need a common external transport at the same wire version.
Peers that both support link comparison probe another mutually enabled transport
while traffic continues on the current one. They can switch to a faster healthy link.
`tsng status` and Devices show the round trip of an encrypted probe to the
destination, including any mesh relay hops. The previous measurement stays
visible while the next probe is in flight. Losing the route or missing two
consecutive probes clears the measurement. Devices shows **Ready** or **Idle**
only while the data path is confirmed and the tunnel has a usable session key.
Control RTT is shown separately.
Selection applies to this device's incoming and outgoing data links; control and
discovery are independent. A relay's next hop may use a different transport.
Every pair uses one internal WireGuard cipher, hidden from these controls.
Changing transport or moving direct → relay → direct preserves that channel,
addresses and interface. An existing TCP connection can resume after temporary
loss, subject to its own timeouts. `tsng up --protocol` supplies the
initial defaults for networks without a saved choice; it does not restrict
which built-in protocols can be enabled later.

Remove an obsolete offline device from a network's shared history:

```sh
tsng network forget-node home old-laptop
tsng network forget-node home 10.13.37.143
```

Networks accept exact names, full ids or unique id prefixes; nodes accept those
id selectors, exact hostnames or overlay IPv4 addresses. Ambiguous selectors
change nothing. Start the network first if it is stopped. In **Show devices**,
click **Forget** beside an offline node and confirm its identity.

Every member has the same cleanup right. The signed cleanup frees the observed
claim's name and IPv4 reservation, survives restarts and reaches offline replicas
when they reconnect. It does not ban the device: a newer signed claim can return.
Online nodes and the currently selected exit node cannot be forgotten.
[State and limits](docs/sync-model.md#offline-node-cleanup).

### Traffic monitor

Open **Traffic monitor** (the pulse icon in the tray window or Android header) to
start an empty live capture. **IP flows** groups both directions of a TCP or UDP
address/port pair and repeated ICMP echoes for an address pair into one row. Select a network and peer, protocol or
role to narrow it down. **Via exit node** shows your outgoing internet traffic.
**Serving exit** shows traffic your device forwards for another peer.

**Resolve names** shows known peers and VIPs by their network names in the
endpoint columns. Hover over a name, or press and hold on Android, to see the
IP address. Clear the checkbox to show all endpoints numerically.

**Transport** shows authenticated control sessions and encrypted datagrams
forwarded between two other endpoints. For relay rows the arrows follow the
two displayed endpoints in order. Rates update once per second. Use the
**TX packets** and **RX packets** columns to see packet counts. The monitor
records header metadata and counters only.

Inactive rows expire after 60 seconds. **Keep until close** retains flows in a
private temporary table owned by the window. Closing it discards the table and
ends collection. Android pauses collection while the activity is in the background.
Under heavy load the monitor displays the number of missed observations.

## Platforms

| Platform                  | Build        | CLI `tsng` | Tray | Exit node: offer / use | Packages                            |
| ------------------------- | ------------ | :--------: | :--: | :--------------------: | ----------------------------------- |
| Linux x86_64              | release      |     ✔      |  ✔   |        ✔ / ✔           | `.deb`, `.pkg.tar.zst`, tarball, Nix |
| Linux aarch64             | release      |     ✔      |  –¹  |        ✔ / ✔           | `.deb`, `.pkg.tar.zst`, tarball, Nix |
| Linux armv7               | release      |     ✔      |  –¹  |        ✔ / ✔           | `.deb`, `.pkg.tar.zst`, tarball      |
| macOS, Apple silicon      | release      |     ✔      |  ✔   |        ✔ / ✔²          | Homebrew, tarball                    |
| macOS, Intel              | from source  |     ✔³     |  ✔³  |        ✔ / ✔²³         | –                                    |
| Windows x86_64            | release      |     ✔      |  ✔   |        ✔ / ✔²          | installer, zip                       |

<sup>¹ Not in the release; builds from source (and through Nix).
² Newer and less battle-tested than on Linux.
³ Builds from source, not covered by CI.</sup>

The Linux release CLI is a single static musl binary, independent of the
distribution's libc. The tray uses dynamic desktop libraries.

## NixOS

The repository is a flake with a package and a module.

```nix
# flake.nix
{
  inputs.tsunagi.url = "github:house-of-vanity/tsunagi";

  outputs = { nixpkgs, tsunagi, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        tsunagi.nixosModules.default
        {
          services.tsunagi = {
            enable = true;
            tray.enable = true;      # optional, for desktops
            users = [ "alice" ];     # may use tsng and the tray without sudo
          };
        }
      ];
    };
  };
}
```

Just trying it: `nix run github:house-of-vanity/tsunagi#tsunagi-cli -- --help`.
`packages.<system>.tsunagi` (with the tray) and `tsunagi-cli` are also exported,
along with `overlays.default`.

For development from a checkout, `nix develop` also exposes the tray's native
runtime libraries, including AppIndicator and graphics/windowing libraries.
Cargo-built binaries such as `target/debug/tsunagi-tray` can run directly inside
this shell, without installing the packaged wrapper.

## Build from source

Rust 1.91 or newer.

```sh
cargo build --release --bin tsng               # the agent and CLI
cargo build --release --bin tsunagi-tray       # the tray (Linux needs GTK 3 and libayatana-appindicator)
```

These commands use the host target. On a glibc-based Linux distribution,
`target/release/tsng` is dynamically linked. For the static x86_64 Linux CLI,
release CI uses Zig 0.14.1 and `cargo-zigbuild` (with CMake, Clang and libclang
installed):

```sh
rustup target add x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --bin tsng
```

The static binary is `target/x86_64-unknown-linux-musl/release/tsng`.

Windows needs [Wintun](https://www.wintun.net) next to `tsng.exe`.
Per-platform notes: [Linux](dist/linux/README.md), [Arch](dist/arch/README.md),
[macOS](dist/macos/README.md), [Windows](dist/windows/README.md).

## How it works

- Your name and secret derive a network identity. Members publish signed
  contact records to the public Mainline DHT under it, and find each other there.
- Every connection proves knowledge of the secret before it's accepted.
  Traffic between members is end-to-end encrypted, relays included.
- Addresses and names are claimed with each device's own key and replicated
  between members. There is no one in charge, so nothing to be taken down.

The secret is the only key, so make it a good one (the generated ones are).
The [threat model](docs/threat-model.md) says what this does and doesn't protect against.

## Documentation

[Architecture](docs/architecture.md) ·
[Protocol](docs/protocol.md) ·
[WireGuard data plane](docs/wireguard.md) ·
[Pairwise Amnezia transport](docs/amnezia.md) ·
[Routing](docs/routing.md) ·
[Exit nodes](docs/exit-node.md) ·
[Virtual services](docs/vip.md) ·
[Threat model](docs/threat-model.md) ·
[Contributing](AGENTS.md)

## Licence

[WTFPL](LICENSE): do what the fuck you want to.

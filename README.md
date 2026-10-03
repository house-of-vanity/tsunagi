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
- **Names for machines:** `server.home` just works, even while `server` is switched off.
- **Exit nodes:** send all your internet traffic through any member that offers one.
- **Multi-hop:** members that can't reach each other directly are routed through a member that can.
- **LAN games:** UDP broadcasts are relayed, so "LAN" lobbies show up across the mesh.
- **Several networks at once** on one device.
- **Tray app** for Windows, macOS and Linux; a command line for everything.

## Install

Grab a build from the [latest release](https://github.com/house-of-vanity/tsunagi/releases/latest).

| Platform              | How                                                                              |
| --------------------- | -------------------------------------------------------------------------------- |
| **Windows**           | Run `tsunagi-setup-<version>-x86_64.exe`. Installs the service, the tray and `tsng`. |
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

Every member gets an address in `10.13.37.0/24` and a name like `<host>.home`.
Machines are called `tsunagi-<id>` until you rename them: `tsng id hostname laptop`.

### Exit nodes

```sh
tsng network exit-node home on    # on the machine that should be the exit
tsng exit-node                    # on another one: who offers an exit
tsng exit-node laptop             # send everything through it
tsng exit-node off
```

The tray does the same with a checkbox. An exit node sees everything you send
through it, so use only members you trust.
[Details and per-OS notes](docs/exit-node.md).

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

The Linux CLI is a single static binary: it runs on any distribution.

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

## Build from source

Rust 1.91 or newer.

```sh
cargo build --release --bin tsng               # the agent and CLI
cargo build --release --bin tsunagi-tray       # the tray (Linux needs GTK 3 and libayatana-appindicator)
```

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
[Routing](docs/routing.md) ·
[Exit nodes](docs/exit-node.md) ·
[Threat model](docs/threat-model.md) ·
[Contributing](AGENTS.md)

## Licence

[WTFPL](LICENSE): do what the fuck you want to.

# Running tsunagi on Arch Linux

Install the package built for your architecture:

```sh
sudo pacman -U tsunagi-*-x86_64.pkg.tar.zst
```

It drops a static, dependency-free binary at `/usr/bin/tsng`, a systemd
service, and a polkit rule, and creates a dedicated system user `tsunagi` the
service runs as.

Start it:

```sh
sudo systemctl enable --now tsunagi
```

Control it with `sudo` (the agent's control socket is private to the service
user; `sudo` reaches it with no extra flags, because the CLI finds the running
service's socket at `/run/tsunagi/agent.sock`):

```sh
sudo tsng status
sudo tsng join -n <network-name> -s <tsn1…secret>
```

## How it runs

The service runs as the unprivileged `tsunagi` user with just two capabilities
(`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`) granted by systemd — no root. systemd
creates and owns its directories:

| what | path |
|---|---|
| state | `/var/lib/tsunagi` |
| cache | `/var/cache/tsunagi` |
| control socket | `/run/tsunagi/agent.sock` |

Installing the package enables and starts the service, and adds the user who ran
pacman to the `tsunagi` group (log out and in again for it to apply). The
control socket is open to that group, so members can run `tsng status`, the
CLI and the tray GUI without sudo; anyone else adds themselves with `sudo
usermod -aG tsunagi "$USER"`. The group also lets its members configure
systemd-resolved for the overlay zones through the polkit rule.

The GUI package depends on `gtk3`, `libayatana-appindicator` (the tray icon),
and the usual windowing libraries.

## Removal

```sh
sudo pacman -R tsunagi
```

stops and disables the service. The `tsunagi` user and `/var/lib/tsunagi` are
left in place; remove them by hand if you want them gone.

## Automatic package repository

GitHub releases are also published to the Arch repository after all release
assets have uploaded. Add this to `/etc/pacman.conf`:

```ini
[btwiusearch.net]
SigLevel = Optional TrustAll
Server = https://btwiusearch.net/arch_repo/$arch/
```

Install with `sudo pacman -Syu tsunagi`, or `sudo pacman -Syu tsunagi-gui` for
the x86_64 desktop variant. Subsequent versions arrive through `pacman -Syu`.
Prerelease tags are included. ARM packages are provided for `aarch64` and `armv7h`.

Maintainers must set the `ARCH_REPO_TOKEN` Actions secret to a fine-grained token
with **Contents: Read and write** permission on `house-of-vanity/arch_repo` only.
The separate notification job fails clearly if the secret is missing; the built
release remains available. Once the secret is configured, rerun the failed job.
A successful notification schedules publication; check the
[Arch repository workflow](https://github.com/house-of-vanity/arch_repo/actions/workflows/update_repo.yaml)
for the deployment result. A manual run there can import an existing tag without
rebuilding it. Repository setup and recovery are documented in
[arch_repo](https://github.com/house-of-vanity/arch_repo#github-setup).

Arch package versions use epoch `1` and spell prereleases as `0.1.0rc.33`, so
pacman upgrades correctly from RC to stable. The epoch also migrates packages
installed using the former `0.1.0_rc.33` spelling. It appears in pacman's version
metadata, not in archive filenames. This does not change the Git tag or the
application's version string.

Package/version checks can be run on Arch Linux with `python`, `libarchive`, and
`zstd` installed: `bash dist/arch/test-pkg.sh`.

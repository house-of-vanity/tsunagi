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
`xdotool` (its `libxdo`), and the usual windowing libraries.

## Removal

```sh
sudo pacman -R tsunagi
```

stops and disables the service. The `tsunagi` user and `/var/lib/tsunagi` are
left in place; remove them by hand if you want them gone.

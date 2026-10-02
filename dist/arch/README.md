# Running tsunagi on Arch Linux

Install the package built for your architecture:

```sh
sudo pacman -U tsunagi-*-x86_64.pkg.tar.zst
```

It drops a static, dependency-free binary at `/usr/bin/tsunagi`, a systemd
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
sudo tsunagi status
sudo tsunagi join <network-name> <tsn1…secret>
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

The polkit rule lets anyone in the `tsunagi` group configure systemd-resolved
for the overlay zones (the service user is in that group). To run the agent as
your own user as well, add yourself to the group: `sudo usermod -aG tsunagi
"$USER"`.

## Removal

```sh
sudo pacman -R tsunagi
```

stops and disables the service. The `tsunagi` user and `/var/lib/tsunagi` are
left in place; remove them by hand if you want them gone.

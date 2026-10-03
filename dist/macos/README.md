# Running tsunagi on macOS

The agent needs **root** on macOS: creating a `utun` interface and writing
`/etc/resolver` are both root-only, and macOS has no per-capability grant like
Linux. There are two ways to run it.

## Quick start — `sudo`

```sh
sudo tsng up
```

In another terminal, the control commands talk to it over the system control
socket and do **not** need `sudo`:

```sh
tsng status
tsng join -n <network-name> -s <tsn1…secret>
```

The agent uses fixed system paths, so the commands find it regardless of whose
shell started `sudo`:

| what | path |
|---|---|
| mandatory state | `/var/db/tsunagi` |
| disposable cache | `/var/db/tsunagi/cache` |
| control socket | `/var/run/tsunagi/agent.sock` |

## Homebrew

```sh
brew tap house-of-vanity/tap
brew install --cask tsunagi-gui    # the tray app, and the agent it needs
# or just the command line agent:
brew install tsunagi
sudo brew services start tsunagi   # the agent, as a root daemon at boot
```

The cask starts the service for you. The agent runs as root, and its control
socket is open to the `admin` group, so the CLI and the tray work without
`sudo` for an administrator.

## Native deployment — root LaunchDaemon

For an always-on agent that starts at boot, install the bundled
[`cy.hexor.tsunagi.plist`](cy.hexor.tsunagi.plist).

```sh
# Put the binary where the plist expects it (edit the plist for another path).
sudo install -m 0755 target/release/tsng /usr/local/bin/tsng

# Install the daemon. launchd refuses a daemon plist that is not owned by
# root:wheel or that is group/world-writable.
sudo install -m 0644 -o root -g wheel \
    dist/macos/cy.hexor.tsunagi.plist \
    /Library/LaunchDaemons/cy.hexor.tsunagi.plist

# Load and start it.
sudo launchctl bootstrap system /Library/LaunchDaemons/cy.hexor.tsunagi.plist
sudo launchctl enable system/cy.hexor.tsunagi
```

Manage it afterwards with:

```sh
sudo launchctl kickstart -k system/cy.hexor.tsunagi   # restart
sudo launchctl bootout system/cy.hexor.tsunagi        # stop and unload
tail -f /var/log/tsunagi.log                          # logs
```

The control commands (`status`, `join`, `network`, `dns`) work the same against
the daemon as against a `sudo tsng up`, over the same socket.

## What the agent does to the system

Everything it installs is tagged to its own interface, computed from local
state, and reversible — it is removed when a network leaves, broadcast is turned
off, or the agent stops:

- a **`utun` interface**, configured with `ifconfig` (addresses, MTU, up) and a
  subnet `route` for the overlay range. The kernel assigns the `utunN` name; the
  agent adopts whatever it is given. A `utun` is torn down with the process, so
  a crash never leaves one behind.
- `/etc/resolver/<network>` files pointing the system resolver at the overlay
  DNS server for each network's zone, with a `port` so the server stays off 53.
  Each file carries a marker line; the agent only ever replaces or removes files
  it wrote, never one you created by hand.
- while broadcast is on, a `255.255.255.255` **route** through the overlay
  interface. The matching inbound-UDP firewall allowance is **not** implemented
  yet (it needs a `pf` anchor); `tsng status` reports that half as incomplete
  and names what to allow by hand if your host firewall drops discovery replies.

Nothing taken from a remote peer ever becomes a path, a command argument or an
OS setting: the interface name comes from the kernel, addresses and ranges from
signed state the agent already verified.

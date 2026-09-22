# tsunagi

A proof-of-concept Rust library for **small private mesh networks** — a handful
of friends, home machines, a few servers. Units to dozens of participants, not
thousands.

The end user configures exactly two things:

```text
network_name
secret          # one shared secret; "password" and "secret" mean the same value
```

From those, every agent independently derives the same network space. There is
no central server, no network owner with special powers, no registration and no
majority vote. Anyone who knows the parameters can join; nobody has to trust
anybody else.

## What this proof of concept actually does

A working library with **real iroh connections** and integration tests:

- persistent device identity stored in SQLite, stable across restarts;
- several independent networks at once in one agent;
- deterministic network identity derived from name + secret;
- candidates supplied by a replaceable discovery component;
- automatic first contact through the public Mainline DHT (BEP44);
- real iroh connections plus an explicit mutual proof of network membership;
- a small versioned control protocol: handshake, hostname/capability
  announcement, ping/pong;
- automatic reconnect with bounded exponential backoff and jitter;
- status snapshots, an event stream and honest diagnostics;
- configuration restored after a restart;
- correct behaviour when the disposable cache is missing or corrupt;
- a **WireGuard data plane**, in userspace: its own key per network, an IPv6
  overlay with deterministically derived addresses and optional IPv4, real
  tunnels carried over iroh, and address ownership enforced rather than
  believed;
- a **command line agent**, `tsunagi`, with a local control socket.

### What it deliberately does **not** do

Not implemented, and not pretended to be: DNS, routing through
intermediate participants, a full CRDT, dynamically loaded plugins, a system
service, a complete CLI, or a local control socket. Snapshot synchronisation
and signed revocations are designed for but not implemented — see
[docs/sync-model.md](docs/sync-model.md). The WireGuard plugin's own limits,
including that its system backend is Linux-only, are in
[docs/wireguard.md](docs/wireguard.md#limits-and-future-work).

**Control and data are separated logically, not physically.** Both ride on
iroh, on different ALPNs and different connections, so the data plane inherits
iroh's hole punching and relay fallback instead of reimplementing them — while
the control protocol still knows nothing about packets and can keep a different
transport underneath it later. Filtering user traffic remains the operating
system's and the user's responsibility, not this library's.

## Requirements

- Rust 1.91 or newer (iroh 1.2 requires it), edition 2024. Pinned dependencies
  in `Cargo.lock`.
- No internet, no public DHT, no public relay, no administrator rights and no changes
  to OS network settings are needed to build or test.
- WireGuard runs in userspace (boringtun): **no kernel module and no `wg`
  tool**. Only creating a real network interface needs `CAP_NET_ADMIN`, and
  `--no-tun` skips even that.

## Trying it on two machines

On the first machine:

```bash
cargo build --release
./target/release/tsunagi status          # this device, the agent, and this host
./target/release/tsunagi network         # the networks this device belongs to
```

Two commands do the work, and they are separate on purpose: `up` runs the
agent — one per device, for as long as you want it — and `join` decides
what it belongs to, at any time, while it runs.

```bash
# Terminal one: the agent. It prints its endpoint id and then serves.
./target/release/tsunagi up

# Terminal two: make a network. With no --secret it invents one and prints
# it, along with the line to send the other machine.
./target/release/tsunagi join --network lab
```

On the second machine, start its agent and join the same network with the
secret that was printed:

```bash
./target/release/tsunagi up
./target/release/tsunagi join --network lab --secret tsn1...
```

**Name and secret are enough for the first meeting.** Mainline DHT discovery
is enabled by default. Each active network publishes this device's endpoint
and searches until the first authenticated connection. While connected it
only republishes; after 60 seconds without any authenticated connection it
searches again. Publication is approximately every five minutes, and records
older than 15 minutes are ignored. DHT storage nodes may retain them longer.

Use `--no-dht` to disable DHT, or `--peer <endpoint-id>` for optional manual
bootstrap. `--reach local` disables public DHT regardless of the DHT flag.
Endpoint records are public, signed, and contain no network secret. Discovery
is not authentication: every connection must still prove network membership.
Details and failure behavior are in [docs/mainline-dht.md](docs/mainline-dht.md).

**One introduction is enough for the whole network.** Members tell each
other about the members they know, and every author of a signed record is
somebody to try, so a device pointed at one member ends up talking to all
of them rather than to the one that happened to be on its command line.
What travels is a candidate — an address somebody has seen — and it is
authenticated by the handshake like any other; being introduced grants
nothing. It is deliberately the same shape a lookup in a distributed hash
table would return, so that is a source to add beside this one rather than
a redesign.

An agent with nobody to contact says so in `status` rather than sitting
there looking patient.

Within a few seconds both print something like:

```text
  + peer b47c958462 connected over direct rtt=Some(4.5ms)
  + data link to b47c958462 for wg-quic: direct via 192.0.2.7:41234, datagram 1382

--- status ---
control: 1 peer(s), 0 dial failure(s), 0 handshake failure(s)
wg-quic: tsun0 on 10.13.37.69/24 mtu 1280, 1/1 tunnel(s) established
  4jO4kx9Z 10.13.37.237 handshake 3s ago tx=0 rx=0 dropped=0 path=direct via 192.0.2.7:41234
```

`1/1 tunnel(s) established` means a real WireGuard handshake completed.

## Checking that it works

From another shell on either machine:

```bash
tsunagi status
```

```text
endpoint  7d76ccbbc21bf30767e14422c0494740a2cecc02aa9f82d5b8d57bdae350e7fc
hostname  tsunagi-7d76ccbbc2
bound     0.0.0.0:41641

network lab (z2o4qwrvnj3zb6st2aoqg4abf342j662q2ujttqrsmz22argk2ba)  active
  peer b345d5271b  tsunagi-b345d5271b  Direct  rtt 24ms
  overlay tsunz2o4qwrvnj3 fd09:…:c1c6/64 and 100.110.49.177 mtu 1280  1/1 tunnel(s) up
    SDsEb/WF  fd09:…:c4b / 100.65.243.53  handshake 4s ago  tx 0 rx 0  Direct via Ip(…)
```

`1/1 tunnel(s) up` and a recent handshake mean the tunnel is live. Then send
real traffic to the peer's overlay address:

```bash
ping6 fd09:…:c4b        # or
ping  100.65.243.53
```

`tx` and `rx` in the status should start moving.

**Addresses are allocated and then remembered.** The default range is
`10.13.37.0/24`; the first member to join settles it and later members adopt
what they find, so `--ipv4-range` only matters for whoever starts the network:

```bash
tsunagi up --ipv4-range 10.44.0.0/16
tsunagi up --ipv4-range none   # no data plane at all
```

One agent has one interface, so two of its networks cannot both use that
range. The second takes the range **derived from its own network id**: not
picked locally — every member derives the same one from something they all
already have — so it is an agreement rather than a guess, and a device in
several networks gets an address in each.

An address is claimed with a record signed by that member's persistent device
key, stored, and merged between every replica. A member that disappears for a
month comes back to the same address, because the claim outlived the session.
No vote is involved — see
[docs/wireguard.md](docs/wireguard.md#ipv4-allocated-signed-and-kept) and
[docs/sync-model.md](docs/sync-model.md).

Because the address is allocated at run time rather than derived, it is not
known until the agent has started and agreed with its peers. The agent then
assigns it to the interface itself.

## Levels

The command line is split the way the design is. A bare `tsunagi up` needs
only a network name and a secret; everything else sits under the level it
belongs to, which `--help` shows as two sections:

* **System** — what the agent itself does: how it reaches peers (`--reach`),
  the one overlay interface it owns (`--interface`, `--mtu`, `--no-tun`), the
  address range (`--ipv4-range`), and the local resolver (`--no-dns` to disable).
* **Transport** — which protocols carry packets (`--protocol`, a list) and
  their own settings (`-o key=value`, or `-o protocol:key=value`).

```bash
tsunagi protocols          # what this build can carry packets with
```

```text
wg-quic  (wire version 4)
        what                  WireGuard's cryptography carried in iroh's QUIC datagrams
        -o keepalive=SECONDS  keeps a tunnel and its link warm through a NAT
        -o mtu=BYTES          largest packet a tunnel will carry, at least 576
```

Each protocol declares its own settings, so the agent can list them without
knowing anything about the protocol, and a setting no selected protocol takes
is refused rather than ignored. `--protocol none` runs the control plane by
itself.

A pair of peers uses a protocol they both have **at the same wire version**.
That is not the software version: two peers on different builds carry traffic
for each other for as long as the bytes between them have not changed. A peer
with nothing in common keeps its control plane — messages and signed state
still flow — and simply has no data plane, which `tsunagi status` shows as a
session with no agreed protocol.

## Names

DNS is enabled by default and serves a local zone for **every network this device is in**,
each named after the network, so members can be reached by name instead of
by address:

```bash
tsunagi up               # DNS is already enabled
dig @127.0.0.1 -p 5354 music.lab
```

An explicit choice is remembered across restarts. `--no-dns` or `tsunagi dns off`
disables it; `--dns` or `tsunagi dns on` enables it again. Existing saved opt-outs
remain respected. The `dns on` and `dns off` commands also take effect immediately
on a running agent. `--dns` and `--no-dns` cannot be combined.

The zone of a network is its name — `--dns-zone` is gone, because with
several networks there is no single zone to name. A network name may contain
dots, so `--network lab.internal` is how you get `music.lab.internal`.

Names come from signed state, which is the point: **a member that is
switched off still resolves**, because its claim outlived the session.

The answers are IPv4 addresses, because that is what the overlay is. The
*questions* are taken on `127.0.0.1` and `[::1]`, over UDP and TCP, so a
resolver reaches it over whichever family it uses; both are published to the
system resolver together. Loopback and nothing else: the zones are a view
for the host running the agent, and binding an overlay address would put
them in front of the whole mesh — an agent in two networks would then answer
one network's questions about the other's names.

The zone is the network name, and it is yours to choose. A name that
shadows a real public domain is reported and then used: a network called
`ru` warns that every public `.ru` name becomes unreachable from this host,
and then does it. Anything that collides with nothing — which is most names
— is said nothing about, because a warning that fires on every private name
anybody picks is how people learn to ignore warnings.

On Linux the agent tells systemd-resolved to send questions for that suffix
here, over D-Bus, scoped to the overlay interface and as a *routing* domain
so it never becomes the resolver for anything else. resolved drops the whole
setting when the interface goes, and the interface goes with the agent.

Only an interface the agent created, though. Under `--no-tun` there is no
host interface at all, and the agent says so and serves the zone on
loopback rather than configuring whatever else on the host happens to share
the name.

That last step needs permission that `CAP_NET_ADMIN` does not give:
systemd-resolved asks polkit, and polkit decides by **user**, not by
capability, so there is no way for the agent to arrange it from inside. On
a desktop the refusal reads `Interactive authentication required`.

Running as a system service is enough. Otherwise the agent prints the rule
that grants it — the four actions it calls and nothing else — ready to
paste:

```bash
sudo tee /etc/polkit-1/rules.d/50-tsunagi-resolved.rules > /dev/null <<'RULE'
polkit.addRule(function(action, subject) {
    var allowed = [
        "org.freedesktop.resolve1.set-dns-servers",
        "org.freedesktop.resolve1.set-domains",
        "org.freedesktop.resolve1.set-default-route",
        "org.freedesktop.resolve1.revert"
    ];
    if (allowed.indexOf(action.id) >= 0 && subject.user == "YOUR-USER") {
        return polkit.Result.YES;
    }
});
RULE
```

**Without it the server still runs** — `tsunagi status` prints where it is
listening and the exact `dig` line — so the automatic part is missing, not
the feature. The refusal is said once rather than on every pass, and retried
slowly, because nothing but a person will change it.

The server is authoritative for its zone and nothing else. No recursion, no
forwarding, no cache: pointing a resolver at it can never make it a route to
the outside.

## Privileges

On Linux the agent **manages its own overlay interface**. It creates the TUN
interface, sets the MTU, brings it up and assigns both overlay addresses, all
over netlink in process — no `ip` invocation, no shell, nothing that a
remote peer could influence.

That needs `CAP_NET_ADMIN`, granted once:

```bash
sudo setcap cap_net_admin+p /usr/local/bin/tsunagi
```

`+p` rather than `+ep`: the capability is then *permitted* but not
*effective*, and the agent raises it only around the handful of netlink calls
that need it — a few milliseconds at startup, and again if its address
allocation changes. Everything else, including every byte from the network,
is handled with it lowered. `+ep` works too; the agent lowers it on the way
in.

`tsunagi status` says which of these applies on the host it runs on, along
with what the agent is doing. It grades each finding: **ok** for what works,
**warn** for what the agent runs without and you can fix from the line it
prints, **FAIL** for what it cannot work around. The words carry the grade as
well as the colour, so the report reads the same piped to a file or on a
terminal without colour, and it honours `NO_COLOR`.

Members are listed online first, then the ones that are away. A member that
is away is reported plainly rather than flagged: in a mesh of laptops it is
the ordinary condition, not a fault. The signed state is what makes that
sayable — it remembers who belongs while they are gone, so the report can say
"offline, 10.13.37.99 still reserved for it" instead of leaving a
dial-failure counter to imply it. Counters are history and are never graded:
a peer that left and came back should not leave the report looking broken.

The other two commands split along the line the system itself draws. `id` is
this **device**: the key it signs with and the name it answers to. `network`
is what it **belongs to**: which networks, their secrets, joining and
leaving. A device outlives every network it is in, and a network outlives
any device in it, so a command that mixed them had to be read twice.

Every item takes the same shape, so there is nothing to remember: name it to
see it, name it with a value to change it.

```
tsunagi id                      everything about this device
tsunagi id hostname             the name it answers to
tsunagi id hostname mango       change it
tsunagi id key                  the key it signs with
tsunagi id key rotate           replace that key

tsunagi network                 the networks this device belongs to
tsunagi network join -n lab -s tsn1…   join one; adds it to a running agent
tsunagi network join -n lab     resume one this device has, or make it on the spot
tsunagi network stop lab        stop serving it, keeping everything
tsunagi network start lab       serve it again, from where it left off
tsunagi network leave lab       give up the address and name, then forget it
tsunagi network secret          the secret of each joined network
tsunagi network secret lab      just that one, for copying
tsunagi network secret generate a fresh secret for a network that does not exist yet

tsunagi dns                     whether the local resolver is serving, and what
tsunagi dns on                  start it, now and after every restart
tsunagi dns off                 stop it, now and after every restart
```

**A network without a secret makes one.** `tsunagi join --network lab`
resolves a bare name in the obvious way: if this device is already in
exactly one network called `lab`, that one — so the name alone resumes what
you have; if it is in none, a fresh random secret, printed in full with the
line to send the other machine:

```
joined `lab` (k2on43wadbi5x267vp6z3ogkm7nbjedfdoxyauxhtxhwqrprylba)
  secret  tsn1u7c…

Run this on the other machine:

  tsunagi join --network lab --secret tsn1u7c…

Its agent has to be running. If it is not:

  tsunagi up --peer 91e83a6e2b7a…
```

Two networks of one name is a thing that happens — a mistyped secret makes
one — so joining says whether the network was already here, and warns when
another configured network answers to the same name. A name is a label and
the id is the identity.

That is the ad-hoc case: one person makes a network and sends the command
round. The secret is printed *only* when the agent invented it — there is
nowhere else to read it from — and never when it was supplied, because then
it is already yours. Two networks of one name and no secret is the one case
with no answer, and it says so instead of choosing.

A secret is printed by `network secret` and nowhere else — not by `id`, not
by `status`, not in a log, a `Debug` rendering or anything sent to a peer.
Asking for it is deliberate, because these reports get pasted into chats.

**`up` takes no network at all** if you would rather decide later: it
brings up the agent and whatever it is already configured for, and waits.
That is the shape of a daemon in one terminal and `tsunagi network join`
in another.

`network join` is also the answer to a question `up` cannot: a state
directory belongs to one live agent, so a second `tsunagi up` cannot add a
network to the one already running. This adds it over the control socket and
it starts at once. With no agent running it is written to the configuration
and starts with the next `up`.

The name is part of the signed state, so changing it revokes the previous
one: there is one record per author, a new version replaces the whole claim,
and no replica can keep the old name standing. Changing it while the agent
runs goes through the agent, which republishes and tells its peers straight
away.

Replacing the signing key makes this device a different member, and it loses
the address and name the old key held — nothing can sign on a retired key's
behalf, and by design there is no authority that could overrule an author. So
the outgoing key signs a release for every network on its way out, which
frees them for whoever wants them next, and the whole thing commits at once.

`status` and `id` both prefer a running agent, which is live and
authoritative, and fall back to reading the state store when there is none.
Reading takes no directory lock, so neither has to wait for the agent it is
asking about — nor does either need one to be running.

### It cleans up after itself

The interface is tied to an open file descriptor and is deliberately **not**
made persistent, so the kernel removes it when the agent exits — on a clean
shutdown, on a panic, on `SIGKILL`, on power loss alike. Keeping it is what
would take an action; removing it is the default.

If something is left behind anyway — an interface made by an older version's
manual recipe, or one from a run killed in the instant between creating it and
recording it — the next start **replaces it**, along with any stale addresses
it carried. Two things are never touched:

* an interface that is not a TUN, because the name colliding with somebody's
  bridge is not a reason to destroy the bridge;
* a TUN that another process is holding open, because that is a working
  overlay belonging to somebody else — most likely a second agent on this
  host, which should be given a different `--wg-prefix`.

Both of those refuse with an explanation rather than guessing.

Two settings the manual recipe used to need are gone with it.
`keep_addr_on_down` existed only because an interface nobody held open lost
carrier and had its IPv6 addresses flushed, and `nodad` only because duplicate
address detection can never finish without carrier. An interface held open for
its whole life has carrier for its whole life.

### The MTU is 1280

The default interface MTU stays at 1280 on direct paths, relays and paths
inside another VPN. Large encrypted packets are split into smaller QUIC
datagrams and reassembled before reaching WireGuard. SSH and full-size TCP
segments therefore do not require a manual MTU override or MSS adjustment.
The original IP packet, including its DF bit, is preserved. See
[docs/wireguard.md](docs/wireguard.md#mtu) for limits and compatibility.

### Summary

| approach | agent runs as | notes |
|---|---|---|
| `setcap cap_net_admin+p` | ordinary user, one capability | recommended: nothing to prepare, nothing left behind. Lost on every rebuild or copy of the binary. |
| systemd service | `User=`, `AmbientCapabilities=CAP_NET_ADMIN` | the same, for an installed service |
| `sudo tsunagi up` | root | everything works, nothing is isolated |
| `--no-tun` | ordinary user, no capabilities | tunnels run and handshake, traffic never reaches the OS |

On Windows, put `wintun.dll` beside the executable and start `tsunagi up`
from PowerShell or Command Prompt opened with **Run as administrator**.
Run commands controlling that agent (`join`, `status`, `dns`, `network`)
as the same Windows user with the same elevation. If Windows denies access
to the agent's control pipe, the command reports a permission error instead
of claiming the agent is absent or trying to edit its locked state.
Creating a TUN without sufficient privileges also explains how to restart
the agent with the required permissions.

**Not implemented yet.** macOS has no provisioner; `--no-tun` is the way to
run it. The control plane and tunnels are unaffected. The decision logic
that says *what* to change is shared and tested on every platform.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The whole suite runs offline on loopback. Set `TSUNAGI_TEST_LOG=tsunagi=debug`
to see agent logs while a test runs.

There are also two runnable demos, which are demos and not substitutes for the
tests:

```bash
cargo run --example two_agents       # control plane only
```

Both run with no privileges and change nothing on the host.

## Usage

```rust,no_run
use std::sync::Arc;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::proto::ControlMessage;
use tsunagi::{Agent, Result};

// The library never starts a runtime, installs a logger, handles signals,
// forks, or calls process::exit. The binary owns all of that.
#[tokio::main]
async fn main() -> Result<()> {
    let config = AgentConfig::new(StoragePaths::user_default()?)
        .with_transport(TransportPolicy::N0Defaults)
        .with_discovery(Arc::new(SharedMemoryDiscovery::new()));

    let agent = Agent::spawn(config).await?;

    let name = NetworkName::new("kitchen-table")?;
    let secret = NetworkSecret::generate();       // 32 random bytes
    println!("share this: {}", secret.encode().as_str());

    let network = agent.join_network(&name, &secret).await?;

    let mut events = agent.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            println!("{event:?}");
        }
    });

    for peer in agent.network_status(network).await?.connected_peers() {
        agent
            .send(network, peer, ControlMessage::Ping { seq: 1, payload: vec![] })
            .await?;
    }

    agent.shutdown().await;
    Ok(())
}
```

`TransportPolicy::LocalOnly` is the default, so a plain `AgentConfig::new` never
reaches the internet by accident. Opt into `DirectOnly` or `N0Defaults`
explicitly.

### Through somebody in the middle

Tsunagi routes the overlay in userspace. A direct data link always wins;
otherwise the shortest available path can pass through several members.
Each authenticated member advertises only its own live, protocol-specific
transport links. The control plane collects these into a graph and replaces
the routing table when connectivity changes; announcements expire after
90 seconds without refresh.

Transit goes transport → router → transport, without entering WireGuard or
the intermediate host's TUN. The payload stays encrypted between the original
endpoints. TUN connects only the local OS to Tsunagi; the kernel needs only
the overlay route through that interface, with no IP forwarding configuration.

A 16-hop limit bounds loops while topology updates converge. Equal shortest
paths use a stable flow hash derived before encryption, so packets of a TCP
or UDP flow keep their path while topology is unchanged. Physical link changes
do not replace end-to-end WireGuard tunnels or change the 1280-byte default MTU.
`status` reports the hop count and first next hop for relayed paths.

The hot path reads an immutable routing snapshot and sends directly to a cached
transport handle. It takes no routing mutex, walks no graph and does not parse
the encrypted payload. See [routing.md](docs/routing.md) for the architecture,
limits and reproducible forwarding microbenchmark.

This wire format requires all members to upgrade together (control ALPN 3,
data ALPN 4); saved identities, network names, secrets and addresses survive.

### LAN game discovery

IPv4 UDP broadcast relay is enabled by default for each network. The IP router
sends one encrypted copy to each participating peer, including through multihop
paths. It supports `255.255.255.255` and the overlay subnet's broadcast address;
received broadcasts never trigger another fanout.

```sh
tsunagi join -n games --no-broadcast
tsunagi join -n games --broadcast
tsunagi network broadcast games off
tsunagi network broadcast games on
```

The choice persists across restarts and a plain `join`. It can be changed while
the agent runs; `status` shows it for each network. The game must send through
the Tsunagi interface. Physical LAN capture/subnet sharing is not implemented.
See [broadcast.md](docs/broadcast.md) for domain isolation and future LAN gateways.

## How peers find each other

Two different lookups are involved, and only one of them is this project's:

**1. Resolving one endpoint's address — iroh's, and it works today.**
With `--reach relay` or `--reach direct`, iroh publishes a signed
record of this endpoint's addresses, keyed by its endpoint id, to the public
service run by Number 0 — "n0", the company behind iroh — at `dns.iroh.link`,
over pkarr and DNS, and resolves other endpoints the same way. That is why `--peer <endpoint-id>` works with no address attached:
iroh looks it up. None of that code is ours.

**2. Finding who is in a network — Mainline DHT by default.**
`NetworkDiscovery` supplies unverified candidates. The Mainline backend uses
a signing key derived from the network name and secret to publish signed
BEP44 records containing each writer's endpoint ID and addresses. Its 16
slots provide starting candidates, not a complete membership list or a limit
on network size. After the first authenticated connection, introductions and
signed state reveal the other members. `StaticBootstrap` (`--peer`) remains
available, and tests use either a local Mainline Testnet or in-memory discovery.

What this means in practice:

- With `relay` or `direct`, **your endpoint id and IP addresses are published
  to a public third-party service** (Number 0's, unless you change it). They are not secret, and the network secret is
  never published, but an observer of that service learns that your endpoint
  exists and where it is. `--reach local` publishes nothing.
- With DHT enabled, endpoint records are also published to the public Mainline
  DHT. They are signed, not encrypted; membership still requires the secret.
- A relay, when one is needed, sees the volume and timing of your traffic — not
  its contents. The default relays are Number 0's, in the US, EU and
  Asia-Pacific.

## Storage

Two physically separate SQLite files, placed wherever the library's
configuration says (`StoragePaths`). A future system service supplies its own
paths; tests always use temporary directories.

| file           | holds                                            | when damaged            |
|----------------|--------------------------------------------------|-------------------------|
| `state.sqlite` | device identity, network configuration, hostname | clear error, never reset |
| `cache.sqlite` | address hints and other recoverable data          | discarded and recreated  |

The `wg-quic` protocol keeps its own keys in its own store under `wg-quic/`,
because a protocol's keys are neither the iroh identity nor the network
secret.

The command line agent puts everything under the platform's per-user
directories by default; `--state-dir` and `--cache-dir` override them.

One state directory belongs to one live agent, enforced with a real OS file
lock rather than an existence check. That directory *is* the identity: one
agent, one device key, one interface, and as many networks as you like on it
— `tsunagi network join` adds them to the agent that is already running,
which is why a second `tsunagi up` on the same directory is refused rather
than made to work. A second agent on the same host is a second identity, and
needs everything of its own: its own state and cache directories, its own
interface name and its own overlay range. The library owns no globals, so
several of them run side by side in one process as readily as in one host.

### Leaving, and starting over

Membership outlives a session, so it also has to be possible to end it.

```bash
tsunagi network                     # what this device belongs to
tsunagi network leave lab           # give up the address and the name, then forget it
tsunagi wipe --yes                  # remove everything and be a stranger again
```

**Stopping is not leaving.** `stop` closes this network's sessions, takes
its address off the interface and keeps it from starting again, and that is
all: the configuration, the secret, the signed state and the protocol key
stay exactly as they are, nothing is announced, and to the others this
device is simply away — an ordinary condition they already handle, with its
address and name still reserved for it. `start` picks it up where it left
off. A network named on the `up` command line is started by that command
whatever its stored state, and the start-up banner says so rather than
letting a `stop` quietly come back.

`leave` is the other one, and it removes, locally: the configuration and
the secret, this network's signed records, its cached address hints and the
protocol key it used there. What it keeps is this author's version counter
for that network — a rejoin has to continue above the release, or every
replica would treat the new claim as stale. Everything about *other*
networks, and the device identity itself, is untouched.

`leave` publishes a signed `Release` **first**, while the agent is running and
its sessions are up, so the address and the name are freed for the others
instead of staying reserved to a member that has gone. They pass the tombstone
on, so a member that was away hears it from them. With no agent running,
nothing can sign or send it: the command says so and refuses, and `--offline`
drops the network locally while leaving the others holding the old claim. The
protocol key for that network goes too — rejoining is joining, not resuming.

`leave`, `stop`, `start`, `secret` and `broadcast` accept an exact stored network
name, its full id, or a unique id prefix (including a copied report ellipsis).
Names are case-sensitive. If several networks share a name, or a name matches
another network's id prefix, the command lists matching names and full ids and
changes nothing. Use a full id to choose explicitly; a full id always takes
precedence over a name. No secret is needed to select a configured network.

`wipe` removes both directories' contents: the device identity, every network,
every signed record and everything a protocol kept beside them. It refuses
while an agent is running, and refuses a directory with no `state.sqlite` in
it, so a mistyped `--state-dir` cannot take somebody's documents with it.
Without `--yes` it only says what it would remove. It is not a goodbye: nobody
is told, because after it there is no key left to sign anything with. Leave the
networks first if the addresses should be freed.

## Documentation

- [docs/architecture.md](docs/architecture.md) — module boundaries and runtime.
- [docs/wireguard.md](docs/wireguard.md) — the WireGuard plugin: overlay
  addressing, announcements, backends, reconciliation.
- [docs/protocol.md](docs/protocol.md) — identity derivation, framing, handshake.
- [docs/sync-model.md](docs/sync-model.md) — the planned signed-state model and
  what is deliberately not built yet.
- [docs/threat-model.md](docs/threat-model.md) — threat model and known limits.
- [docs/testing.md](docs/testing.md) — what the suite covers and what it does not.
- [AGENTS.md](AGENTS.md) — rules for anyone (human or agent) changing this repo.

## Security in one paragraph

Membership is proved by an HMAC over a transcript keyed by a value derived from
the shared secret, bound to the specific iroh connection through the TLS
exporter, to the network id, to both endpoint identities and to distinct role
labels. This targets high-entropy secrets: there is no PAKE here, so a short
human passphrase is guessable offline by anyone who can reach the handshake.
Anyone who knows the secret is a full participant and can create many
identities. Read [docs/threat-model.md](docs/threat-model.md) before relying on
any of this.

## Licence

MIT OR Apache-2.0.

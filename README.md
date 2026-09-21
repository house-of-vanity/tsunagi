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

Not implemented, and not pretended to be: Mainline DHT, DNS, routing through
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
- No internet, no DHT, no public relay, no administrator rights and no changes
  to OS network settings are needed to build or test.
- WireGuard runs in userspace (boringtun): **no kernel module and no `wg`
  tool**. Only creating a real network interface needs `CAP_NET_ADMIN`, and
  `--no-tun` skips even that.

## Trying it on two machines

On the first machine:

```bash
cargo build --release
./target/release/tsunagi id secret generate   # prints tsn1...; share it privately
./target/release/tsunagi status          # this device, the agent, and this host

./target/release/tsunagi up --network lab --secret "$SECRET"
```

It prints its endpoint id and then waits. On the second machine, pass that id:

```bash
./target/release/tsunagi up --network lab --secret "$SECRET" \
  --peer <endpoint-id-from-the-first-machine>
```

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

IPv6 works out of the box: each member's address is derived from the network
id and collides with essentially nothing.

**IPv4 addresses are allocated and then remembered.** The default range is
`10.13.37.0/24`; the first member to join settles it and later members adopt
what they find, so `--ipv4-range` only matters for whoever starts the network:

```bash
tsunagi up --network lab --secret "$SECRET"  --ipv4-range 10.44.0.0/16
tsunagi up --network lab --secret "$SECRET"  --ipv4-range none   # IPv6 only
```

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
  address range (`--ipv4-range`), and the local resolver (`--dns`).
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

`--dns` serves a local DNS zone for the network's members, so they can be
reached by name instead of by address:

```bash
tsunagi up --network lab --secret "$SECRET" --dns
dig @10.13.37.69 -p 5354 music.lab
```

Names come from signed state, which is the point: **a member that is
switched off still resolves**, because its claim outlived the session. IPv4
only — the IPv6 overlay address derives from a key that travels in live
announcements, so it cannot be answered for a member that is away, and
answering for some members and not others depending on who is online is
worse than not answering.

The zone is the network name unless `--dns-zone` says otherwise. It is
yours to choose, so a name that shadows a real public domain is reported and
then used: `--dns-zone ru` warns that every public `.ru` name becomes
unreachable from this host, and then does it. `.internal` is reserved for
exactly this and is never mentioned.

On Linux the agent tells systemd-resolved to send questions for that suffix
here, over D-Bus, scoped to the overlay interface and as a *routing* domain
so it never becomes the resolver for anything else. resolved drops the whole
setting when the interface goes, and the interface goes with the agent.

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

`id` is the other half: it shows what this device is — its signing key, the
name it answers to, and the secret of every network it has joined — and
changes those. Every item takes the same shape, so there is nothing to
remember: name it to see it, name it with a value to change it.

```
tsunagi id                      everything about this device
tsunagi id hostname             the name it answers to
tsunagi id hostname mango       change it
tsunagi id key                  the key it signs with
tsunagi id key rotate           replace that key
tsunagi id secret               the secret of each joined network
tsunagi id secret generate      a fresh secret for a network that does not exist yet
```

Secrets appear in `id`, which is where you go to ask for one, and never in
`status`, in a log, in a `Debug` rendering or in anything sent to a peer.

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

That is the minimum IPv6 requires (RFC 8200), and Linux enforces it by
disabling IPv6 outright on an interface below it — the per-device
`/proc/sys/net/ipv6` entries vanish and adding an address fails with
`Invalid argument`. A smaller MTU cannot work at all, so the agent refuses one
rather than letting it fail later. See
[docs/wireguard.md](docs/wireguard.md#mtu) for the ceiling that pushes back
from the other side.

### Summary

| approach | agent runs as | notes |
|---|---|---|
| `setcap cap_net_admin+p` | ordinary user, one capability | recommended: nothing to prepare, nothing left behind. Lost on every rebuild or copy of the binary. |
| systemd service | `User=`, `AmbientCapabilities=CAP_NET_ADMIN` | the same, for an installed service |
| `sudo tsunagi up` | root | everything works, nothing is isolated |
| `--no-tun` | ordinary user, no capabilities | tunnels run and handshake, traffic never reaches the OS |

**Not implemented yet.** macOS and Windows have no provisioner: both need
real platform work — `utun` and `SystemConfiguration` on one, the IP Helper
API and a Wintun adapter on the other. There the agent says so and `--no-tun`
is the way to run it; the control plane and the tunnels are unaffected. The
decision logic that says *what* to change is shared and tested on every
platform, so only the execution is left to write.

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

## How peers find each other

Two different lookups are involved, and only one of them is this project's:

**1. Resolving one endpoint's address — iroh's, and it works today.**
With `--reach relay` or `--reach direct`, iroh publishes a signed
record of this endpoint's addresses, keyed by its endpoint id, to the public
service run by Number 0 — "n0", the company behind iroh — at `dns.iroh.link`,
over pkarr and DNS, and resolves other endpoints the same way. That is why `--peer <endpoint-id>` works with no address attached:
iroh looks it up. None of that code is ours.

**2. Finding who is in a network — ours, and it is still manual.**
`NetworkDiscovery` maps a secret-derived `DiscoveryKey` to a set of *candidate*
members. Two backends exist: `StaticBootstrap` (what `--peer` feeds) and an
in-memory one for tests. The planned Mainline DHT backend, which would let
members find each other from the network secret alone, is **not implemented**.
So today you bootstrap by passing one peer's id; after that the mesh is
whatever those agents reach.

What this means in practice:

- With `relay` or `direct`, **your endpoint id and IP addresses are published
  to a public third-party service** (Number 0's, unless you change it). They are not secret, and the network secret is
  never published, but an observer of that service learns that your endpoint
  exists and where it is. `--reach local` publishes nothing.
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
lock rather than an existence check.

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

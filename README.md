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
- a **WireGuard data plane**, in userspace: its own key per network,
  deterministic IPv6 overlay addressing, real tunnels carried over iroh, and
  address ownership enforced rather than believed;
- a **command line agent**, `tsunagi`.

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
./target/release/tsunagi secret          # prints tsn1...; share it privately
./target/release/tsunagi doctor          # what this host can and cannot do

./target/release/tsunagi up --network lab --secret "$SECRET" --wireguard
```

It prints its endpoint id and then waits. On the second machine, pass that id:

```bash
./target/release/tsunagi up --network lab --secret "$SECRET" --wireguard \
  --peer <endpoint-id-from-the-first-machine>
```

Within a few seconds both print something like:

```text
  + peer b47c958462 connected over Direct rtt=Some(4.5ms)
  + data link to b47c958462 for wireguard: Direct via Ip(…), datagram 1382

--- status ---
control: 1 peer(s), 0 dial failure(s), 0 handshake failure(s)
wireguard: tsunkkcp43lmdje on fd15:1d9e:fa21:f201:…/64 mtu 1100, 1/1 tunnel(s) established
  4jO4kx9Z fd15:1d9e:fa21:f201:… handshake 3s ago tx=0 rx=0 dropped=0 path=Direct via Ip(…)
```

`1/1 tunnel(s) established` means a real WireGuard handshake completed. Then
`ping6` the peer's overlay address.

Notes:

- Only one side needs `--peer`; the link is bidirectional.
- The default `--transport relay` uses iroh's public address lookup and relays,
  so two machines behind NAT find each other. `--transport local` keeps everything
  on the local network. See *How peers find each other* below — it is worth
  understanding what gets published.
- Without `CAP_NET_ADMIN`, add `--no-tun`: the mesh, the data links and the
  WireGuard handshakes all still run and are visible in the status output, only
  traffic does not reach the operating system. That is the quickest way to
  confirm the network forms.
- Run as root (or grant `CAP_NET_ADMIN`) to get a real interface.

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
cargo run --example wireguard_mesh   # a WireGuard overlay carrying a real packet
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
With `--transport relay` or `--transport direct`, iroh publishes a signed
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
  exists and where it is. `--transport local` publishes nothing.
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

The WireGuard plugin keeps its own keys in its own `wireguard.sqlite`, wherever
its configuration points, because plugin keys are neither the iroh identity nor
the network secret.

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

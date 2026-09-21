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
- a **WireGuard data plane plugin**: its own key per network, deterministic
  IPv6 overlay addressing, a full-mesh configuration built locally, and
  reconciliation that repairs drift.

### What it deliberately does **not** do

Not implemented, and not pretended to be: Mainline DHT, DNS, routing through
intermediate participants, a full CRDT, dynamically loaded plugins, a system
service, a complete CLI, or a local control socket. Snapshot synchronisation
and signed revocations are designed for but not implemented — see
[docs/sync-model.md](docs/sync-model.md). The WireGuard plugin's own limits,
including that its system backend is Linux-only, are in
[docs/wireguard.md](docs/wireguard.md#limits-and-future-work).

**Only control messages travel over iroh. User IP traffic is not tunnelled
through it.** Filtering user traffic is the operating system's and the user's
responsibility, not this library's.

## Requirements

- Rust 1.91 or newer (iroh 1.2 requires it) (edition 2024). Pinned dependencies in `Cargo.lock`.
- No internet, no DHT, no public relay, no administrator rights and no changes
  to OS network settings are needed to build or test.

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
cargo run --example wireguard_mesh   # two agents forming a WireGuard overlay
```

Both run with no privileges and change nothing on the host.

The one part that does change the host's network — the real `wg`/`ip` backend —
is behind `--ignored` and needs Linux, wireguard-tools and `CAP_NET_ADMIN`:

```bash
sudo -E cargo test --test wireguard_system -- --ignored --test-threads=1
```

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

# The WireGuard plugin

WireGuard is the first IP plugin. It creates real IP connectivity between
participants while the control plane keeps doing its own job: deciding who is
in the network and carrying each participant's opaque announcement.

Module boundaries are in [architecture.md](architecture.md), the control
protocol in [protocol.md](protocol.md), and the security consequences in
[threat-model.md](threat-model.md).

## What stays separate

| | |
|---|---|
| **User IP traffic** | Never goes through iroh. iroh carries announcements; packets travel over WireGuard's own UDP sockets. |
| **Addresses** | An iroh address is an address for iroh. The plugin gathers and advertises its own reachability. |
| **Payloads** | The core moves a bounded opaque blob. Only `dataplane::wireguard::announcement` interprets it. |
| **Keys** | One WireGuard key per network, in the plugin's own store. Unrelated to the iroh device key and to the network secret. |
| **Failures** | A data plane error is reported and retried. The control plane keeps running and the agent stays manageable. |

## Deterministic overlay addressing

A mesh with no coordinator cannot hand out addresses, so everyone derives their
own. The result is an IPv6 unique local address (RFC 4193):

```text
prefix (/64) = 0xfd || SHA-256( LP(domain) || LP("prefix") || LP(network_id) )[0..7]
iid    (64b) =         SHA-256( LP(domain) || LP("interface") || LP(network_id) || LP(wg_public_key) )[0..8]
address      = prefix || iid
```

with `domain = "tsunagi-wireguard-overlay-v1"` and `LP(x) = u32_be(len(x)) || x`,
the same unambiguous encoding the rest of the project uses.

Two consequences matter:

* every member of a network derives the **same `/64`**, so the overlay is one
  subnet that nobody had to allocate;
* a member's address is bound to its WireGuard public key, so
  **`AllowedIPs` are derived locally and never taken from what a peer claims**.

That second point is the plugin's central security property. A participant who
knows the network secret can mint as many WireGuard keys — and therefore as
many overlay addresses — as it likes, but it cannot choose to collide with an
existing member's address without finding a hash preimage. An announcement
whose claimed address does not match the derivation is rejected outright.

## The announcement

Carried as the opaque `PluginCapability { protocol: "wireguard", .. }` payload,
encoded with postcard:

| field | meaning |
|---|---|
| `version` | announcement format version, currently 1 |
| `public_key` | the peer's X25519 WireGuard key |
| `listen_port` | the UDP port its interface listens on |
| `endpoints` | reachability the plugin gathered for itself, at most 8 |
| `overlay_address` | what the peer believes its address is — cross-checked, never used |

Validation, all before anything reaches a configuration: the version must
match, the key must not be zero and must not be our own, the port must not be
zero, the endpoint list must be within bounds, unusable endpoints
(unspecified, multicast, broadcast, documentation, port zero) are dropped, and
the claimed overlay address must equal the derived one.

## Building the configuration

Each agent builds its **own** configuration from the agreed set of
participants: for a full mesh of `N` members that is `N - 1` peers locally.
Nobody hands a configuration to anybody else and no participant is
authoritative.

* **Interface name** — `prefix + base32(network_id)`, truncated to the
  platform's 15 characters. Stable across restarts. Two agents on one host in
  the same network need different prefixes.
* **Port** — `PortPolicy::Derived` picks a stable port from the network id
  inside a range, so a peer's cached endpoint keeps working across restarts and
  two networks on one host do not collide. `PortPolicy::Fixed` pins it.
* **Addresses** — the agent's own `/128` plus the shared `/64`.
* **Peer entries** — public key, derived `AllowedIPs`, the peer's first usable
  advertised endpoint, and a keepalive.

Nothing free-form from the network reaches a command argument or a
configuration directive: peer keys, endpoints, prefixes and keepalives are
typed values that the plugin re-serialises itself.

## Backends

The plugin computes *what* the interface should look like; a backend makes it
so. Splitting them is what keeps every interesting decision testable without
root.

* **`RecordingBackend`** — applies configurations in memory. The default test
  suite and the example use it, so neither needs privileges nor touches the
  host. It can also be told to fail, or to report drift.
* **`WgToolBackend`** — drives the real `wg` and `ip` tools. Linux only,
  requires `CAP_NET_ADMIN`. It is split into a **pure planner** and pure
  parsers, which are unit tested on every platform, plus a thin executor. The
  WireGuard configuration is piped to `wg setconf` / `wg syncconf` on standard
  input, so the private key never reaches the filesystem.

Ownership is explicit: the plugin creates the interface and the plugin removes
it. An interface that already exists and is not a WireGuard device is
**refused, not adopted**, so the agent never takes over something it did not
create. It changes no routing, DNS or firewall settings.

## Reconciliation

The plugin reconciles on every change — a peer announcement, a peer leaving —
coalesced over a short debounce, and again on a timer. Each pass reads the
interface back, compares it with the desired state, and applies only if they
differ. A configuration edited by hand is therefore put back the way it should
be, which is exactly what `reconciliation_repairs_a_configuration_edited_by_hand`
in `tests/wireguard.rs` checks.

Deactivating a network removes its interface but **keeps its key**, so coming
back later keeps the same overlay address. Agent shutdown removes every
interface the plugin created.

## What the plugin needs from the core

Three small additions to the `IpPlugin` contract, all generic rather than
WireGuard-specific:

* `on_network_activated` — prepare per-network state before any peer appears;
* `attach(PluginContext)` — a handle to ask for a re-announcement when the
  plugin's own capability changes, and to report an error from its own tasks;
* `shutdown` — remove system objects during a bounded agent shutdown.

Errors reported through the context are counted by the owning network's
runtime, so `NetworkMetrics::plugin_errors` and `Event::PluginError` always
agree.

## Using it

```rust,no_run
use std::sync::Arc;
use std::time::Duration;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{WgToolBackend, WireguardConfig, WireguardPlugin};
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::{Agent, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let paths = StoragePaths::user_default()?;

    // The plugin's own state, separate from the agent's.
    let wireguard = WireguardConfig::new(paths.state_dir.join("wireguard"));
    let backend = WgToolBackend::new().expect("Linux with wg and CAP_NET_ADMIN");
    let plugin = WireguardPlugin::open(wireguard, Arc::new(backend))
        .await
        .expect("wireguard plugin");

    let agent = Agent::spawn(
        AgentConfig::new(paths)
            .with_transport(TransportPolicy::N0Defaults)
            .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
    )
    .await?;

    let network = agent
        .join_network(&NetworkName::new("kitchen-table")?, &NetworkSecret::generate())
        .await?;

    if let Some(view) = plugin.overview(network) {
        println!("{} on {} at {}", view.interface, view.overlay_prefix, view.overlay_address);
    }

    tokio::time::sleep(Duration::from_secs(60)).await;
    agent.shutdown().await;   // removes the interface
    Ok(())
}
```

There is a runnable version in `examples/wireguard_mesh.rs`, which uses the
in-memory backend by default and the real one with `--real`.

## Limits and future work

* **Full mesh only.** Every member configures every other member. Routing
  through an intermediate participant is not implemented.
* **No IPv4 overlay.** Addressing is IPv6 ULA, because it can be derived
  collision-free. An IPv4 overlay would need an allocator, which needs the
  agreed state described in [sync-model.md](sync-model.md).
* **Peer membership is session-scoped.** A peer disappears from the
  configuration when its control session ends. Persisting membership across a
  long absence is part of the same future work.
* **`WgToolBackend` is Linux only.** A netlink backend, and backends for macOS
  and Windows, are not implemented. `WgToolBackend::new()` fails with a clear
  message elsewhere.
* **No MTU or path discovery.** The MTU is a configured constant.
* **The real backend is not exercised by the default suite.** It needs root,
  so its tests live in `tests/wireguard_system.rs` behind `--ignored`.

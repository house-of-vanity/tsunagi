# The WireGuard data plane

WireGuard is the first IP plugin. It carries user traffic between
participants while the control plane keeps doing its own job: deciding who is
in the network and carrying each participant's opaque announcement.

Module boundaries are in [architecture.md](architecture.md), the control
protocol in [protocol.md](protocol.md), the security consequences in
[threat-model.md](threat-model.md).

## Userspace, not the kernel

WireGuard here is [boringtun]'s protocol state machine running in this
process. There is **no kernel WireGuard module** and **no `wg` tool**: the same
code runs everywhere, and the protocol can be exercised in tests without any
privileges at all.

The only privileged step left is creating a packet interface so the operating
system can hand us IP packets, and even that is behind a trait
([`TunFactory`]) with an in-memory implementation.

| | needs privileges | what it proves |
|---|---|---|
| `MemoryTunFactory` | no | handshake, encryption, routing, address ownership |
| `SystemTunFactory` | `CAP_NET_ADMIN` | traffic actually reaches the OS |

[boringtun]: https://docs.rs/boringtun
[`TunFactory`]: https://docs.rs/tsunagi

## Where the packets go

The plugin does not know and does not care. It is handed a `PacketLink` per
peer by the agent and runs a WireGuard tunnel over it:

```text
  TUN device (IP packets)                  PacketLink per peer
       |                                          |
       v                                          v
  destination address -> peer  --Tunn.encapsulate-->  ciphertext -> transport
  source address checked       <--Tunn.decapsulate--  ciphertext <- transport
```

Reachability — hole punching, relay fallback — belongs to the transport, which
today is iroh. That is the whole reason the plugin's announcement says *who* it
is and never *where* it is: there is no address for a peer to advertise, get
wrong, or lie about.

**Two peers behind NAT work exactly as well as iroh does.** iroh hole punches a
direct path when it can and falls back to a relay when it cannot; the tunnel
rides on whichever it got. There is no separate STUN, no separate hole punching
and no second set of NAT problems to solve for WireGuard.

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
* a member's address is bound to its WireGuard public key, so address
  ownership can be checked locally rather than believed.

## Address ownership is enforced, not announced

Kernel WireGuard enforces `AllowedIPs`. In userspace that is our job, and
[`device`] does it on both sides:

* **outbound**, a packet is routed to the peer that *owns* its destination
  address; a destination nobody owns is counted as unroutable and dropped;
* **inbound**, a decrypted packet is dropped unless its *source* is exactly the
  address derived for the peer whose tunnel decrypted it.

So a participant cannot receive traffic addressed to somebody else and cannot
forge traffic that appears to come from somebody else. A participant who knows
the network secret can mint many keys and therefore occupy many addresses, but
it cannot choose to collide with an existing member without finding a hash
preimage.

The announcement also carries the address the peer believes it has. It is never
used — only cross-checked — so a version skew produces a clear rejection rather
than silent non-connectivity.

[`device`]: https://docs.rs/tsunagi

## MTU

Every packet rides in one transport datagram, and WireGuard adds 32 bytes. A
QUIC datagram on a relayed path can be as small as roughly 1160 bytes, so the
default interface MTU is **1100**, which leaves headroom rather than relying on
the best case. Packets that do not fit are dropped and counted
(`dropped_oversize`), never truncated. The observed datagram limit of each link
is reported in the status output.

## Lifecycle

* A network is activated → the plugin loads or creates its key for that
  network, derives the interface name, and creates the packet interface. If
  that fails — no privileges, for instance — the key and the announcement still
  work and the interface is retried on the next reconcile.
* A peer announces its key → recorded.
* A data link to that peer arrives → recorded.
* Reconciliation starts a tunnel for every peer that has **both**, and removes
  tunnels for peers that lost either.
* A network is deactivated, or the agent shuts down → the interface and every
  tunnel go away. The key stays, so coming back keeps the same overlay address.

There is no external configuration file and no command line tool, so unlike a
kernel-WireGuard setup there is nothing outside this process for anybody to
edit. Reconciliation is purely "do the running tunnels match what is known".

## Using it

```bash
# On both machines
tsunagi up --network lab --secret "$SECRET" --wireguard
```

See the two-machine walkthrough in [../README.md](../README.md#trying-it-on-two-machines).

From the library:

```rust,no_run
use std::sync::Arc;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{MemoryTunFactory, WireguardConfig, WireguardPlugin};
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::{Agent, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let paths = StoragePaths::user_default()?;

    // MemoryTunFactory needs no privileges; swap in SystemTunFactory for a
    // real interface.
    let plugin = WireguardPlugin::open(
        WireguardConfig::new(paths.state_dir.join("wireguard")),
        Arc::new(MemoryTunFactory::new()),
    )
    .await
    .expect("wireguard plugin");

    let agent = Agent::spawn(
        AgentConfig::new(paths)
            .with_transport(TransportPolicy::N0Defaults)
            .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
    )
    .await?;

    let network = agent
        .join_network(&NetworkName::new("lab")?, &NetworkSecret::generate())
        .await?;

    if let Some(view) = plugin.overview(network) {
        println!("{} on {}", view.interface, view.overlay_address);
    }
    agent.shutdown().await;
    Ok(())
}
```

## Limits and future work

* **Full mesh only.** Every member runs a tunnel to every other member.
  Routing through an intermediate participant is not implemented.
* **IPv6 overlay only.** Addressing is IPv6 ULA because it can be derived
  collision-free. An IPv4 overlay would need an allocator, which needs the
  agreed state described in [sync-model.md](sync-model.md).
* **No routes, DNS or firewall rules.** The plugin creates its interface and
  nothing else. Anything beyond the overlay `/64` is the operator's business.
* **Membership is session-scoped.** A peer leaves the overlay when its control
  session ends; surviving a long absence is the same future work.
* **Userspace costs CPU.** Kernel WireGuard is faster. A kernel backend could
  return behind the same boundary, but it would give up transport-provided NAT
  traversal unless paired with a local proxy.
* **The system interface path is barely exercised by the default suite**,
  because it needs privileges. Everything else about the data plane is.

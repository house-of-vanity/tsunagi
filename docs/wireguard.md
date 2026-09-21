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
| `MockProvisioner` | no | the above, plus what would have been done to the host |
| `ManagedTunFactory` | `CAP_NET_ADMIN` | traffic actually reaches the OS |

`ManagedTunFactory` creates the interface and configures it; see
*Provisioning the interface* below and *Privileges* in
[../README.md](../README.md#privileges). With no capability the agent runs
with `--no-tun`: everything but the last hop into the kernel still works.

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

## Checking it from outside

`tsunagi status` asks a running agent over its local control socket and prints
what it sees, including whether each tunnel has actually handshaken. See
[../README.md](../README.md#checking-that-it-works).

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

## IPv4: allocated, signed, and kept

IPv6 addresses are *derived*: a 64 bit interface identifier makes a collision
impossible in practice, so nobody has to agree on anything. IPv4 has nothing
like that room, so deriving would collide. Instead an address is **allocated
and then recorded as a signed fact**, using the model in
[sync-model.md](sync-model.md).

```text
default range          10.13.37.0/24   (override with --ipv4-range)
who decides            the first member to claim; later ones adopt what they find
who signs              the claiming member, with its persistent device key
where it is kept       state.sqlite, and every replica that has seen it
what a return costs    nothing: the old address is reclaimed
```

How it works:

1. On joining, an agent reads back the records it already had and learns more
   from its peers.
2. If it already holds an address, it keeps it. **That is the whole point**: a
   participant that was away for a month comes back to the address it signed
   for, because the claim outlived the session.
3. Otherwise it picks a free one — starting from a position derived from its
   own identity, so two newcomers rarely start in the same place — signs the
   claim, commits it together with its version counter, and only then
   announces it.
4. Every replica merges what it receives into what it has. An author missing
   from a snapshot is left alone: absence is not deletion.

**No vote is involved, deliberately.** Anyone who knows the network secret can
mint identities, so a majority proves nothing, and a quorum would stall with
one participant online and diverge across a partition. Two members who claim
the same address at the same moment are resolved by a rule both compute
identically — the lower endpoint id keeps it — and the loser simply allocates
again with a higher version.

**The range is agreed, not configured per member.** `--ipv4-range` says what
this agent would use; a network that has already settled on something else
wins, and the agent adopts it. So the flag matters for whoever starts the
network and is harmless afterwards. Pass `--ipv4-range none` for an IPv6-only
overlay.

The agent puts the address on the interface itself, as soon as the network has
agreed on it — no restart, and the interface is not recreated, which would
drop every tunnel riding on it.

It then checks that it is really there, by binding a UDP socket to it, which
needs no privileges. That check is deliberately independent of the code that
did the assigning: the failure it guards against is a silent one. With the
wrong address on the interface, packets leave with the wrong source and every
peer drops them as not belonging to us, which looks like a broken network
rather than a broken assumption.

A release tombstone exists in the record type and merges correctly, but
nothing emits one yet, so an address stays claimed until the network is
forgotten.

## Address ownership is enforced, not announced

Kernel WireGuard enforces `AllowedIPs`. In userspace that is our job, and
[`device`] does it on both sides:

* **outbound**, a packet is routed to the peer that *owns* its destination
  address; a destination nobody owns is counted as unroutable and dropped;
* **inbound**, a decrypted packet is dropped unless its *source* is exactly the
  address derived for the peer whose tunnel decrypted it.

Both apply to IPv4 and IPv6 alike.

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

Two constraints pull against each other.

**IPv6 sets a floor of 1280 bytes** (RFC 8200), and Linux enforces it
brutally: an interface whose MTU drops below 1280 loses IPv6 entirely — its
`/proc/sys/net/ipv6/conf/<dev>` directory disappears and `ip -6 address add`
answers `Invalid argument`. So the overlay MTU cannot go below 1280, and the
plugin refuses a smaller one at startup instead of letting it fail obscurely.

**The transport sets a ceiling.** Every packet rides in one datagram and
WireGuard adds 32 bytes, so a link must carry `mtu + 32` = 1312 bytes. A direct
QUIC path typically offers around 1380, which fits. A relayed path can offer
less, and then full-size packets do not fit: they are dropped and counted as
`dropped_oversize`, never truncated, and the plugin reports the exact numbers
when the tunnel is set up.

There is no room left to trade, so the default MTU is exactly 1280.
Fragmenting a packet across several datagrams would lift the ceiling and is
not implemented.

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

    // MemoryTunFactory needs no privileges; swap in ManagedTunFactory for a
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
* **Nothing frees an address yet.** The release record exists and merges, but
  no command emits one.
* **A snapshot grows with the number of members ever seen**, and is capped per
  message rather than compacted.
* **No routes, DNS or firewall rules.** The plugin creates its interface and
  nothing else. Anything beyond the overlay `/64` is the operator's business.
* **Membership is session-scoped.** A peer leaves the overlay when its control
  session ends; surviving a long absence is the same future work.
* **Userspace costs CPU.** Kernel WireGuard is faster. A kernel backend could
  return behind the same boundary, but it would give up transport-provided NAT
  traversal unless paired with a local proxy.
* **The interface is managed, not prepared.** On Linux the agent creates the
  TUN interface and configures it over netlink, in process. See
  *Provisioning* below.
* **No provisioner exists for macOS or Windows yet.** There the agent attaches
  to an interface prepared by hand and says so.
* **The system interface path is not exercised by the default suite**, because
  it needs privileges. Everything else about the data plane is.


## Provisioning the interface

Everything the printed `ip` recipe used to do happens in process now, over
netlink. The shape of it is a reconciliation rather than a sequence of
commands: the agent is handed a plan — name, MTU, the addresses the interface
should carry and no others — observes what is actually on the host, and
applies the difference. Running it twice changes nothing the second time.

The decision of *what* to change is
`dataplane::wireguard::provision::plan_changes`: pure, platform-independent
and unit-tested on every platform. Only the execution is behind
`InterfaceProvisioner`, which has three implementations — netlink on Linux, a
`MockProvisioner` over a pretend host for the tests, and one that refuses with
an explanation everywhere else.

### Cleanup is the default, not an action

The interface is created by opening `/dev/net/tun` and is **not** made
persistent, so the kernel destroys it when the last descriptor closes. A clean
shutdown, a panic, `SIGKILL` and a power cut all leave the same amount behind:
nothing. There is no path by which a dead agent leaves an interface, because
keeping one alive is what requires a live process.

This also removes the two settings the manual recipe needed. `keep_addr_on_down`
existed only because an interface nobody held open lost carrier and had its
IPv6 addresses flushed; `nodad` only because duplicate address detection
cannot finish without carrier. An interface held open for its whole life has
carrier for its whole life.

### Repairing what an older run left

Two things can still be sitting on the name: an interface created persistent
by the old recipe, and — narrowly — one from a run killed between `TUNSETIFF`
and the agent recording it. Both are replaced, which discards their stale
addresses with them.

The two refusals are the interesting part:

* **A link that is not a TUN is never touched.** The name is derived from the
  network id, so colliding with a real device is unlikely rather than
  impossible, and deleting somebody's bridge is not a recoverable mistake.
* **A TUN another process holds open is never deleted.** Carrier is the
  signal: a TUN has it exactly while something is attached. An attached one is
  a working overlay, almost certainly a second agent on this host, and it is
  told to use a different `--wg-prefix` instead.

### Privilege

`CAP_NET_ADMIN` is required and is kept out of the *effective* set except
around the netlink calls that need it. `setcap cap_net_admin+p` leaves it
permitted but not effective at exec, which is the resting state; the agent
raises it for a few milliseconds at startup and again when its address
allocation changes.

Two facts shape how that is done. Capabilities on Linux are **per thread**,
and netlink checks the credentials of whichever thread calls `sendmsg` —
which, with an async client, is the connection task and not the caller. So
raising a capability around an `await` would be wrong in the way that works
until the scheduler moves the task.

Therefore: all netlink work runs on one dedicated thread with a current-thread
runtime, where nothing is polled outside a `block_on`, and the capability is
raised immediately before that call and lowered immediately after. Opening the
TUN descriptor is the other privileged act; it is a synchronous call with no
`await` between the guard and the release, so it stays on its own thread by
construction.

### What it cannot be told to do

Nothing here takes a name, an address or a command from the network. The
interface name is derived from the network id, the addresses come from the
local plugin and the signed allocation records, and no external program is
executed at any point — there is no `ip`, no shell and no `PATH` involved.

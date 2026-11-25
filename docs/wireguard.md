# The WireGuard data plane

WireGuard is the single internal IP cipher. It carries user traffic between
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
*Provisioning the interface* below and Privileges in
[../dist/linux/README.md](../dist/linux/README.md). With no capability the agent runs
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

Reachability belongs to external carriers: ordinary WireGuard UDP (`wg`),
Amnezia-masked UDP (`awg`), iroh QUIC (`wg-quic`), or TCP/TLS (`tcp-tls`). The
user's ordered choice applies only to those physical data links. The internal
capability `wireguard-e2e` v4 is fixed and hidden from the CLI/tray controls.
All carriers move the same inner encrypted bytes, including through relays.
The encryption plugin's announcement identifies a key, never an IP endpoint.

A relay removes its adjacent carrier's encryption to read routing metadata,
then sends the inner ciphertext on another carrier. It cannot decrypt the
endpoint IP packet. WireGuard session keys, counters and the interface survive
carrier changes and direct/relay changes. TCP inside the overlay retransmits
after transient loss; ordinary application and WireGuard timeouts still apply.
The UDP modes have their own bounded STUN/pair discovery and can fail on NATs
that iroh can traverse; selecting only AWG does not permit QUIC fallback.

## Checking it from outside

`tsng status` asks a running agent over its local control socket and prints
the external transport or relay route, data readiness and plaintext counters.
An unavailable channel includes a reason such as no common permitted transport. See
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
default range          stable pseudorandom /24 in 10/8, derived from NetworkId
who decides            all members derive the default; signed explicit ranges win
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

**The range is agreed, not configured per member.** New networks use the
same deterministic `/24` on every device, independently of which network a
member activates first or whether any peers are reachable. The derivation
is unchanged from the former fallback; network identity and signed record
encoding are unchanged. Distinct network ids can still derive the same range.

`--ipv4-range` proposes an explicit range; existing signed ranges take
precedence over the new derived default, including the former `10.13.37.0/24`.
Among disagreeing non-default ranges the lowest author id still wins. Updated
members propagate their adopted range in their signed claims; older releases
still apply their original selection rule until those claims converge.
`--ipv4-range none` disables local proposals, as before.

An agent reserves each active network's range before starting its runtime.
Overlapping ranges, including nested blocks such as a `/24` inside a `/16`,
cannot run simultaneously. A late authenticated state update that introduces
an overlap suspends that network before publishing new allocations to plugins
or the interface. Other networks continue running.

Status includes every blocking network's name, id and range. `tsng network
start <name-or-id>` and the tray's switch button stop all blockers before
starting the selected network. Suspended networks keep their startup request
and resume when the blocker stops or is forgotten. A manual stop cancels that
request even for a network already suspended. The user's preference order is
stored locally, so the same selection wins at the next startup; it is never
advertised or treated as a remote network setting. Local IPC uses wire version
19 for the new reports: restart the agent and tray together after upgrading.
The peer control protocol and signed record encoding do not change.

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

The default interface MTU is 1280. The IPv4 overlay permits explicit values
down to 576, but a small physical path does not require lowering the interface
MTU. WireGuard adds 32 bytes; peer relaying also has an envelope. Previously,
a path advertising only 1129 bytes dropped large packets despite the tunnel
being established: ping worked while TCP connections stalled.

The iroh transport now fragments the opaque, encrypted payload according to
the current QUIC datagram limit. It reassembles before handing the ciphertext
to WireGuard or forwarding it through an intermediate peer. This happens below
IP: the inner TCP segment, checksums and DF flag are unchanged. No MSS rewriting
or special SSH settings are needed. This follows the application responsibility
described in [RFC 9221 section 5](https://www.rfc-editor.org/rfc/rfc9221.html#section-5):
QUIC DATAGRAM frames themselves cannot fragment.

Reassembly is bounded and expires incomplete packets; one lost fragment loses
one packet, without blocking unrelated traffic. The logical data payload limit
is 64 KiB, with the relay envelope subtracted before it reaches the plugin.
The new framing uses data ALPN `tsunagi/data/6`; both ends and intermediate
peers need the updated binary. Network identities and saved state do not change.
See [protocol.md](protocol.md#the-data-plane-protocol) for the wire format.

## Lifecycle and counters

The agent owns one interface across every network. On network activation the
internal plugin loads a network-specific key, announces it and reconciles
peer tunnels. It owns no interface or host route. Local IP ingress resolves
the destination owner and sends only through this one plugin. Source admission
is enforced after decryption by the agent, not by trusting a remote address.

A carrier policy change retires physical links while retaining the logical
peer link and the internal tunnel. A peer's control membership ending removes
its tunnel; network deactivation removes that network's channels. Its persistent
key remains. The interface lives until agent shutdown, independently of carrier
availability and individual network lifetimes.

The historical `wg-quic/wireguard.sqlite` remains the canonical key store.
Missing keys migrate from `wg` then `awg` without replacing canonical keys or
modifying the source files. Corrupt legacy databases are hard errors. Old
`-o keepalive=…`, `-o wg:keepalive=…` and `mtu` settings configure the shared
internal channel; contradictory values are rejected. Interface MTU is selected
once with `--mtu`, independent of carrier selection.

The client renews the selected exit peer's session key at 120 seconds, even
when no IP traffic is flowing. The current key can carry packets during the
exchange. Changing the exit moves this behavior to the new network and peer.

The device list shows **Idle** after an established tunnel has had 30 seconds
without IP traffic. Handshakes and keepalives do not restart this interval.
Pending IP packets, a missing path, or a selected exit waiting for a usable
key still show **Waiting**. A reported transport failure shows **Error**.

User traffic counters count original IP bytes once when the encrypted frame is
accepted by the logical transport, and once when decrypted on receipt. They do
not promise remote delivery. They exclude carrier overhead, handshakes,
keepalives, relay transit and carrier delivery probes. Packets queued before a
handshake retain their exact original lengths. Each new tunnel gets an opaque
counter epoch so tray deltas cannot cross a restart, including when its new
counter already exceeds the old one. A carrier switch does not change that
epoch. Network rates sum per-peer deltas; peers arriving with prior traffic
never add that history to the current rate.

## Using it

```bash
# On both machines: the agent, then the network
tsng up
tsng join --network lab --secret "$SECRET"
```

See the two-machine walkthrough in [../README.md](../README.md#trying-it-on-two-machines).

From the library, configure one `WireguardPlugin` with
`AgentConfig::with_tunnel`, the agent's `with_interface`, and independent
`with_carrier` adapters. UDP/TLS carriers also register their physical
`PacketTransport` using `with_custom_transport`. Their own accept tasks pass
real links to `Agent::install_inbound_link`. The `carriers.rs` integration test
is a rootless example for ordinary WG and TLS; `tsunagi-awg/tests/pairs.rs`
covers mixed transports and relay transitions.

## Limits

The default suite exercises real cryptography, sockets, handshakes, storage and
IP routing using memory TUNs. It does not establish public NAT traversal, DPI
effectiveness, actual host TUN performance, or native GUI behavior on every OS.
Userspace encryption costs CPU. Reassembly and packet queues are bounded and
may drop packets; host TCP handles retransmission within its own timeouts.

## Provisioning the interface

Everything the printed `ip` recipe used to do happens in process now, over
netlink. The shape of it is a reconciliation rather than a sequence of
commands: the agent is handed a plan — name, MTU, the addresses the interface
should carry and no others — observes what is actually on the host, and
applies the difference. Running it twice changes nothing the second time.

The decision of *what* to change is
`overlay::provision::plan_changes`: pure, platform-independent
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

* **A link that is not a TUN is never touched.** The interface name is supplied locally, so colliding with a real device is
  possible, and deleting somebody's bridge is not a recoverable mistake.
* **A TUN another process holds open is never deleted.** Carrier is the
  signal: a TUN has it exactly while something is attached. An attached one is
  a working overlay, almost certainly a second agent on this host, and it is
  told to use a different `--interface` instead.

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
interface name comes from local configuration, the addresses come from the
signed allocation records, and no external program is
executed at any point — there is no `ip`, no shell and no `PATH` involved.

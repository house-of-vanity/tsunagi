# Userspace mesh routing

```text
local OS → TUN → IP plugin (encrypt) → router → transport peer link
transport peer link → router → transport peer link       (transit)
transport peer link → router → IP plugin (decrypt) → TUN → local OS
```

The TUN is the boundary of the local host. The kernel sees one overlay route;
it never forwards transit traffic. WireGuard encryption remains end to end.
The core router sees only an opaque payload and routing metadata. iroh is the
current transport adapter, with fragmentation below the routing envelope so
the default 1280-byte interface MTU also works on small QUIC paths.

## Graph and lifecycle

Each authenticated control session advertises that peer's own direct data
links. There is one table for each network, whatever protocols run over it: a
link is a way to reach a neighbour, and a protocol is an end-to-end tunnel to a
peer. The envelope names the protocol, so the two are independent. A neighbour
reached over several kinds of transport (UDP, TCP, QUIC datagrams) is sent to
over the best open one, in the order the protocols were configured, and over
the next if that one fails or cannot carry the frame. Every authenticated
member enters the graph; a member in the middle needs no protocol in common
with either end, only a link to each. A snapshot refreshes on the maintenance
interval, expires after 90 seconds, and is withdrawn when the session ends.
Link arrival, closure and changed announcements rebuild routes immediately.
Unchanged announcements refresh their age without republishing the forwarding
snapshot.

Which protocol a pair of members runs their tunnel in is settled without
asking: the member with the lower endpoint id decides, by the order it
announces its protocols in, among those both have enabled at the same wire
version. Both ends read the same answer from what they already hold. The
tunnel is created as soon as the peer is reachable by any path, and it does not
change when a direct link comes or goes underneath it: as soon as a direct
link comes up it is shorter than the path through others, and traffic moves to
it with nothing to redo. The user sees only a lower round-trip time.

Breadth-first search computes the shortest directed paths and every equal-cost
first hop in sorted order. An actual direct link always wins. The first row is
always supplied by local transport state, never by a remote claim. Routes stop
at 16 links. A packet also carries a decreasing hop limit, bounding temporary
loops if different nodes have not yet received the same topology update.

The existing control plane still forms authenticated pairwise sessions.
Routing provides multihop **data** paths among these members; it does not add
control-plane flooding or carry control sessions through the data plane, so a
member that has no control session with another has no data path to it either.
Announcements are volatile, not durable membership or availability guarantees.

## What "online" means

One definition, computed by the agent and reported identically by `tsng status`
and the tray: a member is online when this agent can reach it by any path — a
live authenticated control session (QUIC keep-alive every 5 seconds, so a
vanished peer is noticed within about 15), or a data path to it through other
members. It is never inferred from ping, which a firewall may block, or from a
tunnel's last handshake, which says only when traffic last flowed.

How it is reached is reported separately: `direct` over a named transport,
`relayed` through a named member over N hops, or no data path yet while one is
being set up. Being relayed is not being degraded in any way but distance, and
is shown so it is not a surprise.

## Packet path

The control loop binds next hops to transport handles in an immutable table
and publishes it through `ArcSwap`. Readers do not acquire the topology mutex.
The transit routine validates the fixed 82-byte envelope, looks up the source
and destination, selects a cached next hop, decrements one byte, and calls the
transport's synchronous datagram send. It never searches the graph, formats an
endpoint string, validates an Ed25519 key, decrypts, or touches TUN.

An exclusively owned receive buffer is reused when decrementing the hop limit.
Shared buffers require a copy through the safe `bytes` API. There is no added
transit queue or timer; every raw transport has its own reader. Readers yield
after 64 ready packets to avoid starving other runtime tasks. Local delivery
uses a bounded 256-datagram inbox and drops a new packet when full. Transport
queues and fragment reassembly retain their own limits.

`PacketLink::send_flow` accepts an opaque 64-bit flow identifier. IP plugins
derive it before encryption from source/destination addresses, protocol and
TCP/UDP ports. WireGuard keeps tags alongside its bounded pending queue, so
the first application packets retain their flow identity after a handshake.
Transit preserves the tag; it never hashes changing ciphertext. Handshake and
keepalive frames use flow zero. Fragmented IP traffic uses a coarse address/
protocol hash because later fragments lack ports; fragmented flows between
the same addresses coalesce. A transition between fragmented and unfragmented
traffic can change its path. The default overlay MTU avoids needing IP
fragmentation for ordinary host TCP traffic.

ECMP is deterministic for a source and flow while the table is unchanged.
Closed next hops are skipped until the control loop replaces the table. A
topology change can move a flow; datagrams remain unreliable and unordered,
and there is no promise to preserve order across a physical path failure.
Logical peer links and end-to-end encryption state survive these changes.

## Verification and measurement

The default offline suite exercises four real agents, iroh transports and
WireGuard tunnels with memory TUNs, plus graph/forwarder unit tests. It needs
neither administrative rights nor public relays/DHT.

Run the forwarding microbenchmark explicitly:

```sh
cargo test --release -p tsunagi-core --lib forwarding_benchmark -- --ignored --nocapture
```

It processes one million 64-byte frames and one million 1280-byte frames with
two equal next hops. Frame construction is outside the timed section; the
actual ingress routine, header validation, snapshot lookup, ECMP, TTL update,
buffer release and mock transport submission are inside. The mock transport
counts sends without storing frames. Results are CPU forwarding cost, **not**
end-to-end network latency or VPN throughput; encryption, fragmentation,
sockets, congestion and scheduling contribute separately.

Wire compatibility: control ALPN `tsunagi/ctrl/5`, data ALPN `tsunagi/data/5`.
Upgrade every participant together; saved identities and network state persist.

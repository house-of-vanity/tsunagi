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
link is a way to reach a neighbour, while the single internal protocol is an
end-to-end tunnel to a peer. The envelope names the protocol, so the two are independent. A neighbour
reached over several kinds of transport (UDP, TCP, QUIC datagrams) receives
traffic over the selected link. Another open link can carry the frame if
the selected link fails or its MTU is too small. The configured order
selects the initial link. Peers with automatic carrier selection can then
prefer a faster measured link for that neighbour. Every authenticated
member enters the graph; a member in the middle needs no protocol in common
with either end, only a link to each. A snapshot refreshes on the maintenance
interval, expires after 90 seconds, and is withdrawn when the session ends.
Link arrival, closure and changed announcements rebuild routes immediately.
Unchanged announcements refresh their age without republishing the forwarding
snapshot.

Every pair uses one internal WireGuard channel, matched by its fixed opaque
capability and independent of the selected external protocols. The tunnel is
created when a member and its key are known; its logical link survives temporary
loss of all physical paths. Carrier selection changes, automatic fallback and
shorter routes keep the same keys, interface and counters. The lower endpoint
id chooses among the mutually enabled external carriers.
A relayed AWG first hop can lead to a QUIC next hop: the user's choice governs
this device's adjacent links, while the inner ciphertext stays unchanged.
An existing TCP connection continues after transient loss if its own timeout
has not expired; a sufficiently long outage can still terminate it.

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

## Carrier health and switching

Two peers advertising `link-choice` v1 automatically compare carriers. The
lower endpoint id opens one alternative while the established carrier keeps
serving traffic. At most two comparisons start concurrently per network. Each
peer pair rotates through its alternatives, with a two-minute interval after
a trial. A failed active link still triggers immediate fallback.

The measurements use authenticated round trips over the data carrier. After
at least six seconds and five successful probes on each link, the alternative
must have zero observed loss in its window and a median RTT improvement of
at least 20% and 5 ms. If early probes are lost while the responder installs
its probe profile, the dialler keeps sampling for up to 30 seconds so those
losses can leave the 20-probe window. The incumbent stays selected if the
alternative fails to qualify. The agents coordinate retirement over their
authenticated control session. An older peer
continues using the configured order and failure recovery. One enabled carrier
restricts the pair to that carrier.

Carrier setup failures and persistent encrypted delivery loss advance the
initiator's ordered fallback cycle. Logical end-to-end links survive while
physical links are retired explicitly. The AWG carrier negotiates a fresh
private pair profile on every reentry, without changing topology's durable
state. See [amnezia.md](amnezia.md) for thresholds and bounds.

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

Wire compatibility: control ALPN `tsunagi/ctrl/8`, data ALPN `tsunagi/data/6`.
Version 1.0.2 interoperates with 1.0.1 peers using these wire versions.
Saved identities and network state persist.

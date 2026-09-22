# Architecture

Scope and non-scope are in [../README.md](../README.md). Rules for changing the
code are in [../AGENTS.md](../AGENTS.md). The wire format is in
[protocol.md](protocol.md).

## Two independent planes

**Control plane.** iroh provides connections between agents and carries control
messages. On top of it, this crate's protocol handles membership
authentication, participant announcements, capability exchange and — later —
state synchronisation and delivery of IP-plugin data.

**Data plane.** Separate plugins create IP connectivity. WireGuard is the first
one and is implemented in userspace — see [wireguard.md](wireguard.md). Plugin
keys, configuration and lifecycle are separate from iroh identity and from the
network secret. The core moves an opaque, bounded payload and never parses it.

**The transport in between.** Plugins do not open connections. They are handed
a `PacketLink` — an authenticated, unreliable datagram channel to one peer for
one protocol — and never learn how it is carried.

The separation between the two planes is **logical, not physical**. Both ride
on iroh, on different ALPNs and different connections. That is deliberate:
iroh's whole value is hole punching a direct path between peers behind NAT,
with a relay as fallback, and a data plane that refused to use it would have to
reimplement all of it. What the separation buys is that `proto` knows nothing
about packets and `dataplane` knows nothing about the control protocol, so
either can be replaced on its own.

A plugin talks to the core through three narrow hooks — `on_network_activated`,
a `PluginContext` for re-announcements and error reports, and a bounded
`shutdown` — so the core never learns anything protocol-specific.

A data plane failure never stops the daemon: the control plane keeps running
and the agent stays manageable.

## Userspace routing

The routing engine builds shortest paths over opaque peer identifiers, with no
WireGuard or iroh dependency. The relay adapter binds those next hops to
`PacketLink` handles and publishes an immutable table per network and protocol.
One reader per raw transport forwards transit without entering the plugin or
TUN. End-to-end plugin links survive physical link changes. The existing
authenticated control mesh supplies first-hand topology; the data router does
not tunnel control sessions. See [routing.md](routing.md).

## Module responsibilities

| component | responsibility |
|---|---|
| `identity` | persistent device identity; network space parameters; derived identifiers and keys |
| `discovery` | obtaining and publishing address hints — not authentication, not state transfer |
| `net` | iroh connections, addresses, paths, statistics, connection events |
| `proto` | message format, handshake, membership proof, protocol limits |
| `agent` | agent and per-network lifecycle, reconnect, in-process message routing |
| `storage` | mandatory state and the separately recoverable cache |
| `state` | signed records that outlive a session, merged between replicas |
| `dataplane::transport` | authenticated datagram links to peers; where reachability lives |
| `dataplane::routing` | transport-independent graph, shortest paths and opaque flow identifiers |
| `dataplane::relay` | immutable forwarding snapshots and transport-to-transport transit |
| `dataplane` | the contract an IP protocol implements |
| `overlay` | the one interface an agent owns: provisioning, the TUN, whose packet is whose |
| `dns` | the DNS view of a network, and telling the system resolver about it |

And in crates of their own:

| crate | responsibility |
|---|---|
| `tsunagi-wg-quic` | the `wg-quic` protocol: its keys, its announcement, its tunnels |
| `tsunagi-cli` | the command line agent: the only place that owns a runtime, a logger and signals |

A protocol is a separate crate so the boundary is the compiler's to enforce,
and so it can carry its own version. That version is not what peers compare:
they compare the *wire* version, which moves only when the bytes do, so two
peers on different releases keep working.

Abstractions exist only where something is really substituted or really needs
isolating for tests: `NetworkDiscovery`, `IpPlugin`, `PacketTransport` /
`PacketLink` (so a protocol's carrier can change), `TunFactory` (which is what
lets the whole data plane be tested without privileges), `InterfaceProvisioner`
and `DnsPublisher` (which are where the platforms differ). Everything else is a
concrete type.

## Runtime shape

```text
Agent                                   one persistent identity, one iroh endpoint,
 ├── EndpointAdapter (two ALPNs)         one state directory, N networks
 ├── Storage  (state.sqlite + cache.sqlite + ownership lock)
 ├── IrohTransport   ── data plane links, weak ref back to the agent
 ├── accept loop task ── routes by ALPN; weak ref, exits when the agent drops
 ├── plugin request loop ── re-announcements and plugin error reports
 └── NetworkRuntime per NetworkId
      ├── discovery + dial loop (bounded concurrency, backoff with jitter)
      ├── Session per peer (control)
      │    ├── reader task  ── frames in  -> SessionEvent
      │    └── writer task  ── encoded frames out
      └── PacketLink per (peer, plugin protocol), handed to the plugin
```

Every strong reference from a background task back to the agent is a `Weak`.
A cycle there would keep the databases open and the directory lock held
forever after shutdown.

The library starts no runtime, installs no logging subscriber, handles no
signals, never forks and never calls `process::exit`. Startup
(`Agent::spawn`) and shutdown (`Agent::shutdown`) are explicit, background
tasks are joined on shutdown, and there is no global mutable state — several
independent agents run in one test process.

`Agent::spawn` returns as soon as the local agent is ready. It never waits for
other participants or for a relay.

### Concurrency decisions

- The network runtime is a single task owning its own state, driven by a
  command channel plus event channels. No shared locks on the hot path.
- A session is two tasks, because a partially consumed stream read cannot be
  cancelled safely. The writer's frame write *is* cancellable, so shutdown
  never waits on a peer that stopped reading.
- Outbound queues are bounded. A full queue fails that send instead of stalling
  every other peer in the network.
- Envelopes are encoded in the runtime, not in the writer, so the exact number
  of control bytes queued is known and reported rather than guessed.
- Simultaneous mutual dials are resolved by a deterministic rule both sides
  compute identically: keep the session whose initiator has the smaller
  endpoint id.

### Storage

Two physically separate SQLite files with their own schema versions and
migrations, no ORM. All access runs on the blocking pool; no database lock is
held across a network `await`. Files are owner-only where the platform supports
it. One state directory belongs to one live agent, enforced by an advisory OS
file lock — an existence check is not enough, because a crashed process must not
block a restart and two agents starting at once must not both win. A clean
shutdown releases the lock immediately.

### Observability

`AgentStatus` separates the three levels deliberately:

- **endpoint** — bound sockets, observed addresses, cache health;
- **logical network** — dial attempts and failures, handshake failures,
  sessions established, disconnects, control message and byte counts, protocol
  violations, plugin errors;
- **connection** — verified paths, selected path, direct/relay, RTT, QUIC
  counters.

Values that cannot honestly be attributed to one network stay at the endpoint
level. A value iroh does not report is `None`.

An iroh address is an address for iroh. It is not assumed usable by any other
protocol; a future WireGuard plugin gathers its own reachability data and ships
it through the control plane as an opaque announcement.

### Relays

Standard iroh behaviour, including relay fallback, is allowed for the control
plane via `TransportPolicy::N0Defaults`. Public relays are fine for development
and carry no availability guarantee. The default is `LocalOnly`, and the test
suite never depends on a relay.

## Multiple networks

Every session, message, task and status carries an explicit `NetworkId`. Being
authenticated in network A grants nothing in network B, even over a shared
physical connection; each network gets its own sessions. Deactivating one
network does not close the agent or disturb the others.

Local deactivation is distinct from a future signed revocation of membership or
of a name. Nothing here is an irreversible global flag.

## Planned, not built

Signed per-author state, snapshots, revocations and merge rules are described
in [sync-model.md](sync-model.md). The module boundaries above are shaped so
that adding them does not require rewriting the core. The data plane locking
policy is likewise deliberately left coarse for now; the conflict domain is
described separately so it can later be narrowed to a network, peer, name or
plugin without touching the core.

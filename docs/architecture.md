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
one and is implemented — see [wireguard.md](wireguard.md). Plugin keys,
configuration and lifecycle are separate from iroh identity and from the
network secret. The core moves an opaque, bounded payload and never parses it.

Only control messages travel over iroh. User IP traffic is not tunnelled
through it; WireGuard packets travel over WireGuard's own UDP sockets.

A plugin talks to the core through three narrow hooks — `on_network_activated`,
a `PluginContext` for re-announcements and error reports, and a bounded
`shutdown` — so the core never learns anything protocol-specific.

A data plane failure never stops the daemon: the control plane keeps running
and the agent stays manageable.

## Module responsibilities

| component | responsibility |
|---|---|
| `identity` | persistent device identity; network space parameters; derived identifiers and keys |
| `discovery` | obtaining and publishing address hints — not authentication, not state transfer |
| `net` | iroh connections, addresses, paths, statistics, connection events |
| `proto` | message format, handshake, membership proof, protocol limits |
| `agent` | agent and per-network lifecycle, reconnect, in-process message routing |
| `storage` | mandatory state and the separately recoverable cache |
| `dataplane` | the contract IP plugins implement, plus the WireGuard plugin |

Abstractions exist only where something is really substituted or really needs
isolating for tests: `NetworkDiscovery`, `IpPlugin`, and `WireguardBackend`
(which is what lets the plugin be tested in full without root). Everything else
is a concrete type.

## Runtime shape

```text
Agent                                   one persistent identity, one iroh endpoint,
 ├── EndpointAdapter                     one state directory, N networks
 ├── Storage  (state.sqlite + cache.sqlite + ownership lock)
 ├── accept loop task  ── weak ref, exits when the agent is dropped
 └── NetworkRuntime per NetworkId
      ├── discovery + dial loop (bounded concurrency, backoff with jitter)
      └── Session per peer
           ├── reader task  ── frames in  -> SessionEvent
           └── writer task  ── encoded frames out
```

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

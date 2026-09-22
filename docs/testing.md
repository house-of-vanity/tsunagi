# Testing

How to run everything is in [../README.md](../README.md). Rules for writing
tests are in [../AGENTS.md](../AGENTS.md).

## Ground rules

Tests use real iroh endpoints on loopback, real handshakes, real SQLite in
per-test temporary directories, and independent agent instances. Discovery is
substitutable; **iroh, authentication, message passing and persistent storage
are not**.

The suite runs with no internet, no public DHT, no public relay, no administrator
rights and no changes to OS network settings: endpoints bind `127.0.0.1:0` and
`[::1]:0`, relays are disabled, address lookup is cleared, port mapping is
disabled, and net-report probing is reduced to its minimum.

Synchronisation is always "wait for a specific event or condition under one
overall deadline" (`wait_event`, `wait_until`, 30 s). The deadline covers the
probe as well as the gaps between probes: a call into a wedged agent that
never answers fails the test rather than hanging the process, which is the
difference between a red run and a test binary still burning a core the next
day. `settle()` exists only for asserting that something did *not* happen.
Ports are dynamic and directories are isolated, so tests run in parallel.

Several library instances in one process is exactly that. It is **not** a test
of several system processes, and is not presented as one.

## What is covered

| # | scenario | file |
|---|---|---|
| 1 | deterministic identity: same name + secret ⇒ same space on different devices; a changed name or secret changes it; hostname, device key and restart do not | `tests/identity.rs` |
| 2 | four agents find each other, authenticate for real and exchange distinguishable messages; a late joiner is picked up; opaque plugin capabilities cross the control plane | `tests/multi_peer.rs` |
| 3 | an attacker who knows the address and the correct public `NetworkId` but not the secret is rejected at the handshake | `tests/authentication.rs` |
| 4 | one agent in two networks: statuses and messages do not mix; a session authenticated for one network cannot speak for the other; deactivating one leaves the other running | `tests/network_isolation.rs` |
| 5 | full stop and recreation from the same database: identity and settings survive, sessions come back automatically, a new local UDP port does not break recovery | `tests/restart.rs` |
| 6 | changing the secret through the library API: device identity survives, old sessions and messages get no access to the new space, and the retired space stays retired across a restart | `tests/restart.rs` |
| 7 | missing, corrupt and stale cache do not prevent connecting; a corrupt mandatory store is a clear error and never a fresh identity; a newer schema is refused; secrets stay out of status and `Debug` | `tests/cache_and_state.rs` |
| 8 | a dead candidate and a vanished peer do not block the others; retries are bounded and stop when the network is deactivated | `tests/resilience.rs` |
| 9 | wrong version, a message before authentication, a proof replayed on another connection, an oversized frame and a `Hello` for an inactive network are all rejected without taking the agent down | `tests/authentication.rs` |
| 10 | a second agent on the same state directory gets a clear error; after a clean stop the directory reopens; shutdown ends background tasks and refuses further work; independent agents coexist in one process | `tests/resilience.rs` |
| 11 | leaving a network frees the address for the others, says plainly when there was nobody to tell, and rejoining afterwards is not mistaken for a stale record; a wipe empties both directories and the next start is a stranger, while a directory that is not ours is refused | `tests/leaving.rs`, `tests/cache_and_state.rs` |
| 12 | a network can be joined into a running agent over the control socket and is live at once; a name with no secret resumes the one network of that name, invents one when there is none, and refuses to choose between two; two networks on one agent each get a range of their own | `tests/local_control.rs`, `tests/network_isolation.rs`, CLI unit tests |

`tests/wireguard.rs` drives the WireGuard data plane over real iroh
connections. Everything is real except the packet interface: real agents, real
control plane, real data links, real WireGuard handshakes and encryption from
boringtun, with an in-memory TUN device so none of it needs privileges. It
covers real IPv6 packets travelling both ways through a tunnel, a three-agent
mesh, a peer that sends from an address it does not own being dropped, packets
for unowned addresses being counted rather than broadcast, a departing peer
losing its tunnel, two networks keeping separate interfaces and keys, restart
keeping the WireGuard identity, shutdown removing every interface, a forged
overlay claim being rejected, and the core carrying the payload without
interpreting it.

The WireGuard traffic tests constrain real QUIC to a 1200-byte path MTU with
PMTU discovery disabled, so large loopback MTUs cannot hide Internet failures.
Checksummed IPv4/TCP packets up to the default 1280-byte interface MTU cross in
both directions without changing DF or packet contents, including through an
intermediate peer. Fragment tests cover reordering, duplicates, loss, changing
fragment sizes, malformed input, timeout and memory bounds. These are packet
transport checks, not a claim to have run an SSH server or a host TCP stack.

Routing tests cover shortest paths, direct preference, deterministic per-flow
ECMP, link loss, protocol isolation, malformed/unknown frames, bounded local
queues, zero-copy transit of an owned buffer, and deliberately inconsistent
tables whose loop terminates at the hop limit. A transit reader is exercised
without any plugin reader, so forwarding cannot accidentally depend on one.
WireGuard tests also cover flow tags queued before a handshake, queue overflow,
and their preservation through encryption.

`tests/wireguard.rs` includes a four-agent chain A—B—C—D with only adjacent data
links. Real encrypted 1280-byte TCP packets travel in both directions while the
middle TUNs remain empty. A direct A—D link is enabled, then removed; the route
switches back to the chain without replacing end-to-end tunnels.

Broadcast tests use limited and directed UDP game discovery packets over real
WireGuard tunnels, including a missing direct link. Each willing peer gets one
copy; disabling reception/origination works at runtime and unicast still works.
IP-router tests cover source/destination domain checks, malformed UDP and the
absence of reflection into outgoing fanout. SQLite migration tests preserve v3
identity/settings and check opt-out after reopen/rejoin. CLI tests cover default
on, per-network opt-out, runtime updates and conflicting flags. Actual games and
host adapter selection are not simulated by these tests.

The ignored `forwarding_benchmark` measures the synchronous transit routine in
release mode, excluding crypto and socket I/O. Run it explicitly as described
in [routing.md](routing.md); it has no timing threshold in the default suite.

Unit tests in `crates/tsunagi/src/state/` cover the signed record model directly: tampering
with any field breaks verification, a newer version wins while an older one
never rolls back, two authors claiming one address resolve the same way no
matter the merge order, one key used in two places is reported rather than
silently merged, a release survives a late-arriving old claim, a bad record in
a batch does not stop the rest, and allocation is deterministic, spread out,
walks past everything taken and reports a full range instead of handing out a
duplicate.

`tests/local_control.rs` covers the local control socket end to end: a client
asking a running agent for status over a real Unix socket, joining and
leaving a network through it, a leftover socket file being replaced while a
live one is not, and the derived socket path staying short enough to bind.

`crates/tsunagi-cli/tests/network_cli.rs` runs the real binary too: joining
with no secret invents one, prints it in full and prints a line the other
side can paste unchanged; a bare name this device already knows resumes
that network instead of inventing another of the same name; and a network
can be stopped and started again with its secret and its place intact.

`crates/tsunagi-cli/tests/dns_service.rs` runs the real binary: the resolver
comes up with no interface to attach it to, the listener is not rebuilt on
the way past, a name outside every zone is refused, each network gets a zone
of its own as it is joined, and the resolver can be switched on and off
while the agent runs.

`tests/discovery.rs` also covers introductions: a device given one
member's address meets every other member, and the ones it was not told
about arrive as candidates that still pass the handshake like any other.

`tests/discovery.rs` covers the discovery contract itself: a static bootstrap
candidate is enough to join, several backends compose, entries are withdrawn
when a network stops, and a forgotten network stays forgotten across a restart.

Unit tests in `crates/tsunagi/src/proto/handshake.rs` cover the transcript construction
itself: role separation, channel binding, identity and network binding,
unambiguous encoding, and rejection under the wrong key.

Unit tests in `crates/tsunagi-wg-quic/src/` cover key clamping against the RFC
7748 vector, overlay derivation, announcement validation including the
address-hijack attempt, interface naming, and IP header parsing against
truncated and nonsense input.

`tests/end_to_end.rs` is the vertical slice: persistent identity → network
space → discovery → iroh → authentication → message exchange.

What the default suite does **not** cover is the real TUN interface, because
that needs `CAP_NET_ADMIN`. Everything above it does run.

Mainline discovery tests use an isolated loopback `mainline::Testnet`.
`tests/mainline_socket.rs` checks that idle UDP receive timeouts do not emit
warnings (including Windows error 10060) and that the same node still answers
a real KRPC ping afterwards. The local dependency correction is documented in
[`vendor/mainline/PATCHES.md`](../vendor/mainline/PATCHES.md).
`tests/mainline.rs` restores two agents after their DHT and disposable cache
have disappeared. `tests/discovery_lifecycle.rs` checks that publication
continues while connected, lookup resumes after isolation, and a hung backend
does not block the network actor. Unit tests cover record bounds, timestamps,
colliding publications, wrong secrets and the full recovery delay with a
paused clock. The public Mainline/relay smoke test is ignored by default.

## Not covered, and not claimed to be

Listed in [sync-model.md](sync-model.md#future-tests): snapshots, revocations,
long partitions, hostname renames, recovery of a returning participant, NAT
traversal, relay fallback, and multi-process or multi-host deployment. None of
these are implemented, and none are marked as passing.

## Debugging a test

```bash
TSUNAGI_TEST_LOG=tsunagi=debug cargo test --test multi_peer -- --nocapture
```

The library never installs a global subscriber; the harness opts in only when
that variable is set.

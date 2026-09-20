# Testing

How to run everything is in [../README.md](../README.md). Rules for writing
tests are in [../AGENTS.md](../AGENTS.md).

## Ground rules

Tests use real iroh endpoints on loopback, real handshakes, real SQLite in
per-test temporary directories, and independent agent instances. Discovery is
substitutable; **iroh, authentication, message passing and persistent storage
are not**.

The suite runs with no internet, no DHT, no public relay, no administrator
rights and no changes to OS network settings: endpoints bind `127.0.0.1:0` and
`[::1]:0`, relays are disabled, address lookup is cleared, port mapping is
disabled, and net-report probing is reduced to its minimum.

Synchronisation is always "wait for a specific event or condition under one
overall deadline" (`wait_event`, `wait_until`, 30 s). `settle()` exists only
for asserting that something did *not* happen. Ports are dynamic and
directories are isolated, so tests run in parallel.

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

`tests/discovery.rs` covers the discovery contract itself: a static bootstrap
candidate is enough to join, several backends compose, entries are withdrawn
when a network stops, and a forgotten network stays forgotten across a restart.

Unit tests in `src/proto/handshake.rs` cover the transcript construction
itself: role separation, channel binding, identity and network binding,
unambiguous encoding, and rejection under the wrong key.

`tests/end_to_end.rs` is the vertical slice: persistent identity → network
space → discovery → iroh → authentication → message exchange.

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

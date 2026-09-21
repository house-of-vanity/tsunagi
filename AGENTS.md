# AGENTS.md

Rules for anyone — human or automated — changing this repository. Read this
before touching the code. Do not restate the full design here; follow the links.

## What this project is

A proof-of-concept agent library for small private mesh networks. A user
supplies a network name and one shared secret; agents derive the same network
space independently, find each other, prove membership and exchange control
messages. Scope and non-scope are in [README.md](README.md).

There is no central server, no owner, no registration and no majority vote.
Design accordingly: a majority is not a root of trust.

## Architectural boundaries

Keep these separate. Crossing them is the main thing to review for.

- **Control plane vs data plane.** iroh carries control messages only. User IP
  traffic is never tunnelled through it. The core must never parse a plugin's
  payload — see `src/dataplane/mod.rs`. Only
  `src/dataplane/wireguard/announcement.rs` interprets WireGuard payloads, and
  only after bounding every field. A data plane failure must never stop the
  control plane.
- **Derived, not claimed.** A WireGuard peer's `AllowedIPs` are always derived
  locally from its public key. Never take them from what the peer announces, or
  a member can route another member's traffic to itself.
- **Plugins own their system objects.** A plugin creates and removes its own
  interface and nothing else. An interface that already exists and is not ours
  is refused, never adopted. Never touch routing, DNS or firewall settings.
- **Device identity vs network identity.** The iroh endpoint id is the device's
  public key. `NetworkId` is derived from name + secret only. Never conflate
  them, and never let one change the other.
- **Discovery vs authentication.** Discovery returns *unverified candidates*.
  It never authenticates, never carries control messages and never mutates
  agent state. Membership is decided only by the handshake.
- **Mandatory state vs disposable cache.** `state.sqlite` is never silently
  reset: damage is a hard error. `cache.sqlite` may be deleted at any time and
  is recreated. A stale cache must never bypass identity or network
  authentication.
- **Candidate vs observed address vs verified path.** Report these as three
  different things. A missing value is `None`, never invented.

## Rules that are not negotiable

1. **Tests come first.** Every substantial change ships with tests for the
   normal path *and* the important failures. See [docs/testing.md](docs/testing.md).
   Do not add tests for getters or to move a coverage number.
2. **Never change `IDENTITY_SCHEME`, the derivation labels, or the transcript
   encoding** in `src/identity/network.rs` and `src/proto/handshake.rs` without
   treating it as an incompatible protocol change. Bumping the crate version or
   the control protocol version must not change an existing `NetworkId`.
3. **Secrets never leak.** Not into logs, not into `Debug`, not into status
   output, not into anything exported to the network. `NetworkSecret` and
   derived keys redact themselves and zeroize; keep it that way.
4. **No panics on untrusted input.** No `unwrap`, `expect` or `panic` on
   anything that came off the network. Clippy enforces this at warn level in
   the library; tests opt out explicitly at the top of each file.
5. **Bounds before allocation.** Frame lengths are checked against
   `Limits::max_frame_len` before a buffer is allocated. Every string, list and
   queue has a limit in `src/config.rs`.
6. **Failure is contained.** A bad signature, wrong secret, malformed packet or
   unknown version rejects one message or one session. It never stops another
   network and never stops the agent. There is no irreversible global error
   flag. A data plane failure must never stop the control plane.
7. **The library owns no globals.** No global tokio runtime, no global tracing
   subscriber, no signal handlers, no `fork`, no `process::exit`, no global
   mutable state. Several agents must run in one test process.
8. **SQLite never blocks the executor.** All database work goes through
   `spawn_blocking`. Never hold a transaction or a database lock across a
   network `await`. When signed records land, writing the record and bumping
   the author's own counter must be one transaction, committed **before**
   publishing to the network.
9. **Shutdown is bounded.** A peer that stops reading must not be able to hold
   up shutdown. Wind tasks down with a grace period and then abort.
10. **Nothing from a remote announcement becomes a shell command, a filesystem
    path or an OS setting.** The agent never touches interfaces or OS settings
    it did not create.

## Where things live

| path                | responsibility |
|---------------------|----------------|
| `src/identity/`     | device identity; deterministic network space identity and derived keys |
| `src/storage/`      | `state.sqlite`, `cache.sqlite`, directory ownership lock |
| `src/discovery.rs`  | candidate sources; test and static backends |
| `src/proto/`        | framing, message formats, membership handshake |
| `src/net.rs`        | iroh endpoint adapter and observability snapshots |
| `src/agent/`        | agent lifecycle, per-network runtimes, sessions, events, status |
| `src/dataplane/`    | the contract IP plugins implement, and the WireGuard plugin |
| `tests/`            | integration tests; `tests/common/` is the shared harness |

Add abstractions only at real substitution or testing boundaries. Do not add a
trait per struct. Prefer one crate with clear modules over many small crates.

## Testing rules

- Use real iroh endpoints on loopback, real handshakes, real SQLite in
  temporary directories, and independent agent instances.
- Discovery may be substituted. **iroh, authentication, message passing and
  persistent storage may not be.**
- No arbitrary multi-second `sleep` as the primary synchronisation. Wait for a
  specific event or condition under one overall deadline (`wait_event`,
  `wait_until`). `settle()` exists only for asserting that something did *not*
  happen.
- The default suite must pass with no internet, no DHT, no public relay, no
  administrator rights and no changes to OS network settings. Anything needing
  the internet, or root, stays out of the default set — the real WireGuard
  backend's tests live in `tests/wireguard_system.rs` behind `--ignored`.
- The WireGuard backend may be substituted (`RecordingBackend`). Its key
  handling, announcements, derived addressing, configuration builder and
  reconciliation may not.
- Running several library instances in one process is not a test of several
  system processes; do not describe it as one.

## Before you open a change

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

CI runs these on Linux, macOS and Windows. A CI config existing is not evidence
that tests ran on every OS — say what you actually ran.

Check the real API of the iroh version in `Cargo.lock` before using it. Do not
invent methods from memory.

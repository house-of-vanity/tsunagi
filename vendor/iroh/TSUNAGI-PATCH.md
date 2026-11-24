# Bounded path retries

This is the crates.io iroh 1.2.0 source, with registry bookkeeping and its
independent Cargo.lock omitted. The workspace selects it with `[patch.crates-io]`.

- Published source commit: `17c0612f80f78f5288e97b818b1360ae6ea0a51a`.
- Crates.io archive SHA-256:
  `b2f8d1cfffc83efe39a1031aab423ce09cb8048071baba550508931e9a81ce46`.
- Upstream source, manifests, examples, tests and license are otherwise retained.

`State::open_path_on_conn` appended a failed path once per connection. The actor
takes the queue every 333 ms and retries every entry on every connection to that
remote. Two failing connections therefore double duplicate work each round.
Tsunagi deliberately keeps control and data on separate QUIC connections, so
merging those connections would violate its architecture and conceal the bug.

On 2026-10-14 a Linux rc.33 daemon reached OOM after roughly five hours. Before
the kill, `/proc` showed anonymous mappings of 40 GiB and 10 GiB, later 20 GiB.
Pointers and container capacities were consistent with the retry queue and its
drained batch. The active worker's stack was in iroh's retry loop,
`open_path_on_all_conns` and `open_path_on_conn`, identified through executable
addresses and tracing metadata in the stripped static binary. This matches
[upstream issue 4509](https://github.com/n0-computer/iroh/issues/4509).

The local change extracts the enqueue operation into `pending_paths.rs`, rejects
duplicates, and limits pending candidates to 64, evicting the oldest before
admitting a new distinct path. The current retry batch and next batch are each
bounded; no wire formats, identity derivation, timers or authentication change.
The upstream deduplication fix was merged in
[PR 4551](https://github.com/n0-computer/iroh/pull/4551) on October 6. Both the
published 1.2.0 source used here and the 1.3.0 crates.io archive (released
September 28) still have the unconditional enqueue. Upgrading to 1.3.0 alone
does not fix this OOM. Remove this override when adopting a release that
includes the fix, retaining a retry regression check.

`crates/tsunagi-core/tests/iroh_path_retries.rs` includes the exact admission
module so its tests run in the default workspace suite, even though vendored
dependencies are excluded from workspace membership. The tests reproduce
multi-connection retry multiplication, preserve FIFO order under duplicate
failures, exercise success draining, and bound length and capacity under 10,000
distinct candidates. They fail with the original unconditional enqueue.
These are queue algorithm tests; the normal integration suite continues to use
real iroh endpoints, membership handshakes, SQLite and encryption.

## Excluding overlay candidates

`Builder::addr_filter` filters discovery publication only. That is insufficient
for an overlay: iroh still put the overlay interface address in the local
candidate watch used for path creation, allowing its own transport packets to
re-enter the overlay. Production logs contained verified data paths via
`10.13.37.*` overlay addresses while their underlay links cycled.

The separate optional `Builder::direct_addr_filter` applies an `AddrFilter`
before storing local direct addresses. Default behavior is unchanged. Tsunagi
uses its existing local-interface exclusion for both this filter and publication,
including the actual kernel-assigned interface name after creation. Control authentication and
wire formats are unchanged. The rootless real-endpoint regression is
`crates/tsunagi-core/tests/iroh_candidates.rs`; overlay subnet filtering for
introductions is also covered in the core. This prevents the recursive path;
it does not prove the historical cause of any particular high byte counter.

## Changes to the owned overlay interface

The optional `Builder::network_change_filter` receives consecutive netwatch
snapshots before iroh rechecks paths and rebinds sockets. Tsunagi suppresses
events caused solely by its own TUN. Adding a second network can then add an
address to the shared interface while the first network keeps its UDP sockets.
Physical interface changes, default-route changes and resume events still
reach iroh. The watcher advances its baseline even for a skipped event.
Keep this behaviour when updating the vendored dependency.

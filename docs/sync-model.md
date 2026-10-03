# Planned state synchronisation

**The first slice of this model is now implemented**, in `crates/tsunagi-core/src/state/`, and is
used for one thing: IPv4 overlay addresses. What follows describes the whole
model; the section at the end says exactly which parts exist.

The proof of concept still exchanges hostname and capability announcements
over live sessions and keeps no replicated history for those, which is why
WireGuard peer *membership* remains session-scoped even though a peer's
*address* no longer is. This file records the intended direction so the module
boundaries in [architecture.md](architecture.md) stay compatible with it, and so
nobody mistakes the current announcements for synchronisation.

There is no fake "ready CRDT" here and no snapshots that are not actually
verified.

## The problem

The network may be unstable. A participant can come back after months. So:

- no dependence on the author of a change being online;
- no dependence on acknowledgements from every participant ever seen;
- any available replica holding the signed data must be able to hand it to a
  returning participant without the original author present.

## The model

**Signed self-contained state per author, merged between replicas.**

A record contains: the network, the author, the author's own retained version,
the full current content, and a signature. A change log may speed delivery up,
but recovery must never require the entire chain from the first event.

A network snapshot is a set of verifiable authored records plus the revocations
needed to interpret them. It is **not** a SQLite dump, and **not** a single
document trusted merely because the neighbour who forwarded it signed it.

## Merge rules

- A snapshot is merged into local state, never substituted for it wholesale.
- An older version never rolls back a newer known one.
- Absence from a snapshot does not mean deletion.
- Duplicates do not change the result.
- Two conflicting signed records at the same version from the same author need
  explicit handling; they are not resolved by luck.
- Neither arrival order nor system clocks decide a winner.
- Compaction must not drop what is needed to stop revoked records being
  resurrected.

## Hostnames

A hostname is a mutable binding to a persistent author, not an identity. A
rename must be a signed record that revokes the specific old binding and
announces the new one, ideally atomically in one record.

Turning a computer off is not a revocation of its hostname and does not remove
the participant. Revocations are not dropped merely because they are old, and
no acknowledgement from offline peers is required to keep working.

## Storage requirement this creates

When signed records land, writing the event and bumping the author's own
counter must happen in **one SQLite transaction, committed before the change is
published to the network**. SQLite gives atomic commit; use it instead of
separate, inconsistent writes. `state.sqlite` already has a schema version and
migrations for this.

## Limits to state honestly

- Data that every copy has lost is not recoverable from the secret.
- A signature proves authorship, not global freshness: a replica can be
  behind, and you cannot tell from the signature alone.
- An isolated new client can end up with incomplete state and has no way to
  know what it is missing.
- Anyone who knows the secret can author records, so a majority of records is
  not evidence of anything.

## What exists today

Implemented, in `crates/tsunagi-core/src/state/`:

* signed records, one per author per network, each holding that author's
  complete current statement rather than a delta;
* signing and verification with the persistent iroh device key, over a
  length-prefixed canonical encoding;
* the merge rules above: higher version wins, an older version never rolls
  back a newer one, duplicates are idempotent, a same-version conflict is
  resolved identically on every replica and reported;
* a release tombstone, which merges correctly and is not undone by a replica
  that has not heard of it — though nothing emits one yet, so freeing an
  address still means forgetting the network;
* persistence in `state.sqlite`, with the record and the author's own version
  counter committed in **one transaction before the record is announced**;
* distribution as a `State` control message, merged into what the receiver
  already holds rather than replacing it;
* allocation of a free IPv4 address against what everybody else holds, which
  is what makes an address stable across an absence.

Deliberately not implemented: compaction, revoking a whole author, record
types beyond addressing, and any bound on how large a snapshot may grow
beyond the per-message limit.

## Future tests

These are **not implemented and must not be reported as passing**:

- snapshot merge against the rules above, including conflicting same-version
  records;
- revocation propagation and resistance to resurrection after compaction;
- long network partitions and rejoin after an extended absence;
- hostname rename with atomic revoke-and-announce;
- recovery of a returning participant from a replica that is not the author;
- NAT traversal and hole punching between real hosts;
- relay fallback behaviour against a self-hosted relay;
- multi-process and multi-host deployment, as opposed to several library
  instances inside one test process.

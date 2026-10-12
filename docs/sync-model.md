# State synchronisation

Signed claims in `crates/tsunagi-core/src/state/` preserve IPv4 reservations and
hostnames across an absence. Signed releases and offline-node cleanup markers
free those reservations durably. Capabilities, links and authenticated sessions
remain volatile; a stored claim never authenticates a live connection.

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
- Neither arrival order nor the receiving replica's clock decides a winner. The
  one thing an author's own clock is used for is the time it first claimed a
  hostname, signed into its record (see below).
- Compaction must not drop what is needed to stop revoked records being
  resurrected.

## Hostnames

A hostname is a mutable binding to a persistent author, not an identity. A
rename must be a signed record that revokes the specific old binding and
announces the new one, ideally atomically in one record.

A hostname belongs to the member that claimed it **first**. Each claim carries
`hostname_since`, the author's own time in milliseconds when it first claimed
that exact name, signed with the rest of the record and kept across every later
version that keeps the name; renaming starts it afresh. Replicas order claims
by `(hostname_since, author id)`, a pure function of the records, so every
replica names the same holder whatever order the records arrived in and there
is no race to lose. A member that arrives later with a name already held keeps
working by address and keeps its claim, but is not found by that name on any
member; it is told so in its status and in `tsng status`, and finds the name
again if the holder renames or releases it.

It is the author's word, so a member with a clock set far back can claim an
older time. That can reorder who holds a *name* and nothing else — addresses,
keys and everything the data plane trusts are decided without it — and anybody
who knows the secret could take a name by other means anyway.

Turning a computer off is not a revocation of its hostname and does not remove
the participant. Revocations are not dropped merely because they are old, and
no acknowledgement from offline peers is required to keep working.

## Offline-node cleanup

Any authenticated member can sign a `SignedRetirement` for another member's
observed `Claim`. It includes the original signed claim as proof and uses the
separate `tsunagi-node-retirement/v1` signing domain. Both signatures and both
network scopes are checked. No owner, vote or quorum is involved, and no member
can fabricate the target's release or invent a future version cutoff.

The strongest observed target version wins; ties use a deterministic canonical
byte order. Claims at or below that version do not occupy an address, hostname
or visible member row. Original signed records remain stored, including their
range, so cleanup does not renumber the network. Markers remain even after a
newer claim returns: absence from a snapshot is never deletion and replaying an
old snapshot cannot restore the retired claim.

The local `Agent::forget_node` API checks the exact observed version again and
refuses self, online nodes, the selected exit node and missing/changed claims.
CLI and tray share this API. A returning live node can sign a newer claim and
allocate against the current holders; it resets the old hostname priority, so
it cannot reclaim a reused name merely by keeping its old timestamp. Cleanup
is not a permanent identity ban or a change of secret.

The marker and requester's own author counter commit in one SQLite transaction
before publication. Receivers persist a verified marker before applying it.
Invalid proofs are rejected individually. Periodic bounded marker batches
rotate through each peer's send queue, including when a queue fills, so a
replica that missed an update can catch up without the requester being online.

One strongest marker per target is retained, with a default limit of 1024 per
network and 1024 bytes per encoded marker. New targets beyond that limit are
refused rather than evicting resurrection protection. Corrupt mandatory marker
storage or a configured limit smaller than the stored set is an explicit error.

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
* a release tombstone, emitted when leaving or replacing the device key and
  not undone by a replica that has not heard of it;
* durable hostnames and equal-rights offline-node retirement described above;
* persistence in `state.sqlite`, with the record and the author's own version
  counter committed in **one transaction before the record is announced**;
* distribution as a `State` control message, merged into what the receiver
  already holds rather than replacing it;
* allocation of a free IPv4 address against what everybody else holds, which
  is what makes an address stable across an absence.

Deliberately not implemented: compaction and permanent author revocation.
Claims have a per-message bound; retirement history also has a per-network bound.

## Future tests

These are **not implemented and must not be reported as passing**:

- resistance to resurrection after compaction (compaction is not implemented);
- long network partitions and rejoin after an extended absence;
- NAT traversal and hole punching between real hosts;
- relay fallback behaviour against a self-hosted relay;
- multi-host deployment. CLI tests do run separate local agent processes;
  library tests run several independent instances inside one process.

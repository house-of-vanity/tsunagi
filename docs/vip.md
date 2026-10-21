# Named virtual services

A VIP is a shared name such as `api.home`, with independent TCP/UDP listeners.
Each listener maps its port to a set of node identities and application ports.
The application uses the name; the automatically allocated IPv4 address is an
internal reservation. The current overlay carries IPv4 only.

## CLI and tray

```sh
tsng vip list home
tsng vip create home api
tsng vip port add home api tcp/443 --backend server1:6443 --backend server2:7443
tsng vip port add home api udp/53 --backend server1:5353
tsng vip backend add home api tcp/443 server3:6443
tsng vip backend remove home api tcp/443 server2:7443
tsng vip port set home api tcp/443 --port-check off
tsng vip port set home api tcp/443 --check-interval-ms 3000 --check-timeout-ms 2000 --failures 2 --successes 1 --idle-timeout 7200
tsng vip show home api
tsng vip status home api --watch
tsng vip edit home api
tsng vip port remove home api udp/53
tsng vip remove home api
```

`list` without a network lists all configured networks. Network and VIP
selectors accept exact names, full ids and unique id prefixes; backend node
selectors also accept stored node names. Ambiguous selections change nothing.
Names resolve to identities when saved, so a renamed node remains a backend.
`--json` provides configuration, revision, counters and observations;
`list`/`watch` emit one JSON object per service/sample. `edit`
opens JSON in `VISUAL`/`EDITOR` and submits one complete version-checked draft.
An invalid or rejected edited file is retained with its path reported.

Each mutating command is atomic. A listener can be added with its full initial
backend set, and `edit` can replace the entire configuration at once. Empty
VIPs/listeners are valid and resolve, but cannot accept traffic. Configuration
updates currently require the network to be active locally. Saved configuration remains visible while a
network is stopped.

The tray's network tile has a **VIP** button. Its separate window edits names,
listeners, backend nodes/ports, check settings and flow timeouts. All edits,
including deletion, remain drafts until **Save**. Status updates do not
replace a dirty draft. A save conflict retains the draft; **Discard / reload**
loads the latest configuration. Closing a dirty window offers explicit discard
or continued editing.

The **Overview** tab shows a total VIP traffic plot and one backend table per
listener, with health, RTT, open flows, totals, TX/RX rates and individual
traffic plots. Plots switch between bytes and packets. Observations describe
traffic seen by this device, not a network-wide aggregate.

An interactive diagram connects the service name through each listener to its
node and target port. Drag to pan, Ctrl+scroll/pinch to zoom, and use **Fit**
to restore the view. Click a backend in the diagram or table to highlight it
and see its identity, address and measurement age. Green branches with moving
dots indicate counter growth during the latest status sample; a blue ring
marks the backend selected for new connections. Existing flows can therefore
keep a different branch active. Idle open flows alone do not light up a branch;
activity expires after five seconds without a fresh sample. Graph interaction
never edits or saves configuration. The **Configuration** tab retains the
explicit Save workflow. Addresses and ids are available in a collapsed detail.

## Delivery and recovery

The client agent selects the eligible backend with the lowest smoothed full
round-trip latency through the actual encrypted data plane, including relays.
Unknown or stale RTT is not treated as zero. Local backends have zero path RTT.
A new flow is pinned to its selected backend; a faster RTT does not move it.
This can concentrate new traffic on the closest node.

At local ingress, NAT replaces destination address/port and reserves an OS
source port for an unambiguous reverse mapping. Return traffic passes normal
network/peer source and destination admission **before** reverse NAT restores
the virtual source address/port. Plugins and encrypted transit stay unchanged.
A peer never gains permission to claim a VIP source. Fragment assembly is
bounded, checksums are updated, packets are fragmented back to the overlay MTU,
and ICMP errors have their quoted NAT headers restored. Fragment caches are
scoped to network and authenticated sender, with idle expiry independent of
further traffic.

For a backend on the client itself, the request is injected into the same TUN
with the nonlocal VIP as source, and the host reply is reverse-translated at
local ingress. The local backend therefore sees the VIP as source; remote
backends see the client's ordinary overlay address. Firewalls and application
bind addresses remain the administrator's responsibility.

Removing a backend/listener/VIP prevents new bindings while existing bindings
continue until idle expiry. Established TCP connections are not migrated. A retransmitted empty SYN may
choose another backend before a SYN-ACK has arrived; SYNs carrying application
data are not retargeted. A new SYN sequence creates a new binding even if the
client reuses its address/port tuple. TCP RST shortens binding retention. An unavailable UDP backend is replaced for subsequent
datagrams; already sent datagrams are never replayed. Stateful UDP applications
may need to re-establish their application session. Protocols that embed IP
addresses or negotiate additional ports require their own configuration; no
application payloads are parsed or rewritten.

Idle expiry defaults to 7200 seconds for TCP and 120 seconds for UDP. Shadow
ports are quarantined for 120 seconds after retirement to reject late replies
and avoid immediate reuse. Active and quarantined bindings share a bounded
capacity. State and sockets are released on network stop or agent shutdown.
A restart drops bindings; shared service configuration remains intact.

## Health

One probe exchange per second measures each used peer through the encrypted
IP tunnel. The EWMA uses 7/8 of the previous sample and 1/8 of the new one.
A probe expires after three seconds; two consecutive missing responses or a
missing data path exclude the peer. Measurements expire after ten seconds.
Probes continue during failure so recovery is automatic.

TCP connect checks default to on. Defaults are a three-second interval,
two-second timeout, two failures to exclude and one success to recover.
Checks are shared for the same network/node/address/TCP-port, run off the
packet path with at most 32 concurrent connects, and are scheduled fairly.
A 250ms worker tick services timers. Connect checks send no application data;
they confirm port acceptance and may appear in server logs. They cannot prove
application readiness after a successful handshake. Disabling port checks
retains data-plane probes.

UDP uses encrypted path checks and explicit ICMP port errors. No arbitrary
probe datagrams are injected into an unknown application protocol. Silence
cannot prove failure of an arbitrary UDP application. An explicit unreachable
port is excluded for ten seconds and then becomes eligible to retry.

## Shared state and addresses

Any authenticated member can create, edit or remove any VIP. Each field is a
self-contained signed register: network, service id, field key, optional encoded
value, Lamport clock, author, durable author counter and signature. Signing uses
the separate `tsunagi-vip-field/v1\0` domain followed by postcard encoding of
those fields with the signature vector empty. The encoding/order is a wire
contract; the identity scheme and handshake transcript are unchanged.

Concurrent edits to different backend fields merge. A conflict on one field
uses `(Lamport clock, author id, canonical bytes)` ordering, independent of wall
time and arrival order. Listener generations prevent backend fields from an
old removed listener reappearing when the port is recreated. Service deletion
is a permanent signed tombstone for its id; recreation gets a fresh id.
Missing snapshot fields are never deletion.

Saving validates the entire draft and checks the revision shown by the editor.
The merged snapshot and author's counter commit together in SQLite before local
routing changes or publication. Receivers verify and persist complete service
snapshots before exposing them. Periodic rotating snapshots repair queue loss
and returning replicas without requiring the creator online. Concurrent edits
made before participants have seen each other can still merge after a save.
A merged configuration exceeding listener/backend limits is reported as an
error and excluded from routing rather than selected according to arrival order.

VIP allocation walks the agreed overlay range from a service-id-derived seed,
excluding known node claims and other allocated VIPs. Nodes avoid known VIP
reservations when choosing a new address. Names colliding with node names or
another service are reported; node names take precedence and service ties use
id order. A partition can temporarily have incomplete state; after merge an
address or conflicting name's effective holder can change. Use DNS names.
DNS TTL is 30 seconds; DNS does not migrate established connections or force
applications to discard cached addresses. Existing NAT bindings retain their
original VIP address while draining.

`Limits` bounds active services (64 by default), permanent deletion markers
(1024), signed fields per active service (192), listeners (16), backends per
listener (32), active TCP checks (32), flow/port reservations (4096) and incomplete
IPv4 datagrams (64). A deleted service retains only its signed permanent
marker; obsolete fields can be dropped because replay cannot override deletion.
A full deletion history is an explicit error; protection is never silently
evicted. Deleted services do not consume the active-service limit. Whole service
snapshots must also fit the configured control frame limit. Corrupt mandatory VIP storage
is a hard error on activation, never reset as a cache.

## Observations and verification

Status is this client's observation. Per VIP/listener/backend it reports the
next selected backend, health reason, RTT and sample age, active bindings,
user IP packet/byte counters, drops and UDP failovers. Probe bytes do not enter
user traffic counters. The GUI and CLI watch derive rates from cumulative
counters; counters reset on restart. These are IP forwarding counters, not
application acknowledgements or guaranteed delivered-byte totals.

Automated tests cover field merging, stale drafts, signed deletion, tampering,
network isolation, SQLite migration and transactional rollback, real port
connect failure/recovery, RTT selection, UDP failover, local hairpin NAT,
fragmentation/checksums, real encrypted TCP/UDP packet delivery and source
admission, real CLI/DNS wiring and draft form rendering. In-memory TUN tests
exercise packets, not an operating system TCP stack. Native desktop behavior,
physical interfaces and cross-platform kernel/firewall behavior need live-host
validation; automated tests do not establish those.

# Mainline rendezvous

`tsunagi up` enables public Mainline DHT discovery. `--no-dht` disables it;
`--dht` explicitly selects the default. `--reach local` always disables it.
Manual `--peer` entries work alongside DHT or on their own. Library callers
opt in with `AgentConfig::with_dht(MainlineDiscovery::default())`; merely
constructing a configuration opens no DHT socket.

One Mainline client serves an agent's active networks. Each network gets its
own BEP44 signing seed, derived with the new `mainline-rendezvous-write-v1`
HKDF label. Existing network IDs, discovery keys and handshake keys are
unchanged. The semi-public `DiscoveryKey` is not used as signing material.
No network name, secret, or signing seed is included in a record or log.

## First contact and recovery

Each active network starts publication and lookup independently. Lookup
streams candidates to the existing dial loop, starting connections before
all slots have been read. Failed/empty rounds retry with increasing delay
(5 to 30 seconds, with jitter). An empty lookup never proves a network empty.
The first successful membership handshake, including an incoming handshake,
stops lookup. Publication continues while there are connected peers.

After the last authenticated session ends, known peers continue to be retried.
If none connects within 60 seconds, DHT lookup resumes. A successful handshake
stops it again. This policy is per network. DHT does not heal a partition in
which every component still has an authenticated neighbor.

Publisher and lookup tasks run outside the network actor, with deadlines,
bounded candidate delivery, and cancellation on deactivation or shutdown.
An unreachable DHT never prevents status, normal sessions or manual bootstrap.
The client socket is released on agent shutdown. The library uses no global
client, runtime, or mutable rendezvous table.
Client clones share that lifetime: create a new `MainlineDiscovery` for a new
agent after shutdown, including when injecting a local test client.

## Records and concurrency

The protocol uses 16 BEP44 salts (`tsunagi-rendezvous-v1` followed by the slot
byte) under the network's signing key. Every publisher chooses two distinct
slots deterministically from SHA-256 of its endpoint ID. Each value describes
only its writer: a format version, publication time, endpoint ID, one relay
URL and up to eight IP addresses. Bencoded values stay within BEP44's 1000-byte
limit. Decoding bounds every field before allocation and rejects unknown
versions, malformed records, timestamps too far in the future and stale data.

Slots hold a changing sample, not the complete membership. Overwrites are
expected and 16 is not a network-size limit. Publishing reads the latest
sequence, increments it, and uses BEP44 CAS with bounded retry on conflict.
CAS is local to each storage node and is not a distributed lock. Valid records
encountered during publication may become candidates on the next explicit
lookup; they never cause connected networks to start dialing from publication.
Lookup queries at most four slots concurrently and returns up to 16 distinct
candidates. At most 16 discovery candidates are retained by default; failed
candidates can be replaced rather than permanently excluding later results.

Values are signed but not encrypted. Possession of a discovery result grants
no network access: iroh authenticates the device and the control handshake
proves membership. Public rendezvous is not an anonymity mechanism.

## Freshness and durable state

Every five minutes (20% jitter), and on an observed endpoint-address change,
the agent publishes fresh data. The address monitor checks every five seconds
by default. Readers accept records for 15 minutes, allowing up to two minutes
of future clock skew. The host clock must therefore be reasonably accurate.
This is application freshness, not a request for DHT nodes to delete data.

BEP44 has no deletion operation. Deactivation stops publication; it never
deletes a shared slot that another member may now occupy. Records expire from
our readers even if storage nodes keep them. A restart restores identity and
active networks from `state.sqlite`, computes the same rendezvous location,
and publishes the current address. Old DHT entries and disposable cache are
not required. A publish reads sequence numbers from DHT, so restarts do not
reset the sequence of a surviving mutable item.

## Tests

The default suite uses Mainline Testnet nodes bound to loopback, real iroh
connections, real membership handshakes, and SQLite in temporary directories.
It covers concurrent publication, colliding slots, network-secret isolation,
record validation, bootstrap after all DHT records and cache disappear,
connected-state lookup suppression, isolation recovery and hung backends.
Public DHT and relay checks are opt-in and are not part of the offline suite.

Run the optional public check with:

```sh
cargo test --locked -p tsunagi --test mainline public_dht_finds_and_authenticates_two_agents -- --ignored --exact
```

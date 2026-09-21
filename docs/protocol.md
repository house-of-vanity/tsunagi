# Protocol

Module boundaries are in [architecture.md](architecture.md); the threat model
is in [threat-model.md](threat-model.md).

## Versioning

Two versions exist and are independent:

- **Identity scheme**, `tsunagi-network-id-v1`. Frozen. Changing it creates a
  different network space for the same name and secret.
- **Control protocol**, ALPN `tsunagi/ctrl/1`, `PROTOCOL_VERSION = 1`.

Upgrading the crate or bumping the control protocol must never change an
existing `NetworkId`.

## Canonical encoding

Everything that is hashed or MAC'd uses length-prefixed fields, written here as
`LP(x) = u32_be(len(x)) || x`. String concatenation is never used, so no two
different field splits can produce the same bytes.

## Network space identity

```text
salt = SHA-256( LP("tsunagi-network-id-v1") || LP(name_utf8) )
prk  = HKDF-SHA256-Extract(salt, ikm = secret_bytes)

info(label)   = LP("tsunagi-network-id-v1") || LP(label)
network_id    = HKDF-Expand(prk, info("network-id"),     32)
discovery_key = HKDF-Expand(prk, info("discovery-key"),  32)
auth_key      = HKDF-Expand(prk, info("handshake-auth"), 32)
```

HKDF's `info` parameter is what separates the three outputs (RFC 5869 §3.2).
The labels and this encoding are frozen.

**Name rules.** 1..=64 bytes of UTF-8, no control characters, no leading or
trailing ASCII whitespace — such a name is *rejected*, not trimmed. The name is
used verbatim: no case folding, no Unicode normalisation. `Home` and `home` are
different network spaces.

**Secret rules.** Used verbatim: never trimmed, case-folded, normalised or
truncated. At least 16 bytes; `NetworkSecret::generate()` produces 32 random
bytes. The canonical text form is `tsn1` followed by lowercase unpadded base32.

**Key separation.** `network_id` is public. `discovery_key` is what a discovery
backend is told; it is secret-derived but is **not** a credential — learning it
does not help pass the handshake, and it must never be used as a password or
bearer token. `auth_key` never leaves the process.

## No competing genesis

A network's description is `NetworkDescriptor { scheme, name, network_id }`. It
contains no creator identity, no creation time and no owner signature, so two
agents started independently with the same parameters produce byte-identical
descriptors. No minimum-hash rule, no vote, no leader. The secret is not part
of it.

A network's name does not change inside an existing space. A different name or
secret is a different space.

## Framing

One QUIC bidirectional stream per session. A frame is `u32_be(len) || payload`.
The announced length is checked against `Limits::max_frame_len` (64 KiB by
default) **before** any buffer of that size is allocated. Payloads are
[postcard], a compact deterministic serde format — not a general RPC framework.

No encryption is layered on top of iroh: QUIC/TLS already provides
confidentiality, integrity and endpoint authentication.

[postcard]: https://docs.rs/postcard

## Handshake

A successful iroh connection proves only *which endpoint* is on the other side,
because the endpoint id is the public key in the TLS certificate. Anyone can
dial us. Membership of a specific network is proved separately.

iroh exposes the TLS exporter (RFC 5705) through
`Connection::export_keying_material`. That yields the same secret bytes on both
ends of *this* connection, which is what stops a proof being replayed
elsewhere. **It proves nothing about the shared secret on its own**, because
both ends of any connection can compute it. The membership proof is the HMAC
keyed by `auth_key`; the exporter output is just one of its inputs.

```text
cb = TLS-Exporter(label = "tsunagi/handshake/v1", context = network_id, 32)

transcript(role) = LP("tsunagi-handshake-v1")
                || LP(role)                    // "initiator-proof" | "responder-proof"
                || LP(u16_be(protocol_version))
                || LP(network_id)              // 32 bytes
                || LP(initiator_endpoint_id)   // 32 bytes
                || LP(responder_endpoint_id)   // 32 bytes
                || LP(cb)                      // 32 bytes
                || LP(nonce_initiator)         // 16 bytes
                || LP(nonce_responder)         // 16 bytes

proof(role) = HMAC-SHA256(auth_key, transcript(role))
```

What each input buys:

| input | property |
|---|---|
| `auth_key` | membership in this network space |
| `cb` | binding to this connection; a captured proof is useless on another |
| `network_id` | binding to this network space |
| both endpoint ids | binding to these two identities |
| distinct `role` labels | no reflection: a proof cannot be bounced back |
| both nonces | freshness contributed by each side |

Message order:

```text
initiator -> responder : Hello     { version, network_id, nonce_i }
initiator <- responder : HelloAck  { version, nonce_r }
initiator -> responder : AuthProof { proof(initiator) }
initiator <- responder : AuthProof { proof(responder) }   // only after the first verified
```

The responder emits nothing derived from `auth_key` until the initiator's proof
verifies, so a caller who does not know the secret learns nothing. Comparison
is constant time. Endpoint ids always come from the TLS certificate, never from
a peer's claim. Until both steps complete, no regular control message is
accepted in either direction. The whole exchange is bounded by
`Limits::handshake_timeout`.

A `Hello` naming a network this agent does not have active is rejected with
"unknown network". Because the claim is unverified at that point, the rejection
event does not report a network id.

## The data plane protocol

IP plugin packets never travel on a control connection. They use their own
ALPN, `tsunagi/data/1`, on their own iroh connection:

```text
initiator -> responder : (the same membership handshake as above)
initiator -> responder : DataOpen    { protocol }
initiator <- responder : DataOpenAck { accepted, max_datagram }
thereafter             : QUIC datagrams carrying that plugin's packets
```

The membership handshake is identical and bound to the same network, so a data
channel cannot be opened by somebody who does not know the secret. `protocol`
is bounded and must name a plugin the responder actually runs; otherwise the
channel is declined, which is an ordinary outcome rather than an error.

Only one side dials — the one with the smaller endpoint id — so two agents
never open two channels for the same thing.

Packets ride as QUIC **datagrams**: unreliable and unordered, which is what a
tunnelled protocol wants, and free of the head-of-line blocking a stream would
add. The datagram limit is what caps a plugin's MTU.

Separate connections mean separate congestion control, so a saturated data
plane cannot delay control messages, and a data plane failure cannot take the
control plane down with it.

## Control messages

After authentication, every frame is an `Envelope { network_id, message }` and
the `network_id` is re-checked against the session's network on every message.
A mismatch ends that session and is counted as a protocol violation; it does
not affect other networks.

| message | meaning |
|---|---|
| `Announce { hostname, capabilities }` | this agent's hostname and IP-plugin capabilities |
| `Ping { seq, payload }` | small request used to verify the exchange |
| `Pong { seq, payload }` | the echoed reply |
| `Bye { reason }` | graceful goodbye; not a revocation of anything |

`PluginCapability { protocol, version, enabled, data }` is opaque to the core:
`data` is bounded and handed to the matching plugin unparsed. Nothing in it is
ever treated as a shell command, filesystem path or OS setting.

Every decoded message is validated against `Limits` before it reaches anything
else. A rejected message never stops a network or the agent.

## Limits

Defaults from `Limits`, all configurable:

| limit | default |
|---|---|
| frame payload | 64 KiB |
| hostname | 255 bytes |
| capabilities per announcement | 16 |
| capability payload | 4 KiB |
| echo payload | 4 KiB |
| reason string | 256 bytes |
| handshake timeout | 10 s |
| dial timeout | 10 s |
| write timeout | 30 s |
| concurrent dials per network | 8 |
| sessions per network | 64 |
| inbound handshakes in flight | 32 |
| outbound queue per session | 64 |

Liveness of an established session is delegated to QUIC: iroh configures
keep-alives and an idle timeout, so a dead peer surfaces as a read error rather
than needing a heartbeat in this protocol.

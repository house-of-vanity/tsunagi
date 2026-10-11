# Pairwise Amnezia transport

The CLI's default carrier preference is `wg,awg,wg-quic,tcp-tls`. To select
AWG explicitly:

```sh
tsng up --protocol awg
tsng up --protocol wg,awg,wg-quic,tcp-tls
```

`awg` is Tsunagi AWG wire version 1. Its packet masking engine is adapted from
[RunaRoo/AmneziaWG-RS](https://github.com/RunaRoo/AmneziaWG-RS), with the pinned
source and license recorded in
[UPSTREAM.md](../crates/tsunagi-awg/UPSTREAM.md). It uses the existing boringtun
Noise/WireGuard implementation instead of upstream's Node, global executors
and OS interface machinery. Compatibility with ordinary Amnezia servers is
not implemented: this carrier connects authenticated Tsunagi members.

## Negotiation and lifetime

There is one independent UDP socket and cancellable packet-engine task per
`(network, peer)` pair. The smaller endpoint id initiates, following the same
rule as other data carriers. Both sides must announce enabled AWG wire version
1. An authenticated iroh control session is required throughout; AWG supplies
no alternate discovery or membership mechanism.

Every `open` generates new masking parameters, a header-protection key, an
outer WireGuard key pair and a PSK. The initiator sends a private `Offer` with
a random attempt id, its public key, candidate socket addresses and the shared
profile. The responder validates it, creates its own fresh key pair and socket,
and returns an `Answer` naming that attempt. Both send masked handshakes and
encrypted delivery probes to the candidates. Only authenticated WireGuard
**data**, not a STUN response or an incoming UDP address alone, verifies a path.

Negotiation payloads are bounded at 4096 bytes (a caller can lower the limit),
redacted in Debug, excluded from public message events and erased on drop.
They are never capabilities, signed records, cache entries or exported status.
At most 128 pairs are admitted per transport, with bounded command/data queues,
at most 32 candidates per attempt and finite establishment deadlines.
Stale answers and duplicate offers are rejected; a new attempt replaces and
closes an older pair engine. Cancellation, peer departure, network deactivation
and shutdown retire sockets without waiting for a remote reader.

A process restart, a failed setup, or a complete fallback cycle returning to AWG
starts fresh negotiation. Normal WireGuard rekeying within a live attempt keeps
that attempt's masking profile. A failed pair does not reconfigure other pairs
or other networks. A full mesh of 15 members uses 14 engines per member and 105
independent pairs in total; it does not create additional system interfaces.

## Masking

Each profile randomizes disjoint H1–H4 header ranges, a 12–48-byte S1–S4 prefix,
a ChaCha20 header-protection key, handshake trailers, junk packet count/lengths,
and extra content padding. Prefix lengths are equal within one profile so
header detection has one offset. A fresh random nonce is in every packet's
prefix; handshake headers and transport headers/counters are protected.
The standard WireGuard header is restored before boringtun authenticates a
message. This preserves boringtun's standard MAC calculations, which is another
reason this is a Tsunagi-specific AWG wire version.

Before a handshake, an I1 signature packet is generated from either a complete
DNS query or SIP OPTIONS template, with fresh identifiers and consistent length
fields, followed by random junk packets. I2–I5 are unused in this version.
The templates are structural generators, not replayed captures. QUIC imitation
is not selected. Masking can change DPI classification; it is not a promise of
indistinguishability or that any particular firewall will admit it.

## Packets, NAT and fallback

The pair engine carries opaque relay envelopes inside authenticated outer WG
packets. It fragments those envelopes into bounded chunks and expires incomplete
assemblies; a logical datagram is bounded at 64 KiB and an outer UDP packet is
at most 1200 bytes. The encapsulated IPv4 headers are internal framing only: no interface or OS address is created for a
pair. Overlay addresses, routing, ownership checks and end-to-end encryption
remain independent. A relay decrypts its own adjacent AWG carrier to forward
opaque end-to-end ciphertext, never the destination's IP packet.

Local IPv4 candidates and simultaneous encrypted probes provide direct UDP
connectivity. In `direct`/`relay` reach mode the CLI also uses
`stun.l.google.com:19302` to discover a server-reflexive address on **this pair's
socket**, with a 1.2-second bound. A STUN result is only a candidate. Local reach
mode makes no STUN request. Configure or disable it with
`-o awg:stun=HOST:PORT` or `-o awg:stun=off`. Failed discovery still permits local
candidates. IPv6-only paths, symmetric NAT and networks blocking arbitrary UDP
may fail AWG and fall back; there is no AWG-over-QUIC substitution or AWG TURN
relay hidden behind its name.

Data delivery checks go through the actual end-to-end encrypted tunnel, once
per second, independently of control-plane RTT. Requests and replies bind a
fresh private marker/key to the sender's endpoint id. Unanswered requests expire
after three seconds. After a 20-second warmup, at least 15 completed observations
and at least 60% loss in the last 20 observations retire a carrier. Probes are
consumed locally after source/destination admission and never enter the TUN.
AWG additionally checks encrypted outer delivery throughout the pair lifetime.

Setup failure or persistent runtime loss advances to the next mutually supported
carrier in the initiator's order. Earlier expired cooldowns do not jump ahead of
untried carriers. Retry cooldowns remain bounded; reaching AWG again negotiates
new parameters. Control sessions and the logical end-to-end tunnel survive a
carrier change. Status names the end-to-end protocol and the actual carrier
separately, so `wg` over `awg` is a valid result.

Control wire version 6 introduces the private transport message. All members
must upgrade together; device identities, network ids, handshake transcript
encoding, signed state and stored network configuration are unchanged. Data
ALPN remains `tsunagi/data/5`; the relay envelope is unchanged.

## Verification

The default rootless, offline tests use real iroh endpoints, membership proofs,
SQLite, UDP sockets, masked WireGuard handshakes, end-to-end encryption and
memory TUNs. They cover independent three-member pairs, full-size bidirectional
packets, restart freshness/socket release, 80% runtime datagram loss, fallback
to real iroh and fresh negotiation on retry, plus malformed profiles/messages,
role checks, probe forgery and STUN response parsing. These tests do not establish
DPI effectiveness, WAN throughput, public NAT traversal or per-pair memory cost.

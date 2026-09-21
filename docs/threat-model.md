# Threat model and known limits

Read this before relying on anything here. The protocol is in
[protocol.md](protocol.md).

## What is protected

- **Network membership.** A peer must prove knowledge of `auth_key`, derived
  from the network name and shared secret, to get an authenticated session.
  Knowing the public `NetworkId`, or an agent's address, is not enough.
- **Endpoint authenticity.** iroh's QUIC/TLS handshake authenticates the
  remote endpoint id, which is its public key. Identities in the membership
  transcript are taken from the certificate, never from a peer's claim.
- **Connection binding.** The membership proof includes TLS exporter output, so
  a proof captured on one connection does not verify on another.
- **Role separation.** Initiator and responder proofs cover different
  transcripts, so a proof cannot be reflected back at its sender.
- **Network isolation.** A session authenticated for network A cannot carry
  messages for network B, even over a shared physical connection.
- **Confidentiality and integrity in transit.** Provided by QUIC/TLS. This
  crate adds no encryption of its own.
- **Overlay address ownership.** A peer's overlay address is derived from its
  public key, not taken from its announcement. Outbound packets go to the owner
  of the destination address; inbound packets are dropped unless their source
  is the address derived for the peer that sent them. A member can therefore
  neither receive nor forge another member's traffic. See
  [wireguard.md](wireguard.md#address-ownership-is-enforced-not-announced).
- **Tunnelled traffic is end-to-end encrypted by WireGuard**, independently of
  this crate. The transport underneath is also encrypted by iroh, but the
  tunnel's confidentiality does not depend on that.
- **Resource bounds.** Frame lengths are validated before allocation; strings,
  lists, queues, concurrent dials and in-flight handshakes are all bounded;
  handshakes, dials and writes have timeouts.

## What is not protected

- **Anyone who knows the secret is a full participant.** They can create
  arbitrarily many identities, flood the network with records and collide with
  other participants' names. This is why a majority is not a root of trust.
  Signatures protect authorship; they do not make a participant honest.
- **Weak secrets.** This targets high-entropy secrets. There is no PAKE, so a
  short human passphrase can be guessed offline by anyone who can reach the
  handshake. Use `NetworkSecret::generate()`.
- **Addresses and metadata are observable.** Anyone able to watch the network
  sees addresses, timing and volume. Discovery backends see the
  `discovery_key` and the addresses published under it, which is enough to map
  a network's participants. This library does not make a network anonymous, and
  having iroh under it does not make it so.
- **A cloned state directory is a cloned identity.** `state.sqlite` holds the
  device secret key and the network secrets. Copying it copies the participant.
  Restoring an old backup rolls the agent's state back, which — once signed
  records exist — can resurrect revoked information or replay stale versions.
- **A compromised host.** The secret is on disk to survive restarts. File
  permissions are owner-only where the platform supports it, and the state
  directory takes an ownership lock, but neither defends against a user who can
  read the file or against malware running as that user.
- **User IP traffic.** Carried by the WireGuard plugin over an iroh data
  connection, and encrypted by WireGuard end to end. *Filtering* it is still
  the operating system's and the user's job: the plugin creates connectivity
  between members and does not police what flows over it.
- **Traffic metadata reaches the relay when one is used.** If iroh cannot hole
  punch, the data connection goes through a relay, which then sees the volume
  and timing of tunnelled traffic — though not its contents, which WireGuard
  encrypted, nor the iroh layer's contents.
- **Overlay address squatting.** A member can mint many WireGuard keys and
  therefore occupy many overlay addresses. It cannot pick which ones, but it
  can consume them and appear as many participants.
- **Plugin keys on disk.** The WireGuard private keys live in the plugin's own
  `wireguard.sqlite`, owner-only where the platform supports it. Copying that
  file copies this agent's overlay identity, exactly as copying `state.sqlite`
  copies its control plane identity.
- **What the data plane does not police.** Address ownership stops a member
  impersonating another member. It does not stop a member sending whatever it
  likes *from its own* address.
- **Denial of service.** Bounds and timeouts stop trivial resource exhaustion
  from a single peer. They do not make the agent resistant to a determined
  attacker who knows the secret, and no rate limiting per identity exists yet.
- **Global freshness.** A signature proves authorship, not that you have the
  newest state. See [sync-model.md](sync-model.md).
- **Discovery is not trustworthy.** It returns candidates. A hostile or stale
  discovery backend can waste dial attempts and learn addresses; it cannot
  forge membership.

## Deliberate design consequences

- **No owner, no vote.** Nobody can evict anybody. Removing a participant means
  changing the secret, which creates a different network space that the removed
  participant cannot enter.
- **Rotating the secret is not revocation of past access.** Anyone who held the
  old secret keeps whatever they already saw.
- **Local deactivation is not revocation.** Deactivating a network stops this
  agent participating. It says nothing about anyone else.
- **Failures are contained, not escalated.** A bad proof, wrong secret,
  malformed frame or unknown version rejects one message or one session. It
  never stops another network and never stops the agent, and there is no
  irreversible global error flag.

## Cryptographic choices

Standard primitives only, no home-made constructions: HKDF-SHA256 (RFC 5869)
for key separation, HMAC-SHA256 for the membership proof, constant-time
verification, iroh's Ed25519 endpoint keys and QUIC/TLS for the transport, and
RFC 5705 TLS exporter output for channel binding. There is no custom encryption
layer and no custom PAKE.

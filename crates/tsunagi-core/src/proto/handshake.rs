//! Mutual proof that both ends belong to the same network space.
//!
//! # Why a successful iroh connection is not enough
//!
//! iroh authenticates *endpoints*: after the QUIC/TLS handshake each side knows
//! the other's [`EndpointId`], because that id is the public key in the
//! certificate. It says nothing about network membership — anybody can dial us.
//! So on top of the authenticated connection we run an explicit mutual proof of
//! knowledge of the derived network authentication key.
//!
//! # Channel binding is not a proof by itself
//!
//! iroh exposes the TLS exporter (RFC 5705) via
//! [`Connection::export_keying_material`]. That gives both sides the same
//! secret bytes for *this* connection, which is exactly what is needed to stop
//! a proof being replayed on another connection. It proves nothing about the
//! shared network secret on its own, because both ends of any connection can
//! compute it. The proof of membership is the HMAC keyed by `auth_key`; the
//! exporter output is only one of its inputs.
//!
//! # The scheme
//!
//! ```text
//! cb   = TLS-Exporter(label = "tsunagi/handshake/v1", context = network_id, 32)
//! LP(x)= u32_be(len(x)) || x
//!
//! transcript(role) = LP("tsunagi-handshake-v1")
//!                 || LP(role)                    // "initiator-proof" | "responder-proof"
//!                 || LP(u16_be(protocol_version))
//!                 || LP(network_id)              // 32 bytes
//!                 || LP(initiator_endpoint_id)   // 32 bytes
//!                 || LP(responder_endpoint_id)   // 32 bytes
//!                 || LP(cb)                      // 32 bytes
//!                 || LP(nonce_initiator)         // 16 bytes
//!                 || LP(nonce_responder)         // 16 bytes
//!
//! proof(role) = HMAC-SHA256(auth_key, transcript(role))
//! ```
//!
//! What each input buys:
//!
//! * `auth_key` — membership. Derived from name+secret only, see
//!   [`crate::identity`].
//! * `cb` — binding to this connection. A proof captured elsewhere is useless
//!   here, because `cb` differs per TLS session.
//! * `network_id` — binding to this network space.
//! * both endpoint ids — binding to these two identities.
//! * distinct `role` labels — no reflection: the responder cannot bounce the
//!   initiator's own proof back at it.
//! * both nonces — freshness contributed by each side.
//!
//! # Message order
//!
//! ```text
//! initiator -> responder : Hello    { version, network_id, nonce_i }
//! initiator <- responder : HelloAck { version, nonce_r }
//! initiator -> responder : AuthProof{ proof(initiator) }
//! initiator <- responder : AuthProof{ proof(responder) }      // only if the first proof verified
//! ```
//!
//! The responder emits nothing derived from `auth_key` until the initiator's
//! proof has verified, so a caller who does not know the secret learns nothing.
//! Until both steps complete, no regular control message is accepted in either
//! direction.
//!
//! [`Connection::export_keying_material`]: iroh::endpoint::Connection::export_keying_material

use hmac::{Hmac, KeyInit, Mac};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::config::Limits;
use crate::error::ProtocolError;
use crate::identity::{NetworkId, NetworkKeys};
use crate::proto::frame::{read_frame, write_frame};
use crate::proto::message::{AuthProof, Hello, HelloAck, PROTOCOL_VERSION, decode, encode};

/// Frozen domain separator of the handshake transcript.
pub const TRANSCRIPT_DOMAIN: &str = "tsunagi-handshake-v1";

/// TLS exporter label used for channel binding.
pub const EXPORTER_LABEL: &[u8] = b"tsunagi/handshake/v1";

/// Transcript role label of the side that dialled.
pub const ROLE_INITIATOR: &str = "initiator-proof";

/// Transcript role label of the side that accepted.
pub const ROLE_RESPONDER: &str = "responder-proof";

/// Length of the channel binding material, in bytes.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Which side of the handshake this agent played.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// This agent dialled.
    Initiator,
    /// This agent accepted.
    Responder,
}

impl Role {
    /// Short label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

/// Result of a completed handshake.
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    /// Network both sides proved membership of.
    pub network_id: NetworkId,
    /// Authenticated endpoint id of the peer, taken from the TLS certificate.
    pub peer: EndpointId,
    /// Which side this agent played.
    pub role: Role,
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Builds the role-specific transcript. Pure function, unit tested.
#[allow(clippy::too_many_arguments)]
pub fn transcript(
    role: &str,
    version: u16,
    network_id: &[u8; 32],
    initiator: &[u8; 32],
    responder: &[u8; 32],
    channel_binding: &[u8],
    nonce_initiator: &[u8; 16],
    nonce_responder: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    push_lp(&mut out, TRANSCRIPT_DOMAIN.as_bytes());
    push_lp(&mut out, role.as_bytes());
    push_lp(&mut out, &version.to_be_bytes());
    push_lp(&mut out, network_id);
    push_lp(&mut out, initiator);
    push_lp(&mut out, responder);
    push_lp(&mut out, channel_binding);
    push_lp(&mut out, nonce_initiator);
    push_lp(&mut out, nonce_responder);
    out
}

/// Computes one proof.
#[allow(clippy::too_many_arguments)]
fn proof(
    auth_key: &[u8; 32],
    role: &str,
    version: u16,
    network_id: &[u8; 32],
    initiator: &[u8; 32],
    responder: &[u8; 32],
    channel_binding: &[u8],
    nonce_initiator: &[u8; 16],
    nonce_responder: &[u8; 16],
) -> [u8; 32] {
    let message = transcript(
        role,
        version,
        network_id,
        initiator,
        responder,
        channel_binding,
        nonce_initiator,
        nonce_responder,
    );
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(auth_key) {
        Ok(mac) => mac,
        // HMAC-SHA256 accepts keys of any length, so a 32 byte key cannot fail.
        Err(_) => unreachable!("HMAC-SHA256 accepts a 32 byte key"),
    };
    mac.update(&message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Verifies a proof in constant time.
#[allow(clippy::too_many_arguments)]
fn verify(
    auth_key: &[u8; 32],
    role: &str,
    version: u16,
    network_id: &[u8; 32],
    initiator: &[u8; 32],
    responder: &[u8; 32],
    channel_binding: &[u8],
    nonce_initiator: &[u8; 16],
    nonce_responder: &[u8; 16],
    candidate: &[u8; 32],
) -> Result<(), ProtocolError> {
    let message = transcript(
        role,
        version,
        network_id,
        initiator,
        responder,
        channel_binding,
        nonce_initiator,
        nonce_responder,
    );
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(auth_key) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA256 accepts a 32 byte key"),
    };
    mac.update(&message);
    mac.verify_slice(candidate)
        .map_err(|_| ProtocolError::AuthenticationFailed)
}

/// Extracts channel binding material from the connection.
fn channel_binding(
    conn: &Connection,
    network_id: &[u8; 32],
) -> Result<Zeroizing<[u8; CHANNEL_BINDING_LEN]>, ProtocolError> {
    let mut out = Zeroizing::new([0u8; CHANNEL_BINDING_LEN]);
    conn.export_keying_material(out.as_mut(), EXPORTER_LABEL, network_id)
        .map_err(|err| ProtocolError::NoChannelBinding(format!("{err:?}")))?;
    Ok(out)
}

fn fresh_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce);
    nonce
}

fn check_version(found: u16) -> Result<(), ProtocolError> {
    if found != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            found,
            supported: PROTOCOL_VERSION,
        });
    }
    Ok(())
}

/// Runs the initiator side of the handshake.
///
/// Bounded by [`Limits::handshake_timeout`].
pub async fn initiate(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_id: EndpointId,
    keys: &NetworkKeys,
    limits: &Limits,
) -> Result<HandshakeOutcome, ProtocolError> {
    tokio::time::timeout(
        limits.handshake_timeout,
        initiate_inner(conn, send, recv, local_id, keys, limits),
    )
    .await
    .unwrap_or(Err(ProtocolError::HandshakeTimeout))
}

async fn initiate_inner(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_id: EndpointId,
    keys: &NetworkKeys,
    limits: &Limits,
) -> Result<HandshakeOutcome, ProtocolError> {
    let network_id = keys.network_id();
    let network_bytes = *network_id.as_bytes();
    let peer = conn.remote_id();

    let initiator = *local_id.as_bytes();
    let responder = *peer.as_bytes();
    let cb = channel_binding(conn, &network_bytes)?;

    let nonce_i = fresh_nonce();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        network_id: network_bytes,
        nonce: nonce_i,
    };
    write_frame(send, &encode(&hello)?, limits.max_frame_len).await?;

    let ack: HelloAck = decode(&read_frame(recv, limits.max_frame_len).await?)?;
    check_version(ack.version)?;
    let nonce_r = ack.nonce;

    let mine = proof(
        keys.auth_key(),
        ROLE_INITIATOR,
        PROTOCOL_VERSION,
        &network_bytes,
        &initiator,
        &responder,
        cb.as_ref(),
        &nonce_i,
        &nonce_r,
    );
    write_frame(
        send,
        &encode(&AuthProof { proof: mine })?,
        limits.max_frame_len,
    )
    .await?;

    let theirs: AuthProof = decode(&read_frame(recv, limits.max_frame_len).await?)?;
    verify(
        keys.auth_key(),
        ROLE_RESPONDER,
        PROTOCOL_VERSION,
        &network_bytes,
        &initiator,
        &responder,
        cb.as_ref(),
        &nonce_i,
        &nonce_r,
        &theirs.proof,
    )?;

    Ok(HandshakeOutcome {
        network_id,
        peer,
        role: Role::Initiator,
    })
}

/// Runs the responder side of the handshake.
///
/// `lookup` maps the network id the peer asked for to the local key material,
/// returning `None` if this agent does not have that network active. Routing
/// stays in the agent; the protocol stays here.
///
/// Bounded by [`Limits::handshake_timeout`].
pub async fn respond<F>(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_id: EndpointId,
    limits: &Limits,
    lookup: F,
) -> Result<HandshakeOutcome, ProtocolError>
where
    F: FnOnce(NetworkId) -> Option<NetworkKeys>,
{
    tokio::time::timeout(
        limits.handshake_timeout,
        respond_inner(conn, send, recv, local_id, limits, lookup),
    )
    .await
    .unwrap_or(Err(ProtocolError::HandshakeTimeout))
}

async fn respond_inner<F>(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_id: EndpointId,
    limits: &Limits,
    lookup: F,
) -> Result<HandshakeOutcome, ProtocolError>
where
    F: FnOnce(NetworkId) -> Option<NetworkKeys>,
{
    let hello: Hello = decode(&read_frame(recv, limits.max_frame_len).await?)?;
    check_version(hello.version)?;

    let network_id = NetworkId::from_bytes(hello.network_id);
    let keys = lookup(network_id).ok_or(ProtocolError::UnknownNetwork)?;

    let peer = conn.remote_id();
    let network_bytes = hello.network_id;
    let initiator = *peer.as_bytes();
    let responder = *local_id.as_bytes();
    let cb = channel_binding(conn, &network_bytes)?;

    let nonce_i = hello.nonce;
    let nonce_r = fresh_nonce();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        nonce: nonce_r,
    };
    write_frame(send, &encode(&ack)?, limits.max_frame_len).await?;

    let theirs: AuthProof = decode(&read_frame(recv, limits.max_frame_len).await?)?;
    verify(
        keys.auth_key(),
        ROLE_INITIATOR,
        PROTOCOL_VERSION,
        &network_bytes,
        &initiator,
        &responder,
        cb.as_ref(),
        &nonce_i,
        &nonce_r,
        &theirs.proof,
    )?;

    // Only now, after the peer proved membership, do we emit our own proof.
    let mine = proof(
        keys.auth_key(),
        ROLE_RESPONDER,
        PROTOCOL_VERSION,
        &network_bytes,
        &initiator,
        &responder,
        cb.as_ref(),
        &nonce_i,
        &nonce_r,
    );
    write_frame(
        send,
        &encode(&AuthProof { proof: mine })?,
        limits.max_frame_len,
    )
    .await?;

    Ok(HandshakeOutcome {
        network_id,
        peer,
        role: Role::Responder,
    })
}

/// Test-only re-export of [`channel_binding`]. See [`crate::test_support`].
#[doc(hidden)]
pub fn channel_binding_for_test(
    conn: &Connection,
    network_id: &[u8; 32],
) -> Result<[u8; 32], ProtocolError> {
    channel_binding(conn, network_id).map(|cb| *cb)
}

/// Test-only re-export of the proof function. See [`crate::test_support`].
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn proof_for_test(
    auth_key: &[u8; 32],
    role: &str,
    version: u16,
    network_id: &[u8; 32],
    initiator: &[u8; 32],
    responder: &[u8; 32],
    channel_binding: &[u8],
    nonce_initiator: &[u8; 16],
    nonce_responder: &[u8; 16],
) -> [u8; 32] {
    proof(
        auth_key,
        role,
        version,
        network_id,
        initiator,
        responder,
        channel_binding,
        nonce_initiator,
        nonce_responder,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// `(auth_key, network_id, initiator_id, responder_id, nonce_i, nonce_r)`
    type Fixture = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 16], [u8; 16]);

    fn fixture() -> Fixture {
        (
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 16], [6u8; 16],
        )
    }

    #[test]
    fn role_labels_produce_different_transcripts() {
        let (key, net, ini, res, ni, nr) = fixture();
        let cb = [7u8; 32];
        let a = proof(&key, ROLE_INITIATOR, 1, &net, &ini, &res, &cb, &ni, &nr);
        let b = proof(&key, ROLE_RESPONDER, 1, &net, &ini, &res, &cb, &ni, &nr);
        assert_ne!(a, b, "reflecting a proof back must not verify");
    }

    #[test]
    fn channel_binding_changes_the_proof() {
        let (key, net, ini, res, ni, nr) = fixture();
        let a = proof(
            &key,
            ROLE_INITIATOR,
            1,
            &net,
            &ini,
            &res,
            &[7u8; 32],
            &ni,
            &nr,
        );
        let b = proof(
            &key,
            ROLE_INITIATOR,
            1,
            &net,
            &ini,
            &res,
            &[8u8; 32],
            &ni,
            &nr,
        );
        assert_ne!(a, b, "a proof must not be replayable on another connection");
    }

    #[test]
    fn identities_and_network_are_bound() {
        let (key, net, ini, res, ni, nr) = fixture();
        let cb = [7u8; 32];
        let base = proof(&key, ROLE_INITIATOR, 1, &net, &ini, &res, &cb, &ni, &nr);
        let other_net = proof(
            &key,
            ROLE_INITIATOR,
            1,
            &[9u8; 32],
            &ini,
            &res,
            &cb,
            &ni,
            &nr,
        );
        let swapped = proof(&key, ROLE_INITIATOR, 1, &net, &res, &ini, &cb, &ni, &nr);
        assert_ne!(base, other_net);
        assert_ne!(base, swapped);
    }

    #[test]
    fn transcript_encoding_is_unambiguous() {
        // Two different field splits that would collide under naive concatenation.
        let a = transcript(
            "ab", 1, &[0u8; 32], &[0u8; 32], &[0u8; 32], b"cd", &[0u8; 16], &[0u8; 16],
        );
        let b = transcript(
            "a", 1, &[0u8; 32], &[0u8; 32], &[0u8; 32], b"bcd", &[0u8; 16], &[0u8; 16],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (key, net, ini, res, ni, nr) = fixture();
        let cb = [7u8; 32];
        let tag = proof(&key, ROLE_INITIATOR, 1, &net, &ini, &res, &cb, &ni, &nr);
        let wrong = [0xAAu8; 32];
        let result = verify(
            &wrong,
            ROLE_INITIATOR,
            1,
            &net,
            &ini,
            &res,
            &cb,
            &ni,
            &nr,
            &tag,
        );
        assert!(matches!(result, Err(ProtocolError::AuthenticationFailed)));
    }
}

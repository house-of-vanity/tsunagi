//! Scenarios 3 and 9: an attacker without the secret, and the protocol's
//! boundaries.
//!
//! These tests speak the wire protocol directly against a real agent, because
//! that is the only way to present a *correct* public network id with a wrong
//! proof, replay a captured proof on a second connection, or send a message
//! before authenticating.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{TestAgent, network, settle, wait_event};
use iroh::endpoint::{Connection, PortmapperConfig, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode};
use tsunagi::agent::Event;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkId, NetworkKeys, NetworkName, NetworkSecret};
use tsunagi::proto::handshake::{ROLE_INITIATOR, ROLE_RESPONDER};
use tsunagi::proto::message::{
    ALPN, AuthProof, ControlMessage, Envelope, Hello, HelloAck, PROTOCOL_VERSION, decode, encode,
};
use tsunagi::proto::{read_frame, write_frame};
use tsunagi::test_support;

/// A bare iroh endpoint with no tsunagi agent behind it.
async fn raw_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

async fn open_control_stream(
    endpoint: &Endpoint,
    target: EndpointAddr,
) -> (Connection, SendStream, RecvStream) {
    let conn = endpoint.connect(target, ALPN).await.unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();
    (conn, send, recv)
}

const LIMIT: usize = 64 * 1024;

/// Sends `Hello` and reads the responder's `HelloAck`.
async fn exchange_hellos(
    send: &mut SendStream,
    recv: &mut RecvStream,
    version: u16,
    network_id: NetworkId,
    nonce: [u8; 16],
) -> HelloAck {
    let hello = Hello {
        version,
        network_id: *network_id.as_bytes(),
        nonce,
    };
    write_frame(send, &encode(&hello).unwrap(), LIMIT)
        .await
        .unwrap();
    decode(&read_frame(recv, LIMIT).await.unwrap()).unwrap()
}

#[tokio::test]
async fn an_attacker_who_knows_the_public_network_id_is_still_rejected() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("closed-network");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    // The attacker knows the address and the correct *public* network id. It
    // does not know the secret, so it cannot compute a valid proof.
    let attacker = raw_endpoint().await;
    let (conn, mut send, mut recv) =
        open_control_stream(&attacker, victim.agent.local_addr()).await;

    let _ack = exchange_hellos(
        &mut send,
        &mut recv,
        PROTOCOL_VERSION,
        network_id,
        [9u8; 16],
    )
    .await;
    let bogus = AuthProof { proof: [0xAB; 32] };
    write_frame(&mut send, &encode(&bogus).unwrap(), LIMIT)
        .await
        .unwrap();

    // The responder must not reveal a proof of its own and must reject us.
    let reply = read_frame(&mut recv, LIMIT).await;
    assert!(
        reply.is_err(),
        "the agent must not answer an invalid proof, got {reply:?}"
    );

    let reason = wait_event(&mut events, |event| match event {
        Event::HandshakeRejected { reason, .. } => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(
        reason.contains("authentication failed"),
        "unexpected reason: {reason}"
    );

    // The victim is unharmed: no session, and the network is still running.
    let status = victim.agent.network_status(network_id).await.unwrap();
    assert!(status.peers.is_empty());
    assert_eq!(status.metrics.sessions_established, 0);

    conn.close(0u32.into(), b"done");
    attacker.close().await;
    victim.agent.shutdown().await;
}

#[tokio::test]
async fn a_wrong_secret_under_the_same_name_lands_in_a_different_space() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("same-name").unwrap();

    let good = TestAgent::spawn(&discovery).await.unwrap();
    let bad = TestAgent::spawn(&discovery).await.unwrap();

    let good_id = good
        .agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();
    let bad_id = bad
        .agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();
    assert_ne!(good_id, bad_id);

    // Even with discovery wired together, the two never form a session.
    //
    // This test only shows that discovery separated them; the authoritative
    // check that the secret itself gates membership is
    // `an_attacker_who_knows_the_public_network_id_is_still_rejected`.
    settle().await;
    let status = good.agent.network_status(good_id).await.unwrap();
    assert!(status.peers.is_empty());

    good.agent.shutdown().await;
    bad.agent.shutdown().await;
}

#[tokio::test]
async fn an_unsupported_protocol_version_is_rejected() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("versioned");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    let attacker = raw_endpoint().await;
    let (conn, mut send, mut recv) =
        open_control_stream(&attacker, victim.agent.local_addr()).await;

    let hello = Hello {
        version: PROTOCOL_VERSION + 7,
        network_id: *network_id.as_bytes(),
        nonce: [1u8; 16],
    };
    write_frame(&mut send, &encode(&hello).unwrap(), LIMIT)
        .await
        .unwrap();
    assert!(read_frame(&mut recv, LIMIT).await.is_err());

    let reason = wait_event(&mut events, |event| match event {
        Event::HandshakeRejected { reason, .. } => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(reason.contains("version"), "unexpected reason: {reason}");

    // The agent is still alive and usable afterwards.
    assert!(victim.agent.network_status(network_id).await.is_ok());

    conn.close(0u32.into(), b"done");
    attacker.close().await;
    victim.agent.shutdown().await;
}

#[tokio::test]
async fn a_control_message_before_authentication_is_rejected() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("no-early-messages");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    let attacker = raw_endpoint().await;
    let (conn, mut send, mut recv) =
        open_control_stream(&attacker, victim.agent.local_addr()).await;

    // A perfectly well formed control message, sent where a Hello belongs.
    let envelope = Envelope {
        network_id: *network_id.as_bytes(),
        message: ControlMessage::Ping {
            seq: 1,
            payload: b"too early".to_vec(),
        },
    };
    write_frame(&mut send, &encode(&envelope).unwrap(), LIMIT)
        .await
        .unwrap();
    assert!(read_frame(&mut recv, LIMIT).await.is_err());

    wait_event(&mut events, |event| match event {
        Event::HandshakeRejected { .. } => Some(()),
        _ => None,
    })
    .await;

    let status = victim.agent.network_status(network_id).await.unwrap();
    assert!(status.peers.is_empty());

    conn.close(0u32.into(), b"done");
    attacker.close().await;
    victim.agent.shutdown().await;
}

#[tokio::test]
async fn an_oversized_frame_is_rejected_before_it_is_allocated() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("bounded-frames");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    let attacker = raw_endpoint().await;
    let (conn, mut send, mut recv) =
        open_control_stream(&attacker, victim.agent.local_addr()).await;

    // Announce four gigabytes and then send nothing. The agent must reject the
    // header instead of allocating the buffer.
    send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(read_frame(&mut recv, LIMIT).await.is_err());

    wait_event(&mut events, |event| match event {
        Event::HandshakeRejected { reason, .. } if reason.contains("exceeds") => Some(()),
        _ => None,
    })
    .await;

    // Still serving other work.
    assert!(victim.agent.network_status(network_id).await.is_ok());

    conn.close(0u32.into(), b"done");
    attacker.close().await;
    victim.agent.shutdown().await;
}

#[tokio::test]
async fn a_proof_cannot_be_replayed_on_another_connection() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("channel-bound");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    // A legitimate member: it knows the secret and can compute real proofs.
    let keys = NetworkKeys::derive(&name, &secret);
    let auth_key = test_support::auth_key(&keys);
    let member = raw_endpoint().await;
    let local = *member.id().as_bytes();
    let remote = *victim.agent.endpoint_id().as_bytes();
    let network_bytes = *network_id.as_bytes();

    // Connection one: a genuine, successful handshake.
    let (conn1, mut send1, mut recv1) =
        open_control_stream(&member, victim.agent.local_addr()).await;
    let nonce_i = [11u8; 16];
    let ack1 = exchange_hellos(
        &mut send1,
        &mut recv1,
        PROTOCOL_VERSION,
        network_id,
        nonce_i,
    )
    .await;
    let cb1 = test_support::channel_binding(&conn1, &network_bytes).unwrap();
    let genuine = test_support::compute_proof(
        &auth_key,
        ROLE_INITIATOR,
        PROTOCOL_VERSION,
        &network_bytes,
        &local,
        &remote,
        &cb1,
        &nonce_i,
        &ack1.nonce,
    );
    write_frame(
        &mut send1,
        &encode(&AuthProof { proof: genuine }).unwrap(),
        LIMIT,
    )
    .await
    .unwrap();
    let their_proof: AuthProof = decode(&read_frame(&mut recv1, LIMIT).await.unwrap()).unwrap();

    // The responder proved membership too, and it used the responder role.
    let expected = test_support::compute_proof(
        &auth_key,
        ROLE_RESPONDER,
        PROTOCOL_VERSION,
        &network_bytes,
        &local,
        &remote,
        &cb1,
        &nonce_i,
        &ack1.nonce,
    );
    assert_eq!(their_proof.proof, expected, "responder proof must verify");
    assert_ne!(
        their_proof.proof, genuine,
        "roles must not produce the same proof, or it could be reflected"
    );

    // Connection two: replay the captured proof verbatim. The TLS exporter
    // differs per connection, so the proof no longer matches.
    let (conn2, mut send2, mut recv2) =
        open_control_stream(&member, victim.agent.local_addr()).await;
    let ack2 = exchange_hellos(
        &mut send2,
        &mut recv2,
        PROTOCOL_VERSION,
        network_id,
        nonce_i,
    )
    .await;
    let cb2 = test_support::channel_binding(&conn2, &network_bytes).unwrap();
    assert_ne!(cb1, cb2, "channel binding must differ between connections");
    let _ = ack2;

    write_frame(
        &mut send2,
        &encode(&AuthProof { proof: genuine }).unwrap(),
        LIMIT,
    )
    .await
    .unwrap();
    assert!(
        read_frame(&mut recv2, LIMIT).await.is_err(),
        "a replayed proof must be rejected"
    );

    let reason = wait_event(&mut events, |event| match event {
        Event::HandshakeRejected { reason, .. } if reason.contains("authentication failed") => {
            Some(reason.clone())
        }
        _ => None,
    })
    .await;
    assert!(reason.contains("authentication failed"));

    conn1.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    member.close().await;
    victim.agent.shutdown().await;
}

#[tokio::test]
async fn a_hello_for_an_inactive_network_is_rejected() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("active-only");

    let victim = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = victim.agent.subscribe();
    victim.agent.join_network(&name, &secret).await.unwrap();

    // A different, perfectly valid network space the victim is not in.
    let other = NetworkKeys::derive(
        &NetworkName::new("somewhere-else").unwrap(),
        &NetworkSecret::generate(),
    );

    let attacker = raw_endpoint().await;
    let (conn, mut send, mut recv) =
        open_control_stream(&attacker, victim.agent.local_addr()).await;
    let hello = Hello {
        version: PROTOCOL_VERSION,
        network_id: *other.network_id().as_bytes(),
        nonce: [3u8; 16],
    };
    write_frame(&mut send, &encode(&hello).unwrap(), LIMIT)
        .await
        .unwrap();
    assert!(read_frame(&mut recv, LIMIT).await.is_err());

    let reason = wait_event(&mut events, |event| match event {
        Event::HandshakeRejected {
            network, reason, ..
        } => {
            // Before a successful handshake the claimed network is unverified,
            // so it must not be reported as fact.
            assert!(network.is_none());
            Some(reason.clone())
        }
        _ => None,
    })
    .await;
    assert!(reason.contains("unknown"), "unexpected reason: {reason}");

    conn.close(0u32.into(), b"done");
    attacker.close().await;
    victim.agent.shutdown().await;
}

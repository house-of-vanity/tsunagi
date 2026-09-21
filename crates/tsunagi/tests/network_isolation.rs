//! Scenario 4: one agent in two networks at once, with no bleed between them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iroh::endpoint::{PortmapperConfig, presets};
use iroh::{Endpoint, RelayMode};
use tsunagi::agent::Event;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::NetworkKeys;
use tsunagi::proto::handshake::ROLE_INITIATOR;
use tsunagi::proto::message::{
    ALPN, AuthProof, ControlMessage, Envelope, Hello, HelloAck, PROTOCOL_VERSION, decode, encode,
};
use tsunagi::proto::{read_frame, write_frame};
use tsunagi::test_support;
use tsunagi::testing::{TestAgent, network, settle, wait_event, wait_for_peers};

const LIMIT: usize = 64 * 1024;

#[tokio::test]
async fn one_agent_in_two_networks_keeps_them_apart() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("alpha-net");
    let (name_b, secret_b) = network("beta-net");

    let hub = TestAgent::spawn(&discovery).await.unwrap();
    let alpha_peer = TestAgent::spawn(&discovery).await.unwrap();
    let beta_peer = TestAgent::spawn(&discovery).await.unwrap();

    let alpha = hub.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = hub.agent.join_network(&name_b, &secret_b).await.unwrap();
    assert_ne!(alpha, beta);

    alpha_peer
        .agent
        .join_network(&name_a, &secret_a)
        .await
        .unwrap();
    beta_peer
        .agent
        .join_network(&name_b, &secret_b)
        .await
        .unwrap();

    wait_for_peers(&hub.agent, alpha, 1).await;
    wait_for_peers(&hub.agent, beta, 1).await;

    // Statuses do not mix: each network sees exactly its own peer.
    let status_alpha = hub.agent.network_status(alpha).await.unwrap();
    let status_beta = hub.agent.network_status(beta).await.unwrap();
    assert_eq!(
        status_alpha.connected_peers(),
        vec![alpha_peer.agent.endpoint_id()]
    );
    assert_eq!(
        status_beta.connected_peers(),
        vec![beta_peer.agent.endpoint_id()]
    );

    // Addressing a peer of one network through the other is refused locally.
    let wrong = hub
        .agent
        .send(
            alpha,
            beta_peer.agent.endpoint_id(),
            ControlMessage::Ping {
                seq: 1,
                payload: Vec::new(),
            },
        )
        .await;
    assert!(matches!(wrong, Err(tsunagi::Error::NoSuchPeer { .. })));

    // Messages stay in their own network.
    let mut events = hub.agent.subscribe();
    hub.agent
        .broadcast(
            alpha,
            ControlMessage::Ping {
                seq: 7,
                payload: b"alpha-only".to_vec(),
            },
        )
        .await
        .unwrap();
    let from = wait_event(&mut events, |event| match event {
        Event::MessageReceived {
            network,
            peer,
            message: ControlMessage::Pong { seq: 7, payload },
        } if payload == b"alpha-only" => Some((*network, *peer)),
        _ => None,
    })
    .await;
    assert_eq!(from, (alpha, alpha_peer.agent.endpoint_id()));

    let beta_status = hub.agent.network_status(beta).await.unwrap();
    assert_eq!(
        beta_status.metrics.control_messages_received,
        beta_status.peers[0].control_messages_received,
        "beta's counters are its own"
    );
    assert!(
        beta_status
            .peers
            .iter()
            .all(|peer| peer.endpoint_id != alpha_peer.agent.endpoint_id())
    );

    // Deactivating one network must not disturb the other.
    hub.agent.deactivate_network(alpha).await.unwrap();
    assert!(hub.agent.network_status(alpha).await.is_err());
    wait_for_peers(&hub.agent, beta, 1).await;
    hub.agent
        .send(
            beta,
            beta_peer.agent.endpoint_id(),
            ControlMessage::Ping {
                seq: 8,
                payload: b"still-here".to_vec(),
            },
        )
        .await
        .unwrap();
    wait_event(&mut events, |event| match event {
        Event::MessageReceived {
            network,
            message: ControlMessage::Pong { seq: 8, .. },
            ..
        } if *network == beta => Some(()),
        _ => None,
    })
    .await;

    hub.agent.shutdown().await;
    alpha_peer.agent.shutdown().await;
    beta_peer.agent.shutdown().await;
}

#[tokio::test]
async fn an_authenticated_session_cannot_speak_for_another_network() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("session-scope-a");
    let (name_b, secret_b) = network("session-scope-b");

    let hub = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = hub.agent.subscribe();
    let alpha = hub.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = hub.agent.join_network(&name_b, &secret_b).await.unwrap();

    // A genuine member of `alpha`, driven by hand so it can misbehave.
    let keys = NetworkKeys::derive(&name_a, &secret_a);
    let auth_key = test_support::auth_key(&keys);
    let member = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();

    let conn = member.connect(hub.agent.local_addr(), ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let alpha_bytes = *alpha.as_bytes();
    let nonce_i = [5u8; 16];
    let hello = Hello {
        version: PROTOCOL_VERSION,
        network_id: alpha_bytes,
        nonce: nonce_i,
    };
    write_frame(&mut send, &encode(&hello).unwrap(), LIMIT)
        .await
        .unwrap();
    let ack: HelloAck = decode(&read_frame(&mut recv, LIMIT).await.unwrap()).unwrap();

    let cb = test_support::channel_binding(&conn, &alpha_bytes).unwrap();
    let proof = test_support::compute_proof(
        &auth_key,
        ROLE_INITIATOR,
        PROTOCOL_VERSION,
        &alpha_bytes,
        member.id().as_bytes(),
        hub.agent.endpoint_id().as_bytes(),
        &cb,
        &nonce_i,
        &ack.nonce,
    );
    write_frame(&mut send, &encode(&AuthProof { proof }).unwrap(), LIMIT)
        .await
        .unwrap();
    let _responder_proof: AuthProof = decode(&read_frame(&mut recv, LIMIT).await.unwrap()).unwrap();

    // Authenticated for alpha. Now try to speak for beta on the same session.
    let smuggled = Envelope {
        network_id: *beta.as_bytes(),
        message: ControlMessage::Ping {
            seq: 99,
            payload: b"wrong network".to_vec(),
        },
    };
    write_frame(&mut send, &encode(&smuggled).unwrap(), LIMIT)
        .await
        .unwrap();

    let reason = wait_event(&mut events, |event| match event {
        Event::ProtocolViolation {
            network, reason, ..
        } if *network == Some(alpha) => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(
        reason.contains("network id does not match"),
        "unexpected reason: {reason}"
    );

    // Beta saw nothing at all, and both networks keep running.
    let beta_status = hub.agent.network_status(beta).await.unwrap();
    assert_eq!(beta_status.metrics.control_messages_received, 0);
    assert!(beta_status.peers.is_empty());
    assert!(hub.agent.network_status(alpha).await.is_ok());

    conn.close(0u32.into(), b"done");
    member.close().await;
    hub.agent.shutdown().await;
}

#[tokio::test]
async fn deactivating_one_network_leaves_the_agent_and_others_running() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("keep-a");
    let (name_b, secret_b) = network("keep-b");

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let alpha = agent.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = agent.agent.join_network(&name_b, &secret_b).await.unwrap();

    agent.agent.deactivate_network(alpha).await.unwrap();
    settle().await;

    let status = agent.agent.status().await.unwrap();
    assert_eq!(status.networks.len(), 2, "both stay configured");
    assert_eq!(
        status.network(&alpha).map(|net| net.state),
        Some(tsunagi::agent::NetworkState::Inactive)
    );
    assert_eq!(
        status.network(&beta).map(|net| net.state),
        Some(tsunagi::agent::NetworkState::Active)
    );

    // Deactivating twice is an error, not a crash.
    assert!(agent.agent.deactivate_network(alpha).await.is_err());
    // And it can be brought back.
    agent.agent.activate_network(alpha).await.unwrap();
    assert!(agent.agent.network_status(alpha).await.is_ok());

    agent.agent.shutdown().await;
}

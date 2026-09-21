//! The full vertical slice: persistent identity, network space, discovery,
//! real iroh connections, authentication and a control message exchange.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{TestAgent, network, wait_event, wait_for_peers};
use tsunagi::agent::Event;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::proto::ControlMessage;

#[tokio::test]
async fn two_agents_authenticate_and_exchange_messages() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("vertical-slice");

    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();

    let mut events_a = a.agent.subscribe();
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    let same_id = b.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(
        network_id, same_id,
        "the same name and secret must produce the same network space"
    );

    let peers = wait_for_peers(&a.agent, network_id, 1).await;
    assert_eq!(peers, vec![b.agent.endpoint_id()]);

    // The exchange itself: a ping must come back as a matching pong.
    a.agent
        .send(
            network_id,
            b.agent.endpoint_id(),
            ControlMessage::Ping {
                seq: 42,
                payload: b"vertical".to_vec(),
            },
        )
        .await
        .unwrap();

    let payload = wait_event(&mut events_a, |event| match event {
        Event::MessageReceived {
            network,
            peer,
            message: ControlMessage::Pong { seq: 42, payload },
        } if *network == network_id && *peer == b.agent.endpoint_id() => Some(payload.clone()),
        _ => None,
    })
    .await;
    assert_eq!(payload, b"vertical".to_vec());

    // Both sides announce a hostname over the authenticated session.
    let status = a.agent.network_status(network_id).await.unwrap();
    let peer = &status.peers[0];
    assert_eq!(peer.hostname.as_deref(), Some(b.agent.hostname().as_str()));
    assert!(peer.transport != tsunagi::net::TransportKind::Unknown);
    assert!(peer.rtt.is_some(), "a verified path must report an RTT");

    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

//! Scenarios 5 and 6: restart recovery and rotating the network secret.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{TestAgent, config_with, network, settle, wait_event, wait_for_peers};
use tsunagi::agent::Event;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::proto::ControlMessage;
use tsunagi::{Agent, Error};

#[tokio::test]
async fn a_restarted_agent_keeps_its_identity_and_reconnects() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("survives-restart");

    let peer = TestAgent::spawn(&discovery).await.unwrap();
    let restarting = TestAgent::spawn(&discovery).await.unwrap();

    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    restarting.agent.join_network(&name, &secret).await.unwrap();

    wait_for_peers(&peer.agent, network_id, 1).await;
    let device_id = restarting.agent.endpoint_id();
    let old_sockets = restarting.agent.status().await.unwrap().bound_sockets;

    let mut peer_events = peer.agent.subscribe();
    let dir = restarting.stop().await;

    // The surviving peer notices the session ending.
    wait_event(&mut peer_events, |event| match event {
        Event::PeerDisconnected { peer, .. } if *peer == device_id => Some(()),
        _ => None,
    })
    .await;

    // Restart from the same state directory. Binding to port zero again means a
    // different local UDP port, which the refreshed discovery entry covers.
    let restarted = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(restarted.endpoint_id(), device_id);
    let new_sockets = restarted.status().await.unwrap().bound_sockets;
    assert_ne!(old_sockets, new_sockets, "a fresh local port is expected");

    // The configured network came back up on its own and both sides reconnect.
    assert!(restarted.is_active(network_id).await);
    wait_for_peers(&restarted, network_id, 1).await;
    wait_for_peers(&peer.agent, network_id, 1).await;

    // And the restored session really works.
    restarted
        .send(
            network_id,
            peer.agent.endpoint_id(),
            ControlMessage::Ping {
                seq: 5,
                payload: b"back".to_vec(),
            },
        )
        .await
        .unwrap();
    let mut events = restarted.subscribe();
    wait_event(&mut events, |event| match event {
        Event::MessageReceived {
            message: ControlMessage::Pong { seq: 5, payload },
            ..
        } if payload == b"back" => Some(()),
        _ => None,
    })
    .await;

    restarted.shutdown().await;
    peer.agent.shutdown().await;
    drop(restarted);
    drop(dir);
}

#[tokio::test]
async fn joining_a_network_twice_is_not_an_error() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("idempotent-join");

    let agent = TestAgent::spawn(&discovery).await.unwrap();

    // Joining is declarative: saying it twice in one run must be fine.
    let first = agent.agent.join_network(&name, &secret).await.unwrap();
    let again = agent.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(first, again);
    assert_eq!(agent.agent.list_networks().await.unwrap().len(), 1);

    // Activating explicitly is the strict version and does report it.
    assert!(matches!(
        agent.agent.activate_network(first).await,
        Err(Error::NetworkAlreadyActive(_))
    ));

    // And after a restart, where the network came back up on its own, the
    // same command must still succeed. This is what running the CLI twice
    // does.
    let dir = agent.stop().await;
    let restarted = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert!(restarted.is_active(first).await, "auto-start brought it up");
    let rejoined = restarted.join_network(&name, &secret).await.unwrap();
    assert_eq!(rejoined, first);
    assert!(restarted.network_status(first).await.is_ok());

    restarted.shutdown().await;
    drop(restarted);
    drop(dir);
}

#[tokio::test]
async fn readiness_does_not_wait_for_anyone_else() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("lonely");

    // No peers exist and no relay is reachable. The agent must still come up.
    let alone = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = alone.agent.join_network(&name, &secret).await.unwrap();

    let status = alone.agent.network_status(network_id).await.unwrap();
    assert!(status.peers.is_empty());
    assert_eq!(status.state, tsunagi::agent::NetworkState::Active);

    alone.agent.shutdown().await;
}

#[tokio::test]
async fn rotating_the_secret_moves_everyone_to_a_new_space() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("rotate-me").unwrap();
    let old_secret = NetworkSecret::generate();
    let new_secret = NetworkSecret::generate();

    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let a_id = a.agent.endpoint_id();

    let old = a.agent.join_network(&name, &old_secret).await.unwrap();
    b.agent.join_network(&name, &old_secret).await.unwrap();
    wait_for_peers(&a.agent, old, 1).await;

    // Rotation through the public API: deactivate the old space, join the new.
    // No dedicated command is needed for this.
    a.agent.deactivate_network(old).await.unwrap();
    let new = a.agent.join_network(&name, &new_secret).await.unwrap();
    assert_ne!(old, new);
    assert_eq!(a.agent.endpoint_id(), a_id, "device identity is untouched");

    // B still holds the old secret, so it must not reach the new space.
    settle().await;
    let status = a.agent.network_status(new).await.unwrap();
    assert!(
        status.peers.is_empty(),
        "the old secret must not open the new space"
    );
    assert!(
        a.agent
            .send(
                old,
                b.agent.endpoint_id(),
                ControlMessage::Ping {
                    seq: 1,
                    payload: Vec::new()
                }
            )
            .await
            .is_err(),
        "the deactivated network cannot be used any more"
    );

    // Once B rotates too, they meet again in the new space.
    b.agent.deactivate_network(old).await.unwrap();
    let b_new = b.agent.join_network(&name, &new_secret).await.unwrap();
    assert_eq!(b_new, new);
    wait_for_peers(&a.agent, new, 1).await;

    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn a_rotated_out_network_does_not_come_back_after_a_restart() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("no-resurrection").unwrap();

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let old = agent
        .agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();
    let new = agent
        .agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();
    agent.agent.deactivate_network(old).await.unwrap();
    let dir = agent.stop().await;

    let restarted = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert!(!restarted.is_active(old).await);
    assert!(restarted.is_active(new).await);
    assert!(matches!(
        restarted.network_status(old).await,
        Err(Error::NetworkNotActive(_))
    ));

    restarted.shutdown().await;
    drop(restarted);
    drop(dir);
}

//! Scenarios 8 and 10: unreachable participants, bounded retries, and the
//! agent lifecycle including state directory ownership.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{TestAgent, config_with, local_config, network, settle, wait_event, wait_for_peers};
use iroh::{EndpointAddr, SecretKey};
use tsunagi::agent::Event;
use tsunagi::config::ReconnectPolicy;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::NetworkKeys;
use tsunagi::proto::ControlMessage;
use tsunagi::{Agent, Error};

/// An endpoint id nobody is listening for, at an address nothing answers on.
fn dead_candidate() -> EndpointAddr {
    let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
    EndpointAddr::new(SecretKey::generate().public()).with_ip_addr(unreachable)
}

#[tokio::test]
async fn a_dead_candidate_does_not_hold_up_the_reachable_ones() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("dead-candidate");
    let keys = NetworkKeys::derive(&name, &secret);

    // Poison the rendezvous table before anybody real shows up.
    let dead = dead_candidate();
    discovery.insert_raw(keys.discovery_key(), dead.clone());

    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let mut events = a.agent.subscribe();

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();

    // The reachable peer still connects.
    let peers = wait_for_peers(&a.agent, network_id, 1).await;
    assert_eq!(peers, vec![b.agent.endpoint_id()]);

    // And the dead candidate is reported as a failure, not silently forgotten.
    wait_event(&mut events, |event| match event {
        Event::DialFailed { peer, .. } if *peer == dead.id => Some(()),
        _ => None,
    })
    .await;

    let status = a.agent.network_status(network_id).await.unwrap();
    assert!(
        status
            .candidates
            .iter()
            .any(|candidate| candidate.endpoint_id == dead.id
                && candidate.consecutive_failures > 0),
        "a failing candidate must stay visible as an unverified candidate"
    );
    assert!(
        status.peers.iter().all(|peer| peer.endpoint_id != dead.id),
        "a candidate must never be reported as a peer"
    );

    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn a_vanished_peer_is_retried_with_backoff_and_others_keep_working() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("vanishing-peer");

    let watcher = TestAgent::spawn_with(
        |cfg| {
            cfg.with_reconnect(ReconnectPolicy {
                initial_delay: Duration::from_millis(50),
                max_delay: Duration::from_millis(200),
                factor: 1.5,
                jitter: 0.2,
                max_consecutive_failures: None,
            })
        },
        &discovery,
    )
    .await
    .unwrap();
    let stayer = TestAgent::spawn(&discovery).await.unwrap();
    let leaver = TestAgent::spawn(&discovery).await.unwrap();

    let network_id = watcher.agent.join_network(&name, &secret).await.unwrap();
    stayer.agent.join_network(&name, &secret).await.unwrap();
    leaver.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&watcher.agent, network_id, 2).await;

    let leaver_id = leaver.agent.endpoint_id();
    let mut events = watcher.agent.subscribe();
    leaver.agent.shutdown().await;
    drop(leaver);

    wait_event(&mut events, |event| match event {
        Event::PeerDisconnected { peer, .. } if *peer == leaver_id => Some(()),
        _ => None,
    })
    .await;

    // The other peer is untouched and still answers.
    watcher
        .agent
        .send(
            network_id,
            stayer.agent.endpoint_id(),
            ControlMessage::Ping {
                seq: 3,
                payload: b"still here".to_vec(),
            },
        )
        .await
        .unwrap();
    wait_event(&mut events, |event| match event {
        Event::MessageReceived {
            peer,
            message: ControlMessage::Pong { seq: 3, .. },
            ..
        } if *peer == stayer.agent.endpoint_id() => Some(()),
        _ => None,
    })
    .await;

    // The watcher does retry the peer that went away.
    wait_event(&mut events, |event| match event {
        Event::DialFailed { peer, .. } if *peer == leaver_id => Some(()),
        _ => None,
    })
    .await;

    // Retries are bounded by the backoff rather than spinning.
    settle().await;
    let status = watcher.agent.network_status(network_id).await.unwrap();
    let failures = status
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint_id == leaver_id)
        .map(|candidate| candidate.consecutive_failures)
        .unwrap_or(0);
    assert!(
        (1..=40).contains(&failures),
        "expected bounded backed-off retries, got {failures}"
    );
    assert_eq!(
        status.connected_peers(),
        vec![stayer.agent.endpoint_id()],
        "the surviving peer keeps its session"
    );

    watcher.agent.shutdown().await;
    stayer.agent.shutdown().await;
}

#[tokio::test]
async fn retries_stop_when_the_network_is_deactivated() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("stop-retrying");
    let keys = NetworkKeys::derive(&name, &secret);
    discovery.insert_raw(keys.discovery_key(), dead_candidate());

    let agent = TestAgent::spawn_with(
        |cfg| {
            cfg.with_discovery_interval(Duration::from_millis(80))
                .with_reconnect(ReconnectPolicy {
                    initial_delay: Duration::from_millis(20),
                    max_delay: Duration::from_millis(60),
                    factor: 1.2,
                    jitter: 0.1,
                    max_consecutive_failures: None,
                })
        },
        &discovery,
    )
    .await
    .unwrap();

    let mut events = agent.agent.subscribe();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();

    // Retries are definitely happening.
    wait_event(&mut events, |event| match event {
        Event::DialFailed { .. } => Some(()),
        _ => None,
    })
    .await;

    agent.agent.deactivate_network(network_id).await.unwrap();

    // Drain whatever was already queued, then require silence.
    while events.try_recv().is_ok() {}
    settle().await;
    let mut stragglers = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(event, Event::DialFailed { .. }) {
            stragglers += 1;
        }
    }
    assert_eq!(
        stragglers, 0,
        "a deactivated network must stop dialling entirely"
    );

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn a_second_agent_on_the_same_state_directory_is_refused() {
    let discovery = SharedMemoryDiscovery::new();
    let dir = tempfile::TempDir::new().unwrap();

    let first = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();

    let second = Agent::spawn(config_with(dir.path(), &discovery)).await;
    match second {
        Err(Error::StateLocked { path }) => {
            assert!(path.starts_with(dir.path()));
        }
        Err(other) => panic!("expected StateLocked, got {other:?}"),
        Ok(agent) => {
            agent.shutdown().await;
            panic!("two live agents must not share one state directory");
        }
    }

    // After a clean stop the directory is immediately claimable again.
    let device_id = first.endpoint_id();
    first.shutdown().await;
    drop(first);

    let third = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(third.endpoint_id(), device_id);
    third.shutdown().await;
    drop(third);
    drop(dir);
}

#[tokio::test]
async fn shutdown_releases_resources_and_rejects_further_work() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("clean-stop");

    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, network_id, 1).await;

    a.agent.shutdown().await;

    // The endpoint is closed and the networks are gone.
    assert!(a.agent.endpoint().is_closed());
    assert!(matches!(
        a.agent.network_status(network_id).await,
        Err(Error::NetworkNotActive(_))
    ));
    assert!(
        a.agent
            .send(
                network_id,
                b.agent.endpoint_id(),
                ControlMessage::Ping {
                    seq: 1,
                    payload: Vec::new()
                }
            )
            .await
            .is_err()
    );

    // Shutting down twice is harmless.
    a.agent.shutdown().await;

    // The peer notices and carries on.
    let status = b.agent.network_status(network_id).await.unwrap();
    assert_eq!(status.state, tsunagi::agent::NetworkState::Active);

    b.agent.shutdown().await;
}

#[tokio::test]
async fn several_independent_agents_coexist_in_one_process() {
    // No global state: two completely separate rendezvous tables, two networks
    // with the same name but different secrets, four agents, one process.
    let left = SharedMemoryDiscovery::new();
    let right = SharedMemoryDiscovery::new();
    let (name, left_secret) = network("same-name-different-world");
    let (_, right_secret) = network("ignored");

    let l1 = TestAgent::spawn(&left).await.unwrap();
    let l2 = TestAgent::spawn(&left).await.unwrap();
    let r1 = TestAgent::spawn(&right).await.unwrap();
    let r2 = TestAgent::spawn(&right).await.unwrap();

    let left_id = l1.agent.join_network(&name, &left_secret).await.unwrap();
    l2.agent.join_network(&name, &left_secret).await.unwrap();
    let right_id = r1.agent.join_network(&name, &right_secret).await.unwrap();
    r2.agent.join_network(&name, &right_secret).await.unwrap();
    assert_ne!(left_id, right_id);

    wait_for_peers(&l1.agent, left_id, 1).await;
    wait_for_peers(&r1.agent, right_id, 1).await;
    assert_eq!(
        l1.agent
            .network_status(left_id)
            .await
            .unwrap()
            .connected_peers(),
        vec![l2.agent.endpoint_id()]
    );

    for agent in [l1, l2, r1, r2] {
        agent.agent.shutdown().await;
    }
}

#[tokio::test]
async fn an_agent_without_discovery_still_starts_and_serves_status() {
    let dir = tempfile::TempDir::new().unwrap();
    let agent = Agent::spawn(local_config(dir.path())).await.unwrap();
    let (name, secret) = network("no-discovery");
    let network_id = agent.join_network(&name, &secret).await.unwrap();

    let status = agent.network_status(network_id).await.unwrap();
    assert!(status.peers.is_empty());
    assert!(status.candidates.is_empty());
    agent.recheck().await;
    assert!(agent.recheck_network(network_id).await.is_ok());

    agent.shutdown().await;
    drop(agent);
    drop(dir);
}

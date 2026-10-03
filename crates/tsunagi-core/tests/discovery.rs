//! Discovery backends: static bootstrap candidates, composition, and the fact
//! that discovery only ever supplies *candidates*.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use tsunagi::Agent;
use tsunagi::discovery::{
    CandidateSource, CompositeDiscovery, NetworkDiscovery, SharedMemoryDiscovery, StaticBootstrap,
};
use tsunagi::identity::NetworkKeys;
use tsunagi::testing::{TestAgent, local_config, network, settle, wait_for_peers};

#[tokio::test]
async fn a_static_bootstrap_candidate_is_enough_to_join() {
    let (name, secret) = network("bootstrap-only");

    // The listener runs with no discovery at all: it only accepts.
    let listener_dir = tempfile::TempDir::new().unwrap();
    let listener = Agent::spawn(local_config(listener_dir.path()))
        .await
        .unwrap();
    let network_id = listener.join_network(&name, &secret).await.unwrap();

    // The joiner is handed the listener's iroh id and addresses up front, which
    // is exactly what a static bootstrap entry is.
    let bootstrap = Arc::new(StaticBootstrap::new([listener.local_addr()]));
    let joiner_dir = tempfile::TempDir::new().unwrap();
    let joiner = Agent::spawn(local_config(joiner_dir.path()).with_discovery(bootstrap))
        .await
        .unwrap();
    joiner.join_network(&name, &secret).await.unwrap();

    wait_for_peers(&joiner, network_id, 1).await;
    wait_for_peers(&listener, network_id, 1).await;

    let status = joiner.network_status(network_id).await.unwrap();
    assert_eq!(
        status
            .candidates
            .iter()
            .find(|candidate| candidate.endpoint_id == listener.endpoint_id())
            .map(|candidate| candidate.source),
        Some(CandidateSource::Bootstrap)
    );

    joiner.shutdown().await;
    listener.shutdown().await;
    drop(joiner);
    drop(listener);
    drop(joiner_dir);
    drop(listener_dir);
}

#[tokio::test]
async fn a_composite_backend_merges_its_sources() {
    let (name, secret) = network("composite");
    let keys = NetworkKeys::derive(&name, &secret);

    let shared = SharedMemoryDiscovery::new();
    let via_shared = TestAgent::spawn(&shared).await.unwrap();
    let network_id = via_shared.agent.join_network(&name, &secret).await.unwrap();

    let bootstrap_dir = tempfile::TempDir::new().unwrap();
    let via_bootstrap = Agent::spawn(local_config(bootstrap_dir.path()))
        .await
        .unwrap();
    via_bootstrap.join_network(&name, &secret).await.unwrap();

    // One backend knows the bootstrap peer, the other knows the shared-table
    // peer. Composed, the joiner reaches both.
    let composite = Arc::new(CompositeDiscovery::new([
        Arc::new(StaticBootstrap::new([via_bootstrap.local_addr()])) as Arc<dyn NetworkDiscovery>,
        Arc::new(shared.clone()) as Arc<dyn NetworkDiscovery>,
    ]));
    let joiner_dir = tempfile::TempDir::new().unwrap();
    let joiner = Agent::spawn(local_config(joiner_dir.path()).with_discovery(composite))
        .await
        .unwrap();
    joiner.join_network(&name, &secret).await.unwrap();

    wait_for_peers(&joiner, network_id, 2).await;

    // Publishing went to the shared backend, so the other agent finds us too.
    assert!(shared.len(&keys.discovery_key()) >= 2);

    joiner.shutdown().await;
    via_bootstrap.shutdown().await;
    via_shared.agent.shutdown().await;
    drop(joiner);
    drop(via_bootstrap);
    drop(joiner_dir);
    drop(bootstrap_dir);
}

#[tokio::test]
async fn discovery_entries_are_withdrawn_when_a_network_stops() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("withdrawn");
    let keys = NetworkKeys::derive(&name, &secret);

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();

    settle().await;
    assert_eq!(discovery.len(&keys.discovery_key()), 1);

    agent.agent.deactivate_network(network_id).await.unwrap();
    assert!(discovery.is_empty(&keys.discovery_key()));

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn forgetting_a_network_removes_it_from_the_state_store() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("forgettable");

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(agent.agent.list_networks().await.unwrap().len(), 1);

    agent.agent.forget_network(network_id).await.unwrap();
    assert!(agent.agent.list_networks().await.unwrap().is_empty());
    assert!(!agent.agent.is_active(network_id).await);

    let dir = agent.stop().await;
    let restarted =
        Agent::spawn(local_config(dir.path()).with_discovery(Arc::new(discovery.clone())))
            .await
            .unwrap();
    assert!(restarted.list_networks().await.unwrap().is_empty());
    assert_eq!(restarted.status().await.unwrap().networks.len(), 0);

    restarted.shutdown().await;
    drop(restarted);
    drop(dir);
}

#[tokio::test]
async fn being_told_about_one_member_is_enough_to_meet_them_all() {
    // A network is a mesh, and which member happened to be named on a
    // command line must not decide who a device ends up talking to. The
    // newcomer is given one address and nothing else; everybody else is
    // learned from the members it meets.
    let (name, secret) = network("introductions");

    // Three that already know each other, and nothing that resolves by
    // network: no shared discovery here, only what members pass on.
    let first_dir = tempfile::TempDir::new().unwrap();
    let first = Agent::spawn(local_config(first_dir.path())).await.unwrap();
    let network_id = first.join_network(&name, &secret).await.unwrap();

    let second_dir = tempfile::TempDir::new().unwrap();
    let second = Agent::spawn(
        local_config(second_dir.path())
            .with_discovery(Arc::new(StaticBootstrap::new([first.local_addr()]))),
    )
    .await
    .unwrap();
    second.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&first, network_id, 1).await;

    let third_dir = tempfile::TempDir::new().unwrap();
    let third = Agent::spawn(
        local_config(third_dir.path())
            .with_discovery(Arc::new(StaticBootstrap::new([first.local_addr()]))),
    )
    .await
    .unwrap();
    third.join_network(&name, &secret).await.unwrap();

    // Each of the two newcomers was given only the first one's address,
    // and each ends up with both of the others.
    wait_for_peers(&second, network_id, 2).await;
    wait_for_peers(&third, network_id, 2).await;
    wait_for_peers(&first, network_id, 2).await;

    // And the one they were not told about is there as an introduction:
    // a candidate like any other, still authenticated by the handshake.
    let status = second.network_status(network_id).await.unwrap();
    let introduced = status
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint_id == third.endpoint_id())
        .map(|candidate| candidate.source);
    assert!(
        matches!(
            introduced,
            Some(CandidateSource::Introduced) | Some(CandidateSource::Member)
        ),
        "the third should have arrived from the others: {introduced:?}"
    );

    second.shutdown().await;
    third.shutdown().await;
    first.shutdown().await;
}

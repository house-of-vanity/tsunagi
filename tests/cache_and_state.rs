//! Scenario 7: the disposable cache and the mandatory state store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;

use common::{TestAgent, config_with, local_config, network, wait_for_peers};
use tsunagi::config::StoragePaths;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::storage::CacheOutcome;
use tsunagi::{Agent, Error};

/// Overwrites a file with bytes that are definitely not a SQLite database.
fn corrupt(path: &std::path::Path) {
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(&[0x7f; 8192]).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn a_missing_cache_is_recreated_and_does_not_block_connecting() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("missing-cache");

    let peer = TestAgent::spawn(&discovery).await.unwrap();
    let subject = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&peer.agent, network_id, 1).await;

    let dir = subject.stop().await;
    let paths = StoragePaths::under(dir.path());
    std::fs::remove_dir_all(&paths.cache_dir).unwrap();
    assert!(!paths.cache_db().exists());

    let restarted = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(
        restarted.status().await.unwrap().cache_outcome,
        CacheOutcome::Created
    );
    wait_for_peers(&restarted, network_id, 1).await;

    restarted.shutdown().await;
    peer.agent.shutdown().await;
    drop(restarted);
    drop(dir);
}

#[tokio::test]
async fn a_corrupt_cache_is_discarded_and_does_not_block_connecting() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("corrupt-cache");

    let peer = TestAgent::spawn(&discovery).await.unwrap();
    let subject = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&peer.agent, network_id, 1).await;

    let device_id = subject.agent.endpoint_id();
    let dir = subject.stop().await;
    let paths = StoragePaths::under(dir.path());
    corrupt(&paths.cache_db());

    let restarted = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    let status = restarted.status().await.unwrap();
    assert!(
        matches!(status.cache_outcome, CacheOutcome::Reset(_)),
        "expected the cache to be discarded, got {:?}",
        status.cache_outcome
    );
    assert!(status.cache_healthy);
    assert_eq!(
        restarted.endpoint_id(),
        device_id,
        "a bad cache must not touch the identity"
    );
    wait_for_peers(&restarted, network_id, 1).await;

    restarted.shutdown().await;
    peer.agent.shutdown().await;
    drop(restarted);
    drop(dir);
}

#[tokio::test]
async fn a_stale_cache_does_not_prevent_connecting_through_discovery() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("stale-cache");

    let peer = TestAgent::spawn(&discovery).await.unwrap();
    let subject = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&peer.agent, network_id, 1).await;

    // Stop both. When they come back they bind new ports, so every cached
    // address hint is stale, and only fresh discovery can bridge the gap.
    let peer_dir = peer.stop().await;
    let subject_dir = subject.stop().await;
    assert!(
        StoragePaths::under(subject_dir.path()).cache_db().exists(),
        "hints were written, so the cache is genuinely stale now"
    );

    let peer_again = Agent::spawn(config_with(peer_dir.path(), &discovery))
        .await
        .unwrap();
    let subject_again = Agent::spawn(config_with(subject_dir.path(), &discovery))
        .await
        .unwrap();

    wait_for_peers(&subject_again, network_id, 1).await;
    wait_for_peers(&peer_again, network_id, 1).await;

    peer_again.shutdown().await;
    subject_again.shutdown().await;
    drop(peer_again);
    drop(subject_again);
    drop(peer_dir);
    drop(subject_dir);
}

#[tokio::test]
async fn a_corrupt_state_store_is_an_error_and_never_a_fresh_identity() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("corrupt-state");

    let subject = TestAgent::spawn(&discovery).await.unwrap();
    let device_id = subject.agent.endpoint_id();
    subject.agent.join_network(&name, &secret).await.unwrap();
    let dir = subject.stop().await;

    let paths = StoragePaths::under(dir.path());
    corrupt(&paths.state_db());

    let result = Agent::spawn(config_with(dir.path(), &discovery)).await;
    match result {
        Err(Error::StateCorrupted { path, reason }) => {
            assert_eq!(path, paths.state_db());
            assert!(!reason.is_empty());
        }
        Err(other) => panic!("expected StateCorrupted, got {other:?}"),
        Ok(agent) => {
            let new_id = agent.endpoint_id();
            agent.shutdown().await;
            panic!(
                "a corrupt state store must not yield a working agent (id {new_id}) — the previous identity was {device_id}"
            );
        }
    }

    drop(dir);
}

#[tokio::test]
async fn a_state_store_from_a_newer_build_is_refused() {
    let dir = tempfile::TempDir::new().unwrap();
    let paths = StoragePaths::under(dir.path());
    std::fs::create_dir_all(&paths.state_dir).unwrap();

    {
        let conn = rusqlite::Connection::open(paths.state_db()).unwrap();
        conn.pragma_update(None, "user_version", 999i64).unwrap();
    }

    let result = Agent::spawn(local_config(dir.path())).await;
    assert!(
        matches!(result, Err(Error::UnsupportedSchema { found: 999, .. })),
        "expected UnsupportedSchema"
    );
}

#[tokio::test]
async fn secrets_never_appear_in_status_or_debug_output() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("no-leaks");

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();

    let status = agent.agent.status().await.unwrap();
    let rendered = format!("{status:?}");
    let encoded = secret.encode();
    assert!(!rendered.contains(encoded.as_str()));
    assert!(rendered.contains(&network_id.to_string()) || rendered.contains("NetworkId"));

    let network_status = agent.agent.network_status(network_id).await.unwrap();
    assert!(!format!("{network_status:?}").contains(encoded.as_str()));

    let keys = tsunagi::identity::NetworkKeys::derive(&name, &secret);
    let keys_debug = format!("{keys:?}");
    assert!(keys_debug.contains("<redacted>"));
    assert!(!keys_debug.contains(encoded.as_str()));

    agent.agent.shutdown().await;
}

//! Scenario 7: the disposable cache and the mandatory state store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;

use tsunagi::config::StoragePaths;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::storage::CacheOutcome;
use tsunagi::testing::{TestAgent, config_with, local_config, network, wait_for_peers};
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

/// A store written by the previous schema must come up, not break.
///
/// The record body gained a hostname, which changed the signing domain, so
/// records written before it can never verify again. Leaving them in place
/// would mean every read rejecting rows that look exactly like corruption.
#[tokio::test]
async fn a_state_store_from_the_previous_schema_is_migrated_and_stays_usable() {
    let dir = tempfile::TempDir::new().unwrap();
    let paths = StoragePaths::under(dir.path());
    std::fs::create_dir_all(&paths.state_dir).unwrap();

    // Build a schema-2 store by hand, with a record in it.
    {
        let conn = rusqlite::Connection::open(paths.state_db()).unwrap();
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE device_identity (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 secret_key BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE networks (
                 network_id BLOB PRIMARY KEY,
                 name TEXT NOT NULL,
                 secret BLOB NOT NULL,
                 auto_start INTEGER NOT NULL DEFAULT 1,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE signed_records (
                 network_id BLOB NOT NULL,
                 author BLOB NOT NULL,
                 version INTEGER NOT NULL,
                 body BLOB NOT NULL,
                 signature BLOB NOT NULL,
                 PRIMARY KEY (network_id, author)
             );
             CREATE TABLE own_record_version (
                 network_id BLOB PRIMARY KEY,
                 version INTEGER NOT NULL
             );
             INSERT INTO signed_records VALUES (x'00', x'11', 7, x'2222', x'3333');
             INSERT INTO own_record_version VALUES (x'00', 7);
             PRAGMA user_version = 2;
             COMMIT;",
        )
        .unwrap();
    }

    // An agent comes up on it, which is the whole point.
    let discovery = SharedMemoryDiscovery::new();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    let (name, secret) = network("migrated");
    let network_id = agent.join_network(&name, &secret).await.unwrap();
    assert!(agent.network_status(network_id).await.is_ok());
    agent.shutdown().await;

    let conn = rusqlite::Connection::open(paths.state_db()).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, tsunagi::storage::SCHEMA_VERSION);

    // The unverifiable record is gone rather than left to be rejected for
    // ever, and the counter is keyed by author now.
    let stale: i64 = conn
        .query_row(
            "SELECT count(*) FROM signed_records WHERE author = x'11'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stale, 0, "records from the old signing domain are dropped");
    conn.query_row(
        "SELECT count(*) FROM own_record_version WHERE author IS NOT NULL",
        [],
        |row| row.get::<_, i64>(0),
    )
    .expect("the counter is keyed by author");
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

#[tokio::test]
async fn a_wipe_removes_everything_and_the_next_start_is_a_stranger() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StoragePaths::under(dir.path());
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wiped");

    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    let before = agent.endpoint_id();
    agent.join_network(&name, &secret).await.unwrap();
    // Something a plugin keeps beside the state, which a wipe must take too.
    std::fs::create_dir_all(paths.state_dir.join("wireguard")).unwrap();
    std::fs::write(paths.state_dir.join("wireguard/keys.sqlite"), b"key").unwrap();

    // Not while an agent owns the directory: a half-wiped state under a
    // running agent is worse than no wipe at all.
    let refused = tsunagi::storage::wipe(&paths).unwrap_err();
    assert!(matches!(refused, Error::StateLocked { .. }), "{refused}");
    agent.shutdown().await;

    let plan = tsunagi::storage::wipe_plan(&paths).unwrap();
    assert!(
        plan.entries().any(|path| path.ends_with("state.sqlite")),
        "{plan:?}"
    );
    assert!(
        plan.entries().any(|path| path.ends_with("wireguard")),
        "what a plugin kept is state too: {plan:?}"
    );

    let wiped = tsunagi::storage::wipe(&paths).unwrap();
    assert_eq!(wiped, plan);
    assert!(!paths.state_db().exists());
    assert!(!paths.state_dir.join("wireguard").exists());
    assert!(!paths.lock_file().exists(), "no lock is left claiming it");

    // A stranger: new identity, no networks, nothing to be surprised by.
    let fresh = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_ne!(fresh.endpoint_id(), before);
    assert!(fresh.list_networks().await.unwrap().is_empty());
    fresh.shutdown().await;
}

#[tokio::test]
async fn wiping_twice_is_as_ordinary_as_wiping_once() {
    let dir = tempfile::tempdir().unwrap();
    let paths = StoragePaths::under(dir.path());
    let discovery = SharedMemoryDiscovery::new();

    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    agent.shutdown().await;

    assert!(!tsunagi::storage::wipe(&paths).unwrap().is_empty());
    let again = tsunagi::storage::wipe(&paths).unwrap();
    assert!(again.is_empty(), "nothing left to remove: {again:?}");
}

#[tokio::test]
async fn a_directory_that_is_not_ours_is_refused_rather_than_emptied() {
    // The mistyped `--state-dir` that would otherwise remove somebody's
    // documents. A marker decides, not the name of the directory.
    let dir = tempfile::tempdir().unwrap();
    let paths = StoragePaths::new(dir.path(), dir.path().join("cache"));
    std::fs::write(dir.path().join("thesis.txt"), b"years of work").unwrap();

    let err = tsunagi::storage::wipe(&paths).unwrap_err();
    assert!(
        err.to_string().contains("does not look like a tsunagi"),
        "{err}"
    );
    assert!(
        dir.path().join("thesis.txt").exists(),
        "nothing was removed"
    );
}

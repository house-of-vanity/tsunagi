//! Local Mainline Testnet, real iroh authentication, and durable agent state.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;
use tsunagi::testing::{local_config, network, wait_for_peers};
use tsunagi::{Agent, config::DiscoveryPolicy, discovery::MainlineDiscovery};

#[tokio::test]
#[ignore = "uses public Mainline DHT and iroh relay services"]
async fn public_dht_finds_and_authenticates_two_agents() {
    tsunagi::testing::init_tracing();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let config = |path: &std::path::Path| {
        tsunagi::config::AgentConfig::new(tsunagi::config::StoragePaths::under(path))
            .with_transport(tsunagi::config::TransportPolicy::N0Defaults)
            .with_dht(MainlineDiscovery::default())
    };
    let a = Agent::spawn(config(a_dir.path())).await.unwrap();
    let b = Agent::spawn(config(b_dir.path())).await.unwrap();
    let (name, secret) = network("mainline-public-smoke");
    let id = a.join_network(&name, &secret).await.unwrap();
    b.join_network(&name, &secret).await.unwrap();
    let found = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if !a.network_status(id).await.unwrap().peers.is_empty()
                && !b.network_status(id).await.unwrap().peers.is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
    assert!(
        found.is_ok(),
        "public DHT/relay discovery did not connect within three minutes"
    );
}
#[tokio::test]
async fn two_agents_restore_after_all_dht_records_and_addresses_are_gone() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let (name, secret) = network("dht-restart");
    let mut identities = None;
    for _ in 0..2 {
        if identities.is_some() {
            for path in [first_dir.path(), second_dir.path()] {
                let cache = tsunagi::config::StoragePaths::under(path).cache_dir;
                if cache.exists() {
                    std::fs::remove_dir_all(cache).unwrap();
                }
            }
        }
        // A fresh Testnet means no old rendezvous record survives. The second
        // pass restores the networks from SQLite without another join command.
        let net = mainline::Testnet::builder(5).build().unwrap();
        let config = |path: &std::path::Path| {
            local_config(path)
                .with_dht(MainlineDiscovery::local_testnet(&net.bootstrap).unwrap())
                .with_discovery_policy(DiscoveryPolicy {
                    lookup_interval: Duration::from_millis(100),
                    max_lookup_interval: Duration::from_millis(300),
                    ..Default::default()
                })
        };
        let (a, b) = tokio::join!(
            Agent::spawn(config(first_dir.path())),
            Agent::spawn(config(second_dir.path()))
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let id = tsunagi::identity::NetworkKeys::derive(&name, &secret).network_id();
        if let Some(old) = identities {
            assert_eq!((a.endpoint_id(), b.endpoint_id()), old);
        } else {
            identities = Some((a.endpoint_id(), b.endpoint_id()));
            let (ra, rb) = tokio::join!(
                a.join_network(&name, &secret),
                b.join_network(&name, &secret)
            );
            assert_eq!(ra.unwrap(), id);
            assert_eq!(rb.unwrap(), id);
        }
        wait_for_peers(&a, id, 1).await;
        wait_for_peers(&b, id, 1).await;
        a.shutdown().await;
        b.shutdown().await;
    }
}

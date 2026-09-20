//! Scenario 1: deterministic network identity.
//!
//! The same name and secret must yield the same network space on different
//! devices, and nothing else — hostname, device key, restart — may change it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{TestAgent, config_with, network};
use tsunagi::Agent;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};

#[test]
fn derivation_is_a_pure_function_of_name_and_secret() {
    let name = NetworkName::new("home").unwrap();
    let other = NetworkName::new("Home").unwrap();
    let secret = NetworkSecret::generate();
    let other_secret = NetworkSecret::generate();

    let a = NetworkKeys::derive(&name, &secret);
    let b = NetworkKeys::derive(&name, &secret);
    assert_eq!(a.network_id(), b.network_id());
    assert_eq!(a.discovery_key(), b.discovery_key());
    assert_eq!(a.descriptor(), b.descriptor());

    // A different name is a different space. Names are used verbatim, so case
    // matters.
    assert_ne!(
        a.network_id(),
        NetworkKeys::derive(&other, &secret).network_id()
    );
    // A different secret is a different space.
    assert_ne!(
        a.network_id(),
        NetworkKeys::derive(&name, &other_secret).network_id()
    );
    // Separated key material: the discovery key is not the network id.
    assert_ne!(a.network_id().as_bytes(), a.discovery_key().as_bytes());
}

#[test]
fn descriptor_carries_no_creator_time_or_secret() {
    let name = NetworkName::new("shared").unwrap();
    let secret = NetworkSecret::generate();
    let first = NetworkKeys::derive(&name, &secret).descriptor();
    let second = NetworkKeys::derive(&name, &secret).descriptor();

    // Two independently built descriptors are byte identical: no random
    // creator id, no creation timestamp, no owner signature.
    assert_eq!(first.to_canonical_bytes(), second.to_canonical_bytes());

    let encoded = first.to_canonical_bytes();
    let secret_bytes = secret.encode();
    assert!(
        !encoded
            .windows(secret_bytes.len())
            .any(|window| window == secret_bytes.as_bytes()),
        "the secret must never appear in the public descriptor"
    );
}

#[test]
fn names_are_validated_not_silently_normalised() {
    assert!(NetworkName::new("").is_err());
    assert!(NetworkName::new(" home").is_err(), "must not be trimmed");
    assert!(NetworkName::new("home ").is_err(), "must not be trimmed");
    assert!(NetworkName::new("ho\nme").is_err());
    assert!(NetworkName::new("a".repeat(65)).is_err());
    assert_eq!(NetworkName::new("home").unwrap().as_str(), "home");
}

#[test]
fn secrets_are_not_truncated_or_normalised() {
    let secret = NetworkSecret::generate();
    let text = secret.encode();
    let round_tripped = NetworkSecret::decode(&text).unwrap();
    assert_eq!(secret, round_tripped);

    // Short secrets are rejected rather than stretched.
    assert!(NetworkSecret::from_bytes(vec![7u8; 15]).is_err());
    assert!(NetworkSecret::from_bytes(vec![7u8; 16]).is_ok());

    // Debug output must not leak the secret.
    let rendered = format!("{secret:?}");
    assert_eq!(rendered, "NetworkSecret(<redacted>)");
}

#[tokio::test]
async fn different_devices_and_hostnames_agree_on_the_network_id() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("agreement");

    let a = TestAgent::spawn_with(|cfg| cfg.with_hostname("alpha"), &discovery)
        .await
        .unwrap();
    let b = TestAgent::spawn_with(|cfg| cfg.with_hostname("beta"), &discovery)
        .await
        .unwrap();

    assert_ne!(
        a.agent.endpoint_id(),
        b.agent.endpoint_id(),
        "different devices must have different endpoint ids"
    );
    assert_eq!(a.agent.hostname(), "alpha");
    assert_eq!(b.agent.hostname(), "beta");

    let id_a = a.agent.join_network(&name, &secret).await.unwrap();
    let id_b = b.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(id_a, id_b);

    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn restart_keeps_the_device_and_network_identity() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("stable");

    let first = TestAgent::spawn(&discovery).await.unwrap();
    let device_id = first.agent.endpoint_id();
    let network_id = first.agent.join_network(&name, &secret).await.unwrap();
    let dir = first.stop().await;

    let reopened = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(
        reopened.endpoint_id(),
        device_id,
        "restarting must not mint a new peer"
    );
    let networks = reopened.list_networks().await.unwrap();
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].network_id, network_id);
    assert!(networks[0].active, "auto-start networks come back up");

    reopened.shutdown().await;
    drop(reopened);
    drop(dir);
}

#[tokio::test]
async fn changing_the_secret_keeps_the_device_identity() {
    let discovery = SharedMemoryDiscovery::new();
    let dir = tempfile::TempDir::new().unwrap();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    let device_id = agent.endpoint_id();

    let name = NetworkName::new("rotating").unwrap();
    let old = agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();
    let new = agent
        .join_network(&name, &NetworkSecret::generate())
        .await
        .unwrap();

    assert_ne!(old, new, "a new secret is a new network space");
    assert_eq!(
        agent.endpoint_id(),
        device_id,
        "rotating the network secret must not change the persistent iroh id"
    );

    agent.shutdown().await;
    drop(agent);
    drop(dir);
}

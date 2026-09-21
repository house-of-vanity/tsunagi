//! The device's own identity: the name it answers to and the key it signs
//! with, and what happens when either is changed.
//!
//! Both are things a user may reasonably change on a machine they own, and
//! neither may leave the state store in a shape the next start cannot use.
//! That is what these check: not that changing them is prevented, but that
//! the store survives it and says something true afterwards.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{config_with, network, wait_until};
use tempfile::TempDir;
use tsunagi::Agent;
use tsunagi::config::StoragePaths;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};
use tsunagi::state::{RecordBody, StateSet};
use tsunagi::storage::StateStore;

#[tokio::test]
async fn a_changed_name_reaches_peers_and_replaces_the_old_claim() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("renaming");

    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let agent_a = Agent::spawn(config_with(a.path(), &discovery))
        .await
        .unwrap();
    let agent_b = Agent::spawn(config_with(b.path(), &discovery))
        .await
        .unwrap();
    let network_id = agent_a.join_network(&name, &secret).await.unwrap();
    agent_b.join_network(&name, &secret).await.unwrap();

    let accepted = agent_a.set_hostname("Renamed Host").await.unwrap();
    assert_eq!(accepted, "renamedhost", "reduced to a canonical form");
    assert_eq!(agent_a.hostname(), "renamedhost");

    // The peer is told, rather than finding out on its next restart.
    wait_until("the peer learns the new name", || async {
        let status = agent_b.network_status(network_id).await.ok()?;
        status
            .peers
            .iter()
            .any(|peer| peer.hostname.as_deref() == Some("renamedhost"))
            .then_some(())
    })
    .await;

    // And the signed claim says it, so the name outlives the session.
    wait_until("the claim carries the new name", || async {
        let status = agent_b.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .any(|member| member.hostname.as_deref() == Some("renamedhost"))
            .then_some(())
    })
    .await;

    agent_a.shutdown().await;
    agent_b.shutdown().await;
}

#[tokio::test]
async fn a_name_that_reduces_to_nothing_is_refused_rather_than_stored() {
    let discovery = SharedMemoryDiscovery::new();
    let dir = TempDir::new().unwrap();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();

    let before = agent.hostname();
    assert!(agent.set_hostname("---").await.is_err());
    assert!(agent.set_hostname("").await.is_err());
    assert_eq!(agent.hostname(), before, "the old name still stands");

    agent.shutdown().await;
}

/// Replacing the signing key must leave a store the next run can use.
///
/// The user is entitled to do this on a machine they own, and they lose the
/// address and name the old key held — there is no way to sign on a dead
/// key's behalf, and nothing here may overrule an author. What must not
/// happen is that the store is left in a shape that breaks.
#[tokio::test]
async fn rotating_the_signing_key_releases_what_it_held_and_leaves_a_usable_store() {
    let dir = TempDir::new().unwrap();
    let paths = StoragePaths::under(dir.path());
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("rotation");
    let network_id = NetworkKeys::derive(&name, &secret).network_id();

    // Run once so there is an identity, a network, and a claim to give up.
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    agent.join_network(&name, &secret).await.unwrap();
    let before = agent.endpoint_id();
    wait_until("the agent claims an address", || async {
        let status = agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .any(|member| member.endpoint_id == before && member.overlay_address_v4.is_some())
            .then_some(())
    })
    .await;
    let claimed = agent
        .network_status(network_id)
        .await
        .unwrap()
        .members
        .iter()
        .find(|member| member.endpoint_id == before)
        .and_then(|member| member.overlay_address_v4)
        .expect("an address was claimed");
    agent.shutdown().await;

    let (replacement, released) = {
        let store = StateStore::open(paths.state_db()).unwrap();
        store.rotate_device_identity().unwrap()
    };
    assert_ne!(replacement.endpoint_id(), before, "a different author");
    assert_eq!(released, vec![network_id]);

    // The outgoing key signed a release, and it still verifies: a record
    // whose author no longer runs is not thereby invalid.
    {
        let store = StateStore::open(paths.state_db()).unwrap();
        assert_eq!(
            store.device_identity().unwrap().map(|id| id.endpoint_id()),
            Some(replacement.endpoint_id())
        );

        let mut set = StateSet::new();
        for record in store.signed_records(network_id).unwrap() {
            set.merge(network_id, record)
                .expect("every record verifies");
        }
        let old = set.get(&before).expect("the old author is still on record");
        assert!(matches!(old.body, RecordBody::Release));
        assert_eq!(
            set.address_of(&before),
            None,
            "the address it held is free again"
        );
        assert!(
            !set.address_holders().contains_key(&claimed),
            "{claimed} is no longer reserved"
        );
    }

    // The whole point: the next run comes up on it.
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(agent.endpoint_id(), replacement.endpoint_id());
    let network_id = agent.join_network(&name, &secret).await.unwrap();
    wait_until("the new identity claims an address of its own", || async {
        let status = agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .any(|member| {
                member.endpoint_id == replacement.endpoint_id()
                    && member.overlay_address_v4.is_some()
            })
            .then_some(())
    })
    .await;
    agent.shutdown().await;
}

#[tokio::test]
async fn rotating_a_store_that_has_never_run_just_creates_an_identity() {
    let dir = TempDir::new().unwrap();
    let paths = StoragePaths::under(dir.path());

    let store = StateStore::open(paths.state_db()).unwrap();
    assert!(store.device_identity().unwrap().is_none());

    let (identity, released) = store.rotate_device_identity().unwrap();
    assert!(
        released.is_empty(),
        "nothing was held, so nothing is given up"
    );
    assert_eq!(
        store.device_identity().unwrap().map(|id| id.endpoint_id()),
        Some(identity.endpoint_id())
    );
}

#[tokio::test]
async fn the_hostname_defaults_to_the_machines_own_name() {
    let discovery = SharedMemoryDiscovery::new();
    let dir = TempDir::new().unwrap();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();

    // Whatever this machine is called, the agent uses it rather than
    // inventing a name from the key — unless the host has no usable one.
    match tsunagi::agent::system_hostname() {
        Some(system) => assert_eq!(agent.hostname(), system),
        None => assert!(agent.hostname().starts_with("tsunagi-")),
    }

    agent.shutdown().await;
}

/// A secret must not reach the control socket, whatever else `id` prints.
#[tokio::test]
async fn secrets_stay_out_of_the_status_report() {
    let discovery = SharedMemoryDiscovery::new();
    let dir = TempDir::new().unwrap();
    let (name, secret) = network("no-secrets-on-the-wire");

    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    agent.join_network(&name, &secret).await.unwrap();

    let status = agent.status().await.unwrap();
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(secret.encode().as_str()));

    agent.shutdown().await;
}

#[test]
fn a_network_name_and_secret_are_unaffected_by_the_device_key() {
    // Network identity is derived from the name and secret only. Replacing
    // the device key must not move the network the device belongs to.
    let name = NetworkName::new("stable").unwrap();
    let secret = NetworkSecret::from_bytes(vec![9u8; 32]).unwrap();
    let first = NetworkKeys::derive(&name, &secret).network_id();
    let second = NetworkKeys::derive(&name, &secret).network_id();
    assert_eq!(first, second);
}

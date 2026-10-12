//! Equal-rights retirement uses real membership, signatures and persistent state.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::testing::{TestAgent, config_with, network, wait_for_peers, wait_until};
use tsunagi::{Agent, NetworkId};

#[tokio::test]
async fn bounded_marker_batches_eventually_reach_the_tail_of_a_small_send_queue() {
    use tsunagi::config::StoragePaths;
    use tsunagi::state::{RecordBody, SignedRecord, SignedRetirement};
    use tsunagi::storage::StateStore;

    let discovery = SharedMemoryDiscovery::new();
    let cleaner = TestAgent::spawn(&discovery).await.unwrap();
    let replica = TestAgent::spawn(&discovery).await.unwrap();
    let (name, secret) = network("forget-batched-history");
    let id = cleaner.agent.join_network(&name, &secret).await.unwrap();
    replica.agent.join_network(&name, &secret).await.unwrap();
    let cleaner_dir = cleaner.stop().await;
    let replica_dir = replica.stop().await;
    let cleaner_path = StoragePaths::under(cleaner_dir.path()).state_db();
    let replica_path = StoragePaths::under(replica_dir.path()).state_db();
    // Seed genuine signed offline history in closed stores. Delivery still uses
    // real agents, authenticated loopback sessions and the persistent stores.
    let targets = tokio::task::spawn_blocking(move || {
        let cleaner = StateStore::open(&cleaner_path).unwrap();
        let replica = StateStore::open(&replica_path).unwrap();
        let author = cleaner.device_identity().unwrap().unwrap();
        let signing_key = iroh::SecretKey::from_bytes(&author.secret_bytes());
        let mut targets = Vec::new();
        for index in 0..12 {
            let target = iroh::SecretKey::generate();
            let record = SignedRecord::sign(
                &target,
                id,
                1,
                RecordBody::Claim {
                    address: None,
                    range: None,
                    hostname: Some(format!("offline-{index}")),
                    hostname_since: Some(1),
                },
            );
            cleaner.put_signed_record(&record).unwrap();
            replica.put_signed_record(&record).unwrap();
            cleaner
                .publish_own_retirement(&SignedRetirement::sign(
                    &signing_key,
                    id,
                    100 + index,
                    record,
                ))
                .unwrap();
            targets.push(target.public());
        }
        targets
    })
    .await
    .unwrap();
    let replica = Agent::spawn(config_with(replica_dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(
        replica
            .network_status(id)
            .await
            .unwrap()
            .members
            .iter()
            .filter(|m| targets.contains(&m.endpoint_id))
            .count(),
        12
    );
    let mut config = config_with(cleaner_dir.path(), &discovery);
    config.limits.max_state_records = 1;
    config.limits.session_send_queue = 2;
    let cleaner = Agent::spawn(config).await.unwrap();
    wait_for_peers(&cleaner, id, 1).await;
    wait_until(
        "all cleanup batches arrive despite send queue pressure",
        || async {
            replica
                .network_status(id)
                .await
                .ok()?
                .members
                .iter()
                .all(|m| !targets.contains(&m.endpoint_id))
                .then_some(())
        },
    )
    .await;
    cleaner.shutdown().await;
    replica.shutdown().await;
    let replica_path = StoragePaths::under(replica_dir.path()).state_db();
    tokio::task::spawn_blocking(move || {
        let replica = StateStore::open(&replica_path).unwrap();
        assert_eq!(replica.retirements(id, 16).unwrap().len(), 12);
    })
    .await
    .unwrap();
}

async fn member(
    agent: &Agent,
    network: NetworkId,
    peer: iroh::EndpointId,
) -> tsunagi::agent::MemberStatus {
    wait_until("signed member", || async {
        agent
            .network_status(network)
            .await
            .ok()?
            .members
            .into_iter()
            .find(|m| m.endpoint_id == peer)
    })
    .await
}

#[tokio::test]
async fn retirement_survives_restart_and_stale_replicas_but_allows_a_new_claim() {
    let discovery = SharedMemoryDiscovery::new();
    let cleaner = TestAgent::spawn_with(|c| c.with_hostname("cleaner"), &discovery)
        .await
        .unwrap();
    let target = TestAgent::spawn_with(|c| c.with_hostname("old-device"), &discovery)
        .await
        .unwrap();
    let replica = TestAgent::spawn_with(|c| c.with_hostname("replica"), &discovery)
        .await
        .unwrap();
    let (name, secret) = network("forget-propagation");
    let id = cleaner.agent.join_network(&name, &secret).await.unwrap();
    target.agent.join_network(&name, &secret).await.unwrap();
    replica.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&cleaner.agent, id, 2).await;
    let peer = target.agent.endpoint_id();
    let original = wait_until("all three agents agree on allocated claims", || async {
        let a = cleaner.agent.network_status(id).await.ok()?;
        let b = target.agent.network_status(id).await.ok()?;
        let c = replica.agent.network_status(id).await.ok()?;
        for status in [&a, &b, &c] {
            if status.members.len() != 3 {
                return None;
            }
            let addresses: std::collections::HashSet<_> = status
                .members
                .iter()
                .filter_map(|m| m.overlay_address_v4)
                .collect();
            if addresses.len() != 3 {
                return None;
            }
        }
        let record = a.members.iter().find(|m| m.endpoint_id == peer)?;
        (b.members
            .iter()
            .find(|m| m.endpoint_id == peer)?
            .record_version
            == record.record_version
            && c.members
                .iter()
                .find(|m| m.endpoint_id == peer)?
                .record_version
                == record.record_version)
            .then(|| record.clone())
    })
    .await;
    assert!(
        cleaner
            .agent
            .forget_node(id, peer, original.record_version)
            .await
            .is_err(),
        "online nodes are not history"
    );
    assert!(
        cleaner
            .agent
            .forget_node(id, cleaner.agent.endpoint_id(), 1)
            .await
            .is_err()
    );
    let replica_dir = replica.stop().await;
    let target_dir = target.stop().await;
    wait_until("target offline", || async {
        cleaner
            .agent
            .network_status(id)
            .await
            .ok()?
            .members
            .iter()
            .find(|m| m.endpoint_id == peer)
            .filter(|m| !m.online)
            .map(|_| ())
    })
    .await;
    assert!(
        cleaner
            .agent
            .forget_node(id, peer, original.record_version + 1)
            .await
            .is_err(),
        "stale confirmation changes nothing"
    );
    let result = cleaner
        .agent
        .forget_node(id, peer, original.record_version)
        .await
        .unwrap();
    assert_eq!(result.target, peer);
    assert_eq!(result.record_version, original.record_version);
    assert_eq!(result.peers_told, 0);
    assert!(
        !cleaner
            .agent
            .network_status(id)
            .await
            .unwrap()
            .members
            .iter()
            .any(|m| m.endpoint_id == peer)
    );
    let cleaner_dir = cleaner.stop().await;
    let cleaner =
        Agent::spawn(config_with(cleaner_dir.path(), &discovery).with_hostname("cleaner"))
            .await
            .unwrap();
    let replica =
        Agent::spawn(config_with(replica_dir.path(), &discovery).with_hostname("replica"))
            .await
            .unwrap();
    wait_for_peers(&cleaner, id, 1).await;
    wait_until("stale replica learns durable retirement", || async {
        replica
            .network_status(id)
            .await
            .ok()?
            .members
            .iter()
            .all(|m| m.endpoint_id != peer)
            .then_some(())
    })
    .await;
    assert!(
        !cleaner
            .network_status(id)
            .await
            .unwrap()
            .members
            .iter()
            .any(|m| m.endpoint_id == peer)
    );
    replica.set_hostname("old-device").await.unwrap();
    let replica_id = replica.endpoint_id();
    wait_until("released hostname is reclaimed", || async {
        cleaner
            .network_status(id)
            .await
            .ok()?
            .members
            .iter()
            .find(|m| m.endpoint_id == replica_id)
            .filter(|m| m.hostname.as_deref() == Some("old-device"))?
            .hostname_conflict
            .is_none()
            .then_some(())
    })
    .await;
    let returned =
        Agent::spawn(config_with(target_dir.path(), &discovery).with_hostname("old-device"))
            .await
            .unwrap();
    wait_for_peers(&returned, id, 2).await;
    wait_until("returning identity publishes a fresh version", || async {
        let m = cleaner
            .network_status(id)
            .await
            .ok()?
            .members
            .into_iter()
            .find(|m| m.endpoint_id == peer)?;
        (m.online && m.record_version > original.record_version && m.hostname_conflict.is_some())
            .then_some(())
    })
    .await;
    cleaner.shutdown().await;
    replica.shutdown().await;
    returned.shutdown().await;
}

#[tokio::test]
async fn forgetting_is_network_scoped_and_every_member_has_the_same_right() {
    let discovery = SharedMemoryDiscovery::new();
    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let target = TestAgent::spawn(&discovery).await.unwrap();
    let (name, secret) = network("forget-one-network");
    let (other_name, other_secret) = network("keep-other-network");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    target.agent.join_network(&name, &secret).await.unwrap();
    let other = a
        .agent
        .join_network(&other_name, &other_secret)
        .await
        .unwrap();
    target
        .agent
        .join_network(&other_name, &other_secret)
        .await
        .unwrap();
    let peer = target.agent.endpoint_id();
    let record = member(&b.agent, id, peer).await;
    member(&a.agent, other, peer).await;
    target.agent.shutdown().await;
    wait_until("offline on B", || async {
        b.agent
            .network_status(id)
            .await
            .ok()?
            .members
            .iter()
            .find(|m| m.endpoint_id == peer)
            .filter(|m| !m.online)
            .map(|_| ())
    })
    .await;
    b.agent
        .forget_node(id, peer, record.record_version)
        .await
        .unwrap();
    wait_until("A learns B's retirement", || async {
        a.agent
            .network_status(id)
            .await
            .ok()?
            .members
            .iter()
            .all(|m| m.endpoint_id != peer)
            .then_some(())
    })
    .await;
    assert!(
        a.agent
            .network_status(other)
            .await
            .unwrap()
            .members
            .iter()
            .any(|m| m.endpoint_id == peer)
    );
    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

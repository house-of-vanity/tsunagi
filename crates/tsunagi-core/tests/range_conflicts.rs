//! Derived defaults and local exclusion of overlapping overlay networks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tsunagi::Agent;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::state::{DEFAULT_IPV4_RANGE, Ipv4Range, derived_ipv4_range};
use tsunagi::testing::{TestAgent, config_with, network, wait_until};

// These tests need discovery to happen before a collision, so keep the initial
// default outside the established ranges. Derived collisions have their own test.
fn network_outside(
    name: &str,
    ranges: &[Ipv4Range],
) -> (
    tsunagi::identity::NetworkName,
    tsunagi::identity::NetworkSecret,
) {
    use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};
    let name = NetworkName::new(name).unwrap();
    let secret = (0..=255u8)
        .map(|seed| NetworkSecret::from_bytes([seed; 32]).unwrap())
        .find(|secret| {
            let derived = derived_ipv4_range(NetworkKeys::derive(&name, secret).network_id());
            ranges.iter().all(|range| !range.contains(derived.base))
        })
        .expect("a deterministic test secret with a non-overlapping default");
    (name, secret)
}

#[tokio::test]
async fn colliding_derived_defaults_are_blocked_instead_of_locally_renumbered() {
    use std::collections::HashMap;
    use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};
    let secret = NetworkSecret::from_bytes([19; 32]).unwrap();
    let mut seen = HashMap::new();
    let (first, second, range) = (0..=65_536)
        .find_map(|index| {
            let name = NetworkName::new(format!("derived-collision-{index}")).unwrap();
            let range = derived_ipv4_range(NetworkKeys::derive(&name, &secret).network_id());
            seen.insert(range.base, name.clone())
                .map(|first| (first, name, range))
        })
        .expect("more network names than possible /24 ranges");
    let agent = TestAgent::spawn(&SharedMemoryDiscovery::new())
        .await
        .unwrap();
    let first = agent.agent.join_network(&first, &secret).await.unwrap();
    let second = agent.agent.join_network(&second, &secret).await.unwrap();
    assert!(agent.agent.is_active(first).await);
    assert!(!agent.agent.is_active(second).await);
    let status = agent.agent.status().await.unwrap();
    let blocked = status.network(&second).unwrap();
    assert_eq!(blocked.range, Some(range));
    assert_eq!(blocked.range_conflicts[0].network_id, first);
    assert_eq!(
        agent.agent.switch_network(second).await.unwrap(),
        vec![first]
    );
    assert_eq!(
        agent.agent.network_status(second).await.unwrap().range,
        Some(range)
    );
    agent.agent.shutdown().await;
}

#[tokio::test]
async fn isolated_first_members_choose_the_same_range_and_keep_it_after_restart() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("derived-first");
    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&SharedMemoryDiscovery::new())
        .await
        .unwrap();
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    let expected = derived_ipv4_range(id);
    for agent in [&a.agent, &b.agent] {
        wait_until("isolated member allocates in its derived range", || async {
            let status = agent.network_status(id).await.ok()?;
            (status.range == Some(expected) && !status.members.is_empty()).then_some(())
        })
        .await;
    }
    let dir = a.stop().await;
    let a = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(a.network_status(id).await.unwrap().range, Some(expected));
    a.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn overlap_blocks_activation_switches_and_resumes_across_restart() {
    let discovery = SharedMemoryDiscovery::new();
    let a = TestAgent::spawn_with(
        |c| c.with_overlay_ipv4_range(Some(DEFAULT_IPV4_RANGE)),
        &discovery,
    )
    .await
    .unwrap();
    let (one_name, one_secret) = network("conflict-one");
    let (two_name, two_secret) = network("conflict-two");
    let one = a.agent.join_network(&one_name, &one_secret).await.unwrap();
    a.agent.network_status(one).await.unwrap();
    let two = a.agent.join_network(&two_name, &two_secret).await.unwrap();
    assert!(a.agent.is_active(one).await);
    assert!(!a.agent.is_active(two).await);
    assert!(matches!(
        a.agent.activate_network(two).await,
        Err(tsunagi::Error::NetworkRangeConflict { .. })
    ));
    let status = a.agent.status().await.unwrap();
    let blocked = status.network(&two).unwrap();
    assert_eq!(blocked.range, Some(DEFAULT_IPV4_RANGE));
    assert_eq!(blocked.range_conflicts[0].network_id, one);
    assert_eq!(blocked.range_conflicts[0].name, one_name);
    assert_eq!(a.agent.switch_network(two).await.unwrap(), vec![one]);
    assert!(a.agent.is_active(two).await);
    assert!(!a.agent.is_active(one).await);

    a.agent.network_status(two).await.unwrap();
    let dir = a.stop().await;
    let a = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    assert!(a.is_active(two).await, "the user's choice survives restart");
    assert!(!a.is_active(one).await);
    a.deactivate_network(two).await.unwrap();
    assert!(
        a.is_active(one).await,
        "suspended networks resume when the blocker stops"
    );
    assert_eq!(
        a.network_status(one).await.unwrap().range,
        Some(DEFAULT_IPV4_RANGE),
        "legacy ranges survive the new default"
    );
    a.shutdown().await;
}

#[tokio::test]
async fn late_authenticated_state_with_a_nested_range_suspends_only_that_network() {
    let discovery = SharedMemoryDiscovery::new();
    let broad: Ipv4Range = "10.90.0.0/16".parse().unwrap();
    let narrow: Ipv4Range = "10.90.12.0/24".parse().unwrap();
    let (name, secret) = network_outside("late-conflict", &[broad]);
    let remote = TestAgent::spawn_with(|c| c.with_overlay_ipv4_range(Some(narrow)), &discovery)
        .await
        .unwrap();
    let target = remote.agent.join_network(&name, &secret).await.unwrap();
    wait_until("remote range is persisted", || async {
        remote
            .agent
            .network_status(target)
            .await
            .ok()?
            .members
            .first()
            .map(|_| ())
    })
    .await;

    let (other_name, other_secret) = network("existing-broad");
    // Seed an existing network using a real agent and its signed claim.
    let seeded = TestAgent::spawn_with(
        |c| c.with_overlay_ipv4_range(Some(broad)),
        &SharedMemoryDiscovery::new(),
    )
    .await
    .unwrap();
    let other = seeded
        .agent
        .join_network(&other_name, &other_secret)
        .await
        .unwrap();
    wait_until("broad range is persisted", || async {
        seeded
            .agent
            .network_status(other)
            .await
            .ok()?
            .members
            .first()
            .map(|_| ())
    })
    .await;
    let dir = seeded.stop().await;
    let seeded = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    seeded.join_network(&name, &secret).await.unwrap();
    wait_until("late overlap suspends the joining network", || async {
        let status = seeded.status().await.ok()?;
        let blocked = status.network(&target)?;
        (!seeded.is_active(target).await
            && blocked
                .range_conflicts
                .iter()
                .any(|c| c.network_id == other))
        .then_some(())
    })
    .await;
    assert!(seeded.is_active(other).await);
    assert_eq!(seeded.switch_network(target).await.unwrap(), vec![other]);
    assert_eq!(
        seeded.network_status(target).await.unwrap().range,
        Some(narrow)
    );
    seeded.shutdown().await;
    remote.agent.shutdown().await;
}

#[tokio::test]
async fn a_wide_range_suspends_all_overlaps_and_manual_stop_cancels_resume() {
    let discovery = SharedMemoryDiscovery::new();
    let hub = TestAgent::spawn(&discovery).await.unwrap();
    let mut members = Vec::new();
    let mut ids = Vec::new();
    for (name, range) in [
        ("narrow-one", "10.81.0.0/24"),
        ("narrow-two", "10.81.1.0/24"),
    ] {
        let peer = TestAgent::spawn_with(
            |c| c.with_overlay_ipv4_range(Some(range.parse().unwrap())),
            &discovery,
        )
        .await
        .unwrap();
        let (name, secret) = network_outside(
            name,
            &[
                "10.81.0.0/24".parse().unwrap(),
                "10.81.1.0/24".parse().unwrap(),
            ],
        );
        let id = peer.agent.join_network(&name, &secret).await.unwrap();
        peer.agent.network_status(id).await.unwrap();
        hub.agent.join_network(&name, &secret).await.unwrap();
        wait_until("hub adopts the established narrow range", || async {
            (hub.agent.network_status(id).await.ok()?.range == Some(range.parse().unwrap()))
                .then_some(())
        })
        .await;
        members.push(peer);
        ids.push(id);
    }
    let (name, secret) = network_outside(
        "wide-overlap",
        &[
            "10.81.0.0/24".parse().unwrap(),
            "10.81.1.0/24".parse().unwrap(),
        ],
    );
    let wide = TestAgent::spawn_with(
        |c| c.with_overlay_ipv4_range(Some("10.0.0.0/8".parse().unwrap())),
        &discovery,
    )
    .await
    .unwrap();
    let id = wide.agent.join_network(&name, &secret).await.unwrap();
    wide.agent.network_status(id).await.unwrap();
    hub.agent.join_network(&name, &secret).await.unwrap();
    wait_until("wide range is blocked by both narrow networks", || async {
        let status = hub.agent.status().await.ok()?;
        let blocked = status.network(&id)?;
        (!hub.agent.is_active(id).await && blocked.range_conflicts.len() == 2).then_some(())
    })
    .await;
    let stopped = hub.agent.switch_network(id).await.unwrap();
    assert_eq!(stopped.len(), 2);
    assert!(ids.iter().all(|id| stopped.contains(id)));
    assert_eq!(hub.agent.switch_network(ids[0]).await.unwrap(), vec![id]);
    assert!(
        hub.agent.is_active(ids[1]).await,
        "switching away from the wide range frees the other narrow range too"
    );
    assert_eq!(hub.agent.switch_network(id).await.unwrap().len(), 2);
    hub.agent.pause_network(ids[0]).await.unwrap();
    hub.agent.deactivate_network(id).await.unwrap();
    assert!(
        !hub.agent.is_active(ids[0]).await,
        "explicitly stopped networks do not resume"
    );
    assert!(hub.agent.is_active(ids[1]).await);
    assert!(
        hub.agent
            .switch_network(tsunagi::NetworkId::from_bytes([0; 32]))
            .await
            .is_err()
    );
    assert!(
        hub.agent.is_active(ids[1]).await,
        "unknown selectors do not stop any network"
    );
    hub.agent.shutdown().await;
    wide.agent.shutdown().await;
    for peer in members {
        peer.agent.shutdown().await;
    }
}

#[tokio::test]
async fn simultaneous_switches_never_leave_overlapping_networks_active() {
    let discovery = SharedMemoryDiscovery::new();
    let agent = TestAgent::spawn_with(
        |c| c.with_overlay_ipv4_range(Some(DEFAULT_IPV4_RANGE)),
        &discovery,
    )
    .await
    .unwrap();
    let (a, a_secret) = network("switch-a");
    let (b, b_secret) = network("switch-b");
    let a = agent.agent.join_network(&a, &a_secret).await.unwrap();
    agent.agent.network_status(a).await.unwrap();
    let b = agent.agent.join_network(&b, &b_secret).await.unwrap();
    let (left, right) = tokio::join!(agent.agent.switch_network(b), agent.agent.switch_network(a));
    left.unwrap();
    right.unwrap();
    assert_ne!(
        agent.agent.is_active(a).await,
        agent.agent.is_active(b).await
    );
    assert_eq!(
        agent
            .agent
            .list_networks()
            .await
            .unwrap()
            .iter()
            .filter(|n| n.active)
            .count(),
        1
    );
    agent.agent.shutdown().await;
}

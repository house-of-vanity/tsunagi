//! Scenario 2: several agents find each other, authenticate for real and
//! exchange distinguishable messages.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::Arc;

use tsunagi::agent::Event;
use tsunagi::dataplane::TestCapabilityPlugin;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::proto::ControlMessage;
use tsunagi::testing::{TestAgent, network, wait_event, wait_for_peers, wait_until};

#[tokio::test]
async fn four_agents_form_a_mesh_and_exchange_distinguishable_messages() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("mesh-of-four");

    let mut agents = Vec::new();
    for index in 0..4 {
        let hostname = format!("host-{index}");
        agents.push(
            TestAgent::spawn_with(move |cfg| cfg.with_hostname(hostname), &discovery)
                .await
                .unwrap(),
        );
    }

    let mut network_ids = HashSet::new();
    for agent in &agents {
        network_ids.insert(agent.agent.join_network(&name, &secret).await.unwrap());
    }
    assert_eq!(network_ids.len(), 1, "one deterministic network space");
    let network_id = network_ids.into_iter().next().unwrap();

    // Full mesh: every agent must end up with the other three.
    for agent in &agents {
        wait_for_peers(&agent.agent, network_id, 3).await;
    }

    // Each peer announced its own hostname, so sessions are distinguishable.
    // A peer counts as connected as soon as its session is authenticated, which
    // can be a round before its announcement carrying the hostname arrives, so
    // this waits for the hostnames rather than reading them straight away.
    let hostnames: HashSet<String> = wait_until("three distinct peer hostnames", || async {
        let status = agents[0].agent.network_status(network_id).await.ok()?;
        let hostnames: HashSet<String> = status
            .peers
            .iter()
            .filter_map(|peer| peer.hostname.clone())
            .collect();
        (hostnames.len() >= 3).then_some(hostnames)
    })
    .await;
    assert_eq!(
        hostnames.len(),
        3,
        "three distinct hostnames: {hostnames:?}"
    );

    // Distinguishable request/response: each peer echoes its own sequence.
    let mut events = agents[0].agent.subscribe();
    for (index, peer) in agents.iter().skip(1).enumerate() {
        agents[0]
            .agent
            .send(
                network_id,
                peer.agent.endpoint_id(),
                ControlMessage::Ping {
                    seq: index as u64 + 1,
                    payload: format!("to-{index}").into_bytes(),
                },
            )
            .await
            .unwrap();
    }

    let mut seen = HashSet::new();
    while seen.len() < 3 {
        let (peer, seq, payload) = wait_event(&mut events, |event| match event {
            Event::MessageReceived {
                network,
                peer,
                message: ControlMessage::Pong { seq, payload },
            } if *network == network_id => Some((*peer, *seq, payload.clone())),
            _ => None,
        })
        .await;
        assert_eq!(payload, format!("to-{}", seq - 1).into_bytes());
        seen.insert(peer);
    }
    assert_eq!(seen.len(), 3);

    for agent in agents {
        agent.agent.shutdown().await;
    }
}

#[tokio::test]
async fn a_late_joiner_is_picked_up_by_the_existing_members() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("late-joiner");

    let first = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = first.agent.join_network(&name, &secret).await.unwrap();

    // Nobody else is there yet. That is "nobody found so far", not proof that
    // the network is empty, and the agent is ready regardless.
    let status = first.agent.network_status(network_id).await.unwrap();
    assert!(status.peers.is_empty());

    let second = TestAgent::spawn(&discovery).await.unwrap();
    second.agent.join_network(&name, &secret).await.unwrap();

    wait_for_peers(&first.agent, network_id, 1).await;
    wait_for_peers(&second.agent, network_id, 1).await;

    first.agent.shutdown().await;
    second.agent.shutdown().await;
}

#[tokio::test]
async fn opaque_plugin_capabilities_cross_the_control_plane() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("capabilities");

    // An explicitly test-only capability: nothing here advertises WireGuard.
    let plugin_a = Arc::new(TestCapabilityPlugin::new("test-ip", b"payload-a".to_vec()));
    let plugin_b = Arc::new(TestCapabilityPlugin::new("test-ip", b"payload-b".to_vec()));

    let a = TestAgent::spawn_with(
        {
            let plugin = Arc::clone(&plugin_a);
            move |cfg| cfg.with_plugin(plugin)
        },
        &discovery,
    )
    .await
    .unwrap();
    let b = TestAgent::spawn_with(
        {
            let plugin = Arc::clone(&plugin_b);
            move |cfg| cfg.with_plugin(plugin)
        },
        &discovery,
    )
    .await
    .unwrap();

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, network_id, 1).await;

    let observed = wait_until("plugin a sees b's capability", || {
        let plugin = Arc::clone(&plugin_a);
        async move {
            let seen = plugin.observed();
            if seen.is_empty() { None } else { Some(seen) }
        }
    })
    .await;

    let (seen_network, seen_peer, capability) = &observed[0];
    assert_eq!(*seen_network, network_id);
    assert_eq!(*seen_peer, b.agent.endpoint_id());
    assert_eq!(capability.protocol, "test-ip");
    assert_eq!(capability.data, b"payload-b".to_vec());
    assert!(capability.enabled);

    // The core carried the payload without interpreting it.
    let status = a.agent.network_status(network_id).await.unwrap();
    assert_eq!(status.peers[0].capabilities[0].data, b"payload-b".to_vec());

    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

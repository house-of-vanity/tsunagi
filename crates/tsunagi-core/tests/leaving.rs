//! Scenario 11: leaving a network, and what the others are left holding.
//!
//! Leaving is not deactivating and not forgetting. It is a signed statement
//! that this member gives up what it claimed, published while there is still
//! somebody to hear it, because signed state has no expiry and nothing else
//! will ever free the address.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::testing::{TestAgent, network, wait_for_peers, wait_until};

#[tokio::test]
async fn leaving_frees_the_address_for_everyone_still_there() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("leaving-frees");

    let leaver = TestAgent::spawn(&discovery).await.unwrap();
    let stayer = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = leaver.agent.join_network(&name, &secret).await.unwrap();
    stayer.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&stayer.agent, network_id, 1).await;

    let leaver_id = leaver.agent.endpoint_id();
    let address = wait_until("the one leaving holds an address", || async {
        let status = stayer.agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .find(|member| member.endpoint_id == leaver_id)?
            .overlay_address_v4
    })
    .await;

    let outcome = leaver.agent.leave_network(network_id).await.unwrap();
    assert!(outcome.announced, "there was a session to announce it on");
    assert_eq!(outcome.peers_told, 1);

    // The one still there drops it from the roster. The tombstone stays in
    // the record set — it has to, or a replica that never heard of it would
    // reinstate the old claim — but a member that gave everything up is not
    // a member, and listing it as one makes leaving look like a fault.
    wait_until("the member is gone from the roster", || async {
        let status = stayer.agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .all(|member| member.endpoint_id != leaver_id)
            .then_some(())
    })
    .await;
    let taken = stayer.agent.network_status(network_id).await.unwrap();
    assert!(
        !taken
            .members
            .iter()
            .any(|member| member.overlay_address_v4 == Some(address)),
        "the address is free for somebody else"
    );

    // And locally there is no membership left to be surprised by.
    assert!(
        leaver.agent.list_networks().await.unwrap().is_empty(),
        "the network is gone from the store"
    );
    assert!(!leaver.agent.is_active(network_id).await);

    leaver.agent.shutdown().await;
    stayer.agent.shutdown().await;
}

#[tokio::test]
async fn leaving_with_nobody_connected_says_so_rather_than_pretending() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("leaving-alone");

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();

    // Nobody is here, so the tombstone reaches nobody. The network is still
    // left — the caller asked — but the outcome does not claim an audience
    // there was not one for.
    let outcome = agent.agent.leave_network(network_id).await.unwrap();
    assert!(outcome.announced, "it was published locally");
    assert_eq!(outcome.peers_told, 0);
    assert!(agent.agent.list_networks().await.unwrap().is_empty());

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn leaving_a_network_that_is_not_running_tells_nobody() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("leaving-inactive");

    let agent = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();
    agent.agent.deactivate_network(network_id).await.unwrap();

    // There is no runtime to sign and send from, so nothing was announced
    // and the outcome says exactly that instead of a quiet success.
    let outcome = agent.agent.leave_network(network_id).await.unwrap();
    assert!(!outcome.announced);
    assert_eq!(outcome.peers_told, 0);
    assert!(agent.agent.list_networks().await.unwrap().is_empty());

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn rejoining_after_leaving_is_not_taken_for_a_stale_record() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("leaving-rejoin");

    let returner = TestAgent::spawn(&discovery).await.unwrap();
    let stayer = TestAgent::spawn(&discovery).await.unwrap();
    let network_id = returner.agent.join_network(&name, &secret).await.unwrap();
    stayer.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&stayer.agent, network_id, 1).await;

    let returner_id = returner.agent.endpoint_id();
    wait_until("the one leaving holds an address", || async {
        stayer
            .agent
            .network_status(network_id)
            .await
            .ok()?
            .members
            .iter()
            .find(|member| member.endpoint_id == returner_id)?
            .overlay_address_v4
    })
    .await;

    returner.agent.leave_network(network_id).await.unwrap();
    wait_until("the release reached the other one", || async {
        let status = stayer.agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .all(|member| member.endpoint_id != returner_id)
            .then_some(())
    })
    .await;

    // The same device, the same key, the same network. The version counter
    // survived leaving on purpose: a claim numbered below the release would
    // be ignored by every replica that already has the release, and this
    // member would be invisible for good.
    returner.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&stayer.agent, network_id, 1).await;
    let again = wait_until("the returning member is seen again", || async {
        stayer
            .agent
            .network_status(network_id)
            .await
            .ok()?
            .members
            .iter()
            .find(|member| member.endpoint_id == returner_id)?
            .overlay_address_v4
    })
    .await;
    assert!(
        tsunagi::state::DEFAULT_IPV4_RANGE.contains(again),
        "an address in the network's range: {again}"
    );

    returner.agent.shutdown().await;
    stayer.agent.shutdown().await;
}

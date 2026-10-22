//! Signed hostname ownership remains independent of connectivity and identity order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use tsunagi::{
    discovery::SharedMemoryDiscovery,
    testing::{TestAgent, network, wait_for_peers, wait_until},
};
#[tokio::test]
async fn a_name_belongs_to_the_member_that_claimed_it_first_on_every_member() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("first-claim");
    let spawn = |hostname: &'static str| {
        let discovery = discovery.clone();
        async move {
            TestAgent::spawn_with(move |config| config.with_hostname(hostname), &discovery)
                .await
                .unwrap()
        }
    };

    let first = spawn("music").await;
    let network_id = first.agent.join_network(&name, &secret).await.unwrap();
    let first_id = first.agent.endpoint_id();
    wait_until("the first claim is signed", || async {
        let status = first.agent.network_status(network_id).await.ok()?;
        status
            .members
            .iter()
            .any(|m| m.endpoint_id == first_id && m.hostname.as_deref() == Some("music"))
            .then_some(())
    })
    .await;

    // Whatever the ids turn out to be, the later one does not take it.
    let second = spawn("music").await;
    let third = spawn("studio").await;
    second.agent.join_network(&name, &secret).await.unwrap();
    third.agent.join_network(&name, &secret).await.unwrap();
    let second_id = second.agent.endpoint_id();
    for agent in [&first, &second, &third] {
        wait_for_peers(&agent.agent, network_id, 2).await;
    }

    for (viewer, label) in [(&first, "first"), (&second, "second"), (&third, "third")] {
        let status = wait_until(&format!("{label} sees both claims"), || async {
            let status = viewer.agent.network_status(network_id).await.ok()?;
            // The roster is the authors of signed records, so a member
            // being in it means its claim has arrived.
            let both = [first_id, second_id]
                .iter()
                .all(|id| status.members.iter().any(|m| m.endpoint_id == *id));
            both.then_some(status)
        })
        .await;
        let holder = status
            .members
            .iter()
            .find(|m| m.endpoint_id == first_id)
            .unwrap();
        let loser = status
            .members
            .iter()
            .find(|m| m.endpoint_id == second_id)
            .unwrap();
        assert_eq!(holder.hostname.as_deref(), Some("music"), "{label}");
        assert_eq!(loser.hostname, None, "{label}: no name for the later one");
        let conflict = loser.hostname_conflict.as_ref().expect(label);
        assert_eq!(conflict.name, "music");
        assert_eq!(conflict.holder, first_id);
        assert!(holder.hostname_conflict.is_none(), "{label}");
        // Nothing about being second makes it less of a member.
        assert!(
            loser.online || viewer.agent.endpoint_id() == second_id,
            "{label}"
        );
    }

    // The later one is told so itself, and keeps working.
    let own = second.agent.network_status(network_id).await.unwrap();
    let conflict = own.hostname_conflict.expect("told its name is taken");
    assert_eq!(
        (conflict.name.as_str(), conflict.holder),
        ("music", first_id)
    );
    assert!(
        first
            .agent
            .network_status(network_id)
            .await
            .unwrap()
            .hostname_conflict
            .is_none()
    );

    first.stop().await;
    second.stop().await;
    third.stop().await;
}

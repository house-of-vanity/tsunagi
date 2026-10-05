//! Connectivity does not depend on what kind of link each hop happens to be,
//! and a member is online however far away it is.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use iroh::EndpointId;
use tsunagi::NetworkId;
use tsunagi::agent::DataPath;
use tsunagi::dataplane::transport::SharedLink;
use tsunagi::dataplane::{IpPlugin, PluginCapability, PluginError};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::testing::{TestAgent, network, wait_for_peers, wait_until};

/// A protocol that moves bytes between two members unchanged and keeps the
/// link it was handed, so a test can use the link directly.
#[derive(Debug)]
struct Carrier {
    protocol: String,
    links: Mutex<HashMap<EndpointId, SharedLink>>,
}

impl Carrier {
    fn new(protocol: &str) -> Arc<Self> {
        Arc::new(Self {
            protocol: protocol.into(),
            links: Mutex::default(),
        })
    }

    fn link(&self, peer: EndpointId) -> Option<SharedLink> {
        self.links.lock().unwrap().get(&peer).cloned()
    }
}

impl IpPlugin for Carrier {
    fn protocol_id(&self) -> &str {
        &self.protocol
    }

    fn protocol_version(&self) -> u16 {
        1
    }

    fn local_capability(
        &self,
        _network: NetworkId,
    ) -> Result<Option<PluginCapability>, PluginError> {
        Ok(Some(PluginCapability {
            protocol: self.protocol.clone(),
            version: 1,
            enabled: true,
            data: Vec::new(),
        }))
    }

    fn on_peer_capability(
        &self,
        _network: NetworkId,
        _peer: EndpointId,
        _capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_peer_link(&self, _network: NetworkId, peer: EndpointId, link: SharedLink) {
        self.links.lock().unwrap().insert(peer, link);
    }

    fn on_peer_gone(&self, _network: NetworkId, peer: EndpointId) {
        self.links.lock().unwrap().remove(&peer);
    }

    fn on_network_deactivated(&self, _network: NetworkId) {}
}

type Blocked = Arc<Mutex<HashSet<EndpointId>>>;

async fn member(
    discovery: &SharedMemoryDiscovery,
    plugins: &[Arc<Carrier>],
    blocked: &Blocked,
) -> TestAgent {
    let plugins: Vec<_> = plugins.to_vec();
    let blocked = Arc::clone(blocked);
    TestAgent::spawn_with(
        move |config| {
            let config = config.with_unreachable_data_peers(blocked);
            plugins
                .into_iter()
                .fold(config, |config, plugin| config.with_plugin(plugin))
        },
        discovery,
    )
    .await
    .unwrap()
}

async fn exchange(from: &SharedLink, to: &SharedLink, payload: &'static [u8]) {
    from.send(Bytes::from_static(payload)).unwrap();
    let got = tokio::time::timeout(tsunagi::testing::DEADLINE, to.recv())
        .await
        .expect("the datagram should arrive")
        .expect("the link stays open");
    assert_eq!(got, Bytes::from_static(payload));
}

#[tokio::test]
async fn a_tunnel_crosses_a_member_that_shares_no_protocol_with_either_end_and_moves_to_a_direct_link_by_itself()
 {
    // A and B share one protocol and nothing else. C shares a different
    // one with each, so every link here is of a different kind and the
    // middle has never heard of what A and B speak. A and B cannot reach
    // each other directly, which is the case a blocked UDP path produces.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("mixed-transports");

    let blocked_a: Blocked = Arc::default();
    let blocked_b: Blocked = Arc::default();
    let a_shared = Carrier::new("shared");
    let b_shared = Carrier::new("shared");
    let a = member(
        &discovery,
        &[Carrier::new("a-and-c"), Arc::clone(&a_shared)],
        &blocked_a,
    )
    .await;
    let b = member(
        &discovery,
        &[Carrier::new("c-and-b"), Arc::clone(&b_shared)],
        &blocked_b,
    )
    .await;
    let c = member(
        &discovery,
        &[Carrier::new("a-and-c"), Carrier::new("c-and-b")],
        &Blocked::default(),
    )
    .await;
    let (a_id, b_id, c_id) = (
        a.agent.endpoint_id(),
        b.agent.endpoint_id(),
        c.agent.endpoint_id(),
    );
    blocked_a.lock().unwrap().insert(b_id);
    blocked_b.lock().unwrap().insert(a_id);

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();
    for agent in [&a, &b, &c] {
        wait_for_peers(&agent.agent, network_id, 2).await;
    }

    // The tunnel comes up through C, and data goes both ways.
    let to_b = wait_until("a has a link to b", || async { a_shared.link(b_id) }).await;
    let to_a = wait_until("b has a link to a", || async { b_shared.link(a_id) }).await;
    exchange(&to_b, &to_a, b"a to b, sealed").await;
    exchange(&to_a, &to_b, b"b to a, sealed").await;

    // The status says what is true: online, and through whom.
    let status = a.agent.network_status(network_id).await.unwrap();
    let b_peer = status.peers.iter().find(|p| p.endpoint_id == b_id).unwrap();
    assert_eq!(b_peer.data_path, DataPath::Relayed { hops: 2, via: c_id });
    let c_peer = status.peers.iter().find(|p| p.endpoint_id == c_id).unwrap();
    assert!(matches!(&c_peer.data_path, DataPath::Direct { transport } if transport == "a-and-c"));
    let b_member = wait_until("a lists b as a member", || async {
        let status = a.agent.network_status(network_id).await.ok()?;
        status.members.into_iter().find(|m| m.endpoint_id == b_id)
    })
    .await;
    assert!(b_member.online);
    let carried = c.agent.network_status(network_id).await.unwrap().relay;
    assert!(carried.forwarded >= 2, "{carried:?}");

    // The direct path becomes possible: the same link carries on, now
    // without C, and nobody has to do anything about it.
    blocked_a.lock().unwrap().clear();
    blocked_b.lock().unwrap().clear();
    wait_until("a reaches b directly", || async {
        let status = a.agent.network_status(network_id).await.ok()?;
        let peer = status.peers.iter().find(|p| p.endpoint_id == b_id)?;
        matches!(&peer.data_path, DataPath::Direct { transport } if transport == "shared")
            .then_some(())
    })
    .await;
    let forwarded = c
        .agent
        .network_status(network_id)
        .await
        .unwrap()
        .relay
        .forwarded;
    exchange(&to_b, &to_a, b"direct now").await;
    assert!(
        Arc::ptr_eq(&to_b, &a_shared.link(b_id).unwrap()),
        "the tunnel's link is the one it always had"
    );
    assert_eq!(
        c.agent
            .network_status(network_id)
            .await
            .unwrap()
            .relay
            .forwarded,
        forwarded,
        "nothing goes through C any more"
    );

    a.stop().await;
    b.stop().await;
    c.stop().await;
}

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

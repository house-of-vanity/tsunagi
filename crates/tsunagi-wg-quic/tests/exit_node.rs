//! Exit nodes, end to end: real agents, a real control plane, real iroh data
//! links and real WireGuard, with an in-memory packet interface and a mock
//! host, so no privileges are needed and the machine's network is untouched.
//!
//! One agent offers itself as an exit node; another chooses it, and an
//! ordinary internet packet leaves the second agent's interface, arrives on
//! the first one's, and the answer comes back with the internet's own source
//! address.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::EndpointId;
use tempfile::TempDir;
use tsunagi::dataplane::IpPlugin;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::NetworkId;
use tsunagi::overlay::{
    BroadcastHostRules, MemoryTun, MemoryTunFactory, MockHostRules, OverlayError, TunDevice,
    TunFactory, TunRequest,
};
use tsunagi::testing::{network, wait_until};
use tsunagi::{Agent, NetworkStatus};
use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};

const INTERNET: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// An in-memory interface on a host whose rules are a mock.
///
/// Not "on the host": the agent must not go looking for an address on a real
/// link. It only has host *rules*, which is what an exit node needs from it.
#[derive(Debug, Clone)]
struct RuledTuns {
    tuns: MemoryTunFactory,
    rules: MockHostRules,
}

impl TunFactory for RuledTuns {
    fn name(&self) -> &str {
        "memory-with-rules"
    }

    fn on_host(&self) -> bool {
        false
    }

    fn host_rules(&self) -> Option<Arc<dyn BroadcastHostRules>> {
        Some(Arc::new(self.rules.clone()))
    }

    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> tsunagi::BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
        self.tuns.create(request)
    }

    fn reconfigure<'a>(
        &'a self,
        request: TunRequest,
    ) -> tsunagi::BoxFuture<'a, Result<(), OverlayError>> {
        self.tuns.reconfigure(request)
    }

    fn destroy<'a>(&'a self, name: &'a str) -> tsunagi::BoxFuture<'a, ()> {
        self.tuns.destroy(name)
    }
}

struct Node {
    _dir: TempDir,
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    tuns: MemoryTunFactory,
    rules: MockHostRules,
}

impl Node {
    async fn spawn(discovery: &SharedMemoryDiscovery, tag: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let tuns = MemoryTunFactory::new();
        let rules = MockHostRules::new();
        let plugin = WireguardPlugin::open(
            WireguardConfig::new(dir.path().join("wireguard"))
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        )
        .await
        .unwrap();
        let agent = Agent::spawn(
            tsunagi::testing::config_with(dir.path(), discovery)
                .with_overlay_ipv4_range(Some(tsunagi::state::DEFAULT_IPV4_RANGE))
                .with_interface(
                    Arc::new(RuledTuns {
                        tuns: tuns.clone(),
                        rules: rules.clone(),
                    }),
                    tag,
                    1280,
                )
                .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
        )
        .await
        .unwrap();
        Self {
            _dir: dir,
            agent,
            plugin,
            tuns,
            rules,
        }
    }

    fn id(&self) -> EndpointId {
        self.agent.endpoint_id()
    }

    async fn overlay(&self, network: NetworkId) -> Ipv4Addr {
        wait_until("the network agreed an overlay address", || async {
            self.plugin.overview(network)?.overlay_address_v4
        })
        .await
    }

    async fn tun(&self) -> Arc<MemoryTun> {
        let name = wait_until("the packet interface exists", || async {
            self.agent.overlay().map(|overlay| overlay.interface)
        })
        .await;
        self.tuns.device(&name).expect("the device was created")
    }

    async fn wait_for_tunnels(&self, network: NetworkId, count: usize) {
        wait_until("established WireGuard tunnels", || async {
            let view = self.plugin.overview(network)?;
            (view.established_peers() == count).then_some(())
        })
        .await;
    }

    async fn status(&self, network: NetworkId) -> NetworkStatus {
        self.agent.network_status(network).await.unwrap()
    }
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Bytes {
    let total = 20 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.push((4 << 4) | 5);
    packet.push(0);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(253);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}

async fn next(tun: &MemoryTun) -> Bytes {
    tokio::time::timeout(Duration::from_secs(10), tun.pop_to_os())
        .await
        .expect("a packet reaches the operating system")
        .unwrap()
}

#[tokio::test]
async fn a_member_sends_its_internet_traffic_through_an_exit_node_and_gets_the_answers() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("exit-node");
    let server = Node::spawn(&discovery, "texita").await;
    let client = Node::spawn(&discovery, "texitb").await;
    let id = server.agent.join_network(&name, &secret).await.unwrap();
    client.agent.join_network(&name, &secret).await.unwrap();
    server.wait_for_tunnels(id, 1).await;
    client.wait_for_tunnels(id, 1).await;
    let server_addr = server.overlay(id).await;
    let client_addr = client.overlay(id).await;
    let server_tun = server.tun().await;
    let client_tun = client.tun().await;

    // Off until its owner turns it on: nothing is announced, and choosing it
    // is refused rather than quietly accepted.
    assert!(!server.status(id).await.exit_offer);
    assert!(
        client
            .status(id)
            .await
            .peers
            .iter()
            .all(|peer| !peer.exit_node)
    );
    let refused = client.agent.set_exit_via(id, Some(server.id())).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(client.status(id).await.exit_via.is_none());

    // The server turns it on. Its host rules are applied, and the client
    // learns of it over the control channel.
    server.agent.set_exit_offer(id, true).await.unwrap();
    let plan = server.rules.exit().installed().expect("rules were applied");
    assert_eq!(plan.offer, vec![tsunagi::state::DEFAULT_IPV4_RANGE]);
    assert!(!plan.client);
    let status = server.status(id).await;
    assert!(status.exit_offer);
    assert!(status.exit_rules.offer.as_ref().unwrap().ok);
    wait_until("the client sees an exit node", || async {
        client
            .status(id)
            .await
            .peers
            .iter()
            .any(|peer| peer.endpoint_id == server.id() && peer.exit_node)
            .then_some(())
    })
    .await;

    // The client chooses it; its routes are installed.
    client
        .agent
        .set_exit_via(id, Some(server.id()))
        .await
        .unwrap();
    let status = client.status(id).await;
    assert_eq!(status.exit_via, Some(server.id()));
    assert!(status.exit_via_online);
    assert!(
        client
            .rules
            .exit()
            .installed()
            .expect("client rules")
            .client
    );

    // An ordinary packet for the internet leaves the client's interface and
    // arrives on the server's, from the client's overlay address.
    client_tun.push_from_os(ipv4_packet(client_addr, INTERNET, b"GET /"));
    let request = next(&server_tun).await;
    assert_eq!(&request[12..16], &client_addr.octets());
    assert_eq!(&request[16..20], &INTERNET.octets());
    assert_eq!(&request[20..], b"GET /");

    // The host's answer, from the internet's own address, comes back.
    server_tun.push_from_os(ipv4_packet(INTERNET, client_addr, b"200 OK"));
    let reply = next(&client_tun).await;
    assert_eq!(&reply[12..16], &INTERNET.octets());
    assert_eq!(&reply[16..20], &client_addr.octets());
    assert_eq!(&reply[20..], b"200 OK");

    // Members still reach each other directly, exit node or not.
    client_tun.push_from_os(ipv4_packet(client_addr, server_addr, b"ping"));
    let direct = next(&server_tun).await;
    assert_eq!(&direct[12..16], &client_addr.octets());
    assert_eq!(&direct[16..20], &server_addr.octets());

    // Stopping puts everything back, and the choice is gone.
    client.agent.set_exit_via(id, None).await.unwrap();
    assert!(client.status(id).await.exit_via.is_none());
    assert!(client.rules.exit().installed().is_none());
    server.agent.set_exit_offer(id, false).await.unwrap();
    assert!(server.rules.exit().installed().is_none());
    wait_until("the client sees it withdrawn", || async {
        client
            .status(id)
            .await
            .peers
            .iter()
            .all(|peer| !peer.exit_node)
            .then_some(())
    })
    .await;

    client.agent.shutdown().await;
    server.agent.shutdown().await;
}

#[tokio::test]
async fn an_agent_that_is_not_offering_drops_a_members_internet_packets() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("exit-node-off");
    let server = Node::spawn(&discovery, "texitc").await;
    let client = Node::spawn(&discovery, "texitd").await;
    let id = server.agent.join_network(&name, &secret).await.unwrap();
    client.agent.join_network(&name, &secret).await.unwrap();
    server.wait_for_tunnels(id, 1).await;
    client.wait_for_tunnels(id, 1).await;
    let client_addr = client.overlay(id).await;
    let server_tun = server.tun().await;
    let client_tun = client.tun().await;

    // With no exit node chosen, the client's own interface has nowhere to
    // send the packet, and nothing reaches the server.
    client_tun.push_from_os(ipv4_packet(client_addr, INTERNET, b"nowhere"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server_tun.pop_to_os())
            .await
            .is_err(),
        "nothing was sent"
    );
    assert!(
        server.rules.exit().installed().is_none(),
        "no rules without the switch"
    );

    client.agent.shutdown().await;
    server.agent.shutdown().await;
}

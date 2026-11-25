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
use tsunagi::identity::{NetworkId, NetworkName, NetworkSecret};
use tsunagi::overlay::{MemoryTun, MemoryTunFactory, MockHostRules};
use tsunagi::state::{DEFAULT_IPV4_RANGE, Ipv4Range};
use tsunagi::testing::{network, wait_until};
use tsunagi::{Agent, AgentConfig, NetworkStatus};
use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};

const INTERNET: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

struct Node {
    dir: TempDir,
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    tuns: MemoryTunFactory,
    rules: MockHostRules,
}

impl Node {
    async fn spawn(discovery: &SharedMemoryDiscovery, tag: &str) -> Self {
        Self::open(
            TempDir::new().unwrap(),
            discovery,
            tag,
            Some(DEFAULT_IPV4_RANGE),
        )
        .await
    }

    async fn open(
        dir: TempDir,
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        range: Option<Ipv4Range>,
    ) -> Self {
        let config =
            tsunagi::testing::config_with(dir.path(), discovery).with_overlay_ipv4_range(range);
        Self::start(dir, tag, config).await
    }

    async fn start(dir: TempDir, tag: &str, config: AgentConfig) -> Self {
        let tuns = MemoryTunFactory::new();
        let rules = MockHostRules::new();
        let plugin = WireguardPlugin::open(
            WireguardConfig::new(dir.path().join("wireguard"))
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        )
        .await
        .unwrap();
        let agent = Agent::spawn(
            config
                .with_interface(
                    Arc::new(tuns.clone().with_host_rules(Arc::new(rules.clone()))),
                    tag,
                    1280,
                )
                .with_tunnel(plugin.clone() as Arc<dyn IpPlugin>)
                .with_carrier(Arc::new(
                    tsunagi::dataplane::transport::iroh_link::IrohCarrier,
                )),
        )
        .await
        .unwrap();
        Self {
            dir,
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

    async fn selected_exits(&self) -> Vec<(NetworkId, EndpointId)> {
        self.agent
            .status()
            .await
            .unwrap()
            .networks
            .into_iter()
            .filter_map(|network| Some((network.network_id, network.exit_via?)))
            .collect()
    }

    async fn shutdown(self) -> TempDir {
        self.agent.shutdown().await;
        self.dir
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

struct ExitNetwork<'a> {
    id: NetworkId,
    peer: &'a Node,
    client_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
    peer_tun: Arc<MemoryTun>,
}

impl<'a> ExitNetwork<'a> {
    async fn join(
        client: &Node,
        peer: &'a Node,
        credentials: (NetworkName, NetworkSecret),
    ) -> Self {
        let (name, secret) = credentials;
        let id = peer.agent.join_network(&name, &secret).await.unwrap();
        peer.overlay(id).await;
        let range = peer.status(id).await.range.unwrap();
        peer.agent.set_exit_offer(id, true).await.unwrap();
        client.agent.join_network(&name, &secret).await.unwrap();
        client.wait_for_tunnels(id, 1).await;
        peer.wait_for_tunnels(id, 1).await;
        let client_addr = wait_until(
            "client adopts the peer's range and sees its exit offer",
            || async {
                let address = client.plugin.overview(id)?.overlay_address_v4?;
                (range.contains(address)
                    && client
                        .status(id)
                        .await
                        .peers
                        .iter()
                        .any(|p| p.endpoint_id == peer.id() && p.exit_node))
                .then_some(address)
            },
        )
        .await;
        Self {
            id,
            peer,
            client_addr,
            peer_addr: peer.overlay(id).await,
            peer_tun: peer.tun().await,
        }
    }

    async fn check_mesh(&self, client_tun: &MemoryTun) {
        let request = ipv4_packet(self.client_addr, self.peer_addr, self.id.as_bytes());
        client_tun.push_from_os(request.clone());
        assert_eq!(next(&self.peer_tun).await, request);
        let reply = ipv4_packet(self.peer_addr, self.client_addr, self.id.as_bytes());
        self.peer_tun.push_from_os(reply.clone());
        assert_eq!(next(client_tun).await, reply);
    }
}

#[tokio::test]
async fn switching_the_exit_between_networks_keeps_both_overlays_reachable() {
    let discovery = SharedMemoryDiscovery::new();
    let client = Node::open(TempDir::new().unwrap(), &discovery, "client", None).await;
    let left = Node::spawn(&discovery, "left").await;
    let right_range = "10.99.0.0/16".parse().unwrap();
    let right = Node::open(
        TempDir::new().unwrap(),
        &discovery,
        "right",
        Some(right_range),
    )
    .await;
    let alpha = ExitNetwork::join(&client, &left, network("exit-left")).await;
    let beta = ExitNetwork::join(&client, &right, network("exit-right")).await;
    let tun = client.tun().await;

    for exit in [&alpha, &beta] {
        client
            .agent
            .set_exit_via(exit.id, Some(exit.peer.id()))
            .await
            .unwrap();
        let plan = client.rules.exit().installed().unwrap();
        assert_eq!(plan.client_source, Some(exit.client_addr));
        assert_eq!(plan.overlay.len(), 2);
        let internet = ipv4_packet(exit.client_addr, INTERNET, b"request");
        tun.push_from_os(internet.clone());
        assert_eq!(next(&exit.peer_tun).await, internet);
        let reply = ipv4_packet(INTERNET, exit.client_addr, b"reply");
        exit.peer_tun.push_from_os(reply.clone());
        assert_eq!(next(&tun).await, reply);

        for net in [&alpha, &beta] {
            let selected = (net.id == exit.id).then(|| net.peer.id());
            assert_eq!(client.status(net.id).await.exit_via, selected);
            net.check_mesh(&tun).await;
        }
    }
    // Right offers on beta only. An invalid replacement must preserve the live route.
    assert!(
        client
            .agent
            .set_exit_via(alpha.id, Some(right.id()))
            .await
            .is_err()
    );
    assert_eq!(client.selected_exits().await, [(beta.id, right.id())]);
    let request = ipv4_packet(beta.client_addr, INTERNET, b"still using beta");
    tun.push_from_os(request.clone());
    assert_eq!(next(&beta.peer_tun).await, request);

    // Two independent commands may race. Both must leave one effective exit,
    // and restarting from the same SQLite state must restore that exact choice.
    let (one, two) = tokio::join!(
        client.agent.set_exit_via(alpha.id, Some(left.id())),
        client.agent.set_exit_via(beta.id, Some(right.id())),
    );
    one.unwrap();
    two.unwrap();
    let exits = client.selected_exits().await;
    assert!(
        exits == [(alpha.id, left.id())] || exits == [(beta.id, right.id())],
        "{exits:?}"
    );
    let (lost, live) = if exits[0].0 == alpha.id {
        (&alpha, &beta)
    } else {
        (&beta, &alpha)
    };
    lost.peer.agent.shutdown().await;
    client.wait_for_tunnels(lost.id, 0).await;
    wait_until("the selected exit is offline", || async {
        let status = client.status(lost.id).await;
        (status.exit_via == Some(lost.peer.id()) && !status.exit_via_online).then_some(())
    })
    .await;
    assert!(client.rules.exit().installed().unwrap().client);
    let dropped = client.agent.overlay().unwrap().counters.undeliverable;
    tun.push_from_os(ipv4_packet(lost.client_addr, INTERNET, b"offline exit"));
    wait_until(
        "internet traffic cannot use the other offering peer",
        || async { (client.agent.overlay()?.counters.undeliverable > dropped).then_some(()) },
    )
    .await;
    live.check_mesh(&tun).await;

    let dir = client.shutdown().await;
    let restarted = Node::open(dir, &discovery, "client", None).await;
    assert_eq!(restarted.selected_exits().await, exits);
    restarted.agent.shutdown().await;
    live.peer.agent.shutdown().await;
}

async fn shared_nodes() -> (Node, Node) {
    let discovery = SharedMemoryDiscovery::new();
    let client = Node::open(TempDir::new().unwrap(), &discovery, "client", None).await;
    let dir = TempDir::new().unwrap();
    let config = tsunagi::testing::config_with(dir.path(), &discovery);
    let peer = Node::start(dir, "shared", config).await;
    (client, peer)
}

async fn shared_networks<'a>(client: &Node, peer: &'a Node) -> [ExitNetwork<'a>; 2] {
    // Fixed credentials keep the two automatically derived /24s distinct.
    let join = |name, secret| {
        let credentials = (
            NetworkName::new(name).unwrap(),
            NetworkSecret::from_bytes(secret).unwrap(),
        );
        ExitNetwork::join(client, peer, credentials)
    };
    [
        join("shared-left", [1; 32]).await,
        join("shared-right", [2; 32]).await,
    ]
}

#[tokio::test]
#[ignore = "observes a full 180-second WireGuard key lifetime on real clocks"]
async fn only_the_selected_exit_stays_keyed_through_idle_expiry() {
    let (client, peer) = shared_nodes().await;
    let [chosen, other] = shared_networks(&client, &peer).await;
    client
        .agent
        .set_exit_via(chosen.id, Some(peer.id()))
        .await
        .unwrap();
    let tunnel = |network| {
        client
            .plugin
            .overview(network)
            .unwrap()
            .peers
            .into_iter()
            .find(|p| p.endpoint_id == peer.id())
            .unwrap()
            .tunnel
            .unwrap()
    };
    let epoch = tunnel(chosen.id).stats.counter_epoch;
    let mut old_key_seen = false;
    tokio::time::timeout(Duration::from_secs(210), async {
        let mut poll = tokio::time::interval(Duration::from_millis(500));
        loop {
            poll.tick().await;
            let warm = tunnel(chosen.id);
            let cold = tunnel(other.id);
            assert_eq!(warm.stats.counter_epoch, epoch);
            let warm_age = warm
                .health
                .since_handshake
                .expect("usable exit key throughout idle");
            assert_eq!((warm.stats.tx_bytes, warm.stats.rx_bytes), (0, 0));
            assert_eq!((cold.stats.tx_bytes, cold.stats.rx_bytes), (0, 0));
            if cold
                .health
                .since_handshake
                .is_some_and(|age| age >= Duration::from_secs(150))
            {
                old_key_seen = true;
            }
            if old_key_seen && !cold.health.is_up() {
                assert!(
                    warm_age < Duration::from_secs(90),
                    "exit key renewed before expiry"
                );
                assert!(warm.health.idle && cold.health.idle);
                break;
            }
        }
    })
    .await
    .expect("unselected peer's unused session expired");

    let packet = ipv4_packet(chosen.client_addr, INTERNET, b"first IP packet after idle");
    client.tun().await.push_from_os(packet.clone());
    assert_eq!(next(&chosen.peer_tun).await, packet);
    assert!(!tunnel(chosen.id).health.idle);
    client
        .agent
        .set_exit_via(other.id, Some(peer.id()))
        .await
        .unwrap();
    client.wait_for_tunnels(other.id, 1).await;
    assert!(tunnel(other.id).health.idle, "warming sends no IP payload");
    client.agent.shutdown().await;
    peer.agent.shutdown().await;
}

#[tokio::test]
async fn selecting_a_shared_peer_uses_only_the_chosen_membership_for_exit() {
    let (client, peer) = shared_nodes().await;
    let meshes = shared_networks(&client, &peer).await;
    let tun = client.tun().await;
    for (chosen, other) in [(&meshes[0], &meshes[1]), (&meshes[1], &meshes[0])] {
        client
            .agent
            .set_exit_via(chosen.id, Some(peer.id()))
            .await
            .unwrap();
        assert_eq!(client.selected_exits().await, [(chosen.id, peer.id())]);
        assert_eq!(
            client.rules.exit().installed().unwrap().client_source,
            Some(chosen.client_addr)
        );
        chosen.check_mesh(&tun).await;
        other.check_mesh(&tun).await;
        let request = ipv4_packet(chosen.client_addr, INTERNET, b"external");
        tun.push_from_os(request.clone());
        assert_eq!(next(&chosen.peer_tun).await, request);
        // Both memberships authenticate the same device key. A reply through
        // its other tunnel still lacks the external-source exception.
        let wrong_source = client.agent.overlay().unwrap().counters.wrong_source;
        chosen
            .peer_tun
            .push_from_os(ipv4_packet(INTERNET, other.client_addr, b"wrong mesh"));
        wait_until(
            "external reply on unselected membership is rejected",
            || async {
                (client.agent.overlay()?.counters.wrong_source > wrong_source).then_some(())
            },
        )
        .await;
        let reply = ipv4_packet(INTERNET, chosen.client_addr, b"reply");
        chosen.peer_tun.push_from_os(reply.clone());
        assert_eq!(next(&tun).await, reply);
        let expected = tsunagi::overlay::exit::ExitTraffic {
            tx_bytes: request.len() as u64,
            rx_bytes: reply.len() as u64,
        };
        wait_until("exit totals for the selected membership", || async {
            (client.status(chosen.id).await.exit_traffic == Some(expected)).then_some(())
        })
        .await;
        assert_eq!(client.status(other.id).await.exit_traffic, None);
    }
    peer.agent.shutdown().await;
    client.agent.shutdown().await;
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

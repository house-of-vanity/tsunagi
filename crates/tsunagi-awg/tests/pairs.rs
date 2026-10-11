//! Real membership, UDP sockets, pair negotiation and nested WireGuard encryption.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use bytes::Bytes;
use std::{
    net::Ipv4Addr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::transport::{
    ControlSender, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::overlay::{MemoryTun, MemoryTunFactory};
use tsunagi::testing::{config_with, network, wait_for_peers, wait_until};
use tsunagi::{Agent, BoxFuture, NetworkId};
use tsunagi_awg::{AWG_PROTOCOL, AwgPlugin, AwgTransport};
use tsunagi_wg_quic::WireguardConfig;

struct Node {
    agent: Agent,
    plugin: Arc<AwgPlugin>,
    transport: Arc<AwgTransport>,
    tuns: MemoryTunFactory,
    loss: Arc<AtomicBool>,
}
impl Node {
    async fn open(root: &Path, discovery: &SharedMemoryDiscovery, interface: &str) -> Self {
        Self::open_with_fallback(root, discovery, interface, false).await
    }
    async fn open_with_fallback(
        root: &Path,
        discovery: &SharedMemoryDiscovery,
        interface: &str,
        fallback: bool,
    ) -> Self {
        Self::open_config(root, discovery, interface, fallback, 1280).await
    }
    async fn open_config(
        root: &Path,
        discovery: &SharedMemoryDiscovery,
        interface: &str,
        fallback: bool,
        mtu: u32,
    ) -> Self {
        let identity =
            tsunagi::storage::StateStore::open(tsunagi::StoragePaths::under(root).state_db())
                .unwrap()
                .load_or_create_device_identity()
                .unwrap();
        let transport = AwgTransport::new(identity.endpoint_id(), Ipv4Addr::LOCALHOST);
        let plugin = AwgPlugin::open(
            WireguardConfig::new(root.join("awg"))
                .with_mtu(mtu)
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
            transport.clone(),
        )
        .await
        .unwrap();
        let loss = Arc::new(AtomicBool::new(false));
        let faults = Arc::new(FaultTransport {
            inner: transport.clone(),
            loss: loss.clone(),
        });
        let tuns = MemoryTunFactory::new();
        let mut config = config_with(root, discovery)
            .with_interface(Arc::new(tuns.clone()), interface, mtu)
            .with_overlay_ipv4_range(Some(tsunagi::state::DEFAULT_IPV4_RANGE))
            .with_plugin(plugin.clone() as Arc<dyn IpPlugin>)
            .with_custom_transport(AWG_PROTOCOL, faults);
        if fallback {
            let quic = tsunagi_wg_quic::WireguardPlugin::open(
                WireguardConfig::new(root.join("wg-quic"))
                    .with_mtu(mtu)
                    .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
            )
            .await
            .unwrap();
            config = config.with_plugin(quic);
        }
        let agent = Agent::spawn(config).await.unwrap();
        let inbound_agent = agent.clone();
        let inbound_transport = transport.clone();
        let inbound_loss = loss.clone();
        tokio::spawn(async move {
            while let Some(mut link) = inbound_transport.next_inbound().await {
                link.link = impaired(link.link, inbound_loss.clone());
                let _ = inbound_agent.install_inbound_link(link).await;
            }
        });
        Self {
            agent,
            plugin,
            transport,
            tuns,
            loss,
        }
    }
    async fn ready(&self, id: NetworkId, n: usize) {
        wait_until("AWG outer paths and end-to-end handshakes", || async {
            (self
                .transport
                .overview(id)
                .iter()
                .filter(|p| !p.closed && !p.path.contains("establishing"))
                .count()
                == n
                && self
                    .plugin
                    .overview(id)?
                    .peers
                    .iter()
                    .filter(|p| {
                        p.tunnel
                            .as_ref()
                            .is_some_and(|t| t.health.is_up() && t.path.contains("awg UDP via"))
                    })
                    .count()
                    == n)
                .then_some(())
        })
        .await;
    }
    fn tun(&self) -> Arc<MemoryTun> {
        self.tuns
            .device(&self.agent.overlay().unwrap().interface)
            .unwrap()
    }
    fn addr(&self, id: NetworkId) -> Ipv4Addr {
        self.plugin
            .overview(id)
            .unwrap()
            .overlay_address_v4
            .unwrap()
    }
}
fn packet(source: Ipv4Addr, dest: Ipv4Addr, len: usize) -> Bytes {
    let mut bytes = vec![0; len];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 253;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&dest.octets());
    rand::fill(&mut bytes[20..]);
    Bytes::from(bytes)
}
async fn exchange(a: &Node, b: &Node, id: NetworkId) {
    for len in [64, 1097, 1280] {
        let bytes = packet(a.addr(id), b.addr(id), len);
        a.tun().push_from_os(bytes.clone());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), b.tun().pop_to_os())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
    }
}
#[tokio::test]
async fn real_pairs_carry_full_size_packets_and_restart_with_fresh_profiles() {
    tsunagi::testing::init_tracing();
    let discovery = SharedMemoryDiscovery::new();
    let roots = [
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    ];
    let a = Node::open(roots[0].path(), &discovery, "awga").await;
    let b = Node::open(roots[1].path(), &discovery, "awgb").await;
    let c = Node::open(roots[2].path(), &discovery, "awgc").await;
    let (name, secret) = network("awg-pairs");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();
    for node in [&a, &b, &c] {
        wait_for_peers(&node.agent, id, 2).await;
        node.ready(id, 2).await;
    }
    let ids: std::collections::HashSet<_> = [&a, &b, &c]
        .into_iter()
        .flat_map(|n| n.transport.overview(id).into_iter().map(|p| p.attempt))
        .collect();
    assert_eq!(
        ids.len(),
        3,
        "one independent profile for each of three pairs"
    );
    exchange(&a, &b, id).await;
    exchange(&b, &a, id).await;
    exchange(&a, &c, id).await;
    let old_ports: Vec<_> = a
        .transport
        .overview(id)
        .into_iter()
        .filter_map(|p| p.local_port)
        .collect();
    a.agent.shutdown().await;
    for port in old_ports {
        wait_until("old pair socket released", || async {
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .ok()
        })
        .await;
    }
    let restarted = Node::open(roots[0].path(), &discovery, "awga").await;
    restarted.ready(id, 2).await;
    assert!(
        restarted
            .transport
            .overview(id)
            .iter()
            .all(|p| !ids.contains(&p.attempt))
    );
    exchange(&restarted, &b, id).await;
    exchange(&c, &restarted, id).await;
    restarted.agent.shutdown().await;
    b.agent.shutdown().await;
    c.agent.shutdown().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), restarted.transport.next_inbound())
            .await
            .unwrap()
            .is_none()
    );
}

// Drops datagrams at the link boundary. Membership, control, sockets, crypto,
// addressing and storage remain real. This substitutes a lossy physical path.
#[derive(Debug)]
struct FaultTransport {
    inner: Arc<AwgTransport>,
    loss: Arc<AtomicBool>,
}
impl PacketTransport for FaultTransport {
    fn name(&self) -> &str {
        AWG_PROTOCOL
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn attach_control(&self, sender: Arc<dyn ControlSender>) {
        self.inner.attach_control(sender);
    }
    fn on_control(
        &self,
        network: NetworkId,
        peer: iroh::EndpointId,
        protocol: &str,
        bytes: &[u8],
    ) -> Result<(), TransportError> {
        self.inner.on_control(network, peer, protocol, bytes)
    }
    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: iroh::EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async move {
            Ok(impaired(
                self.inner.open(network, peer, protocol).await?,
                self.loss.clone(),
            ))
        })
    }
}
fn impaired(raw: SharedLink, loss: Arc<AtomicBool>) -> SharedLink {
    Arc::new(FaultLink {
        raw,
        loss,
        sequence: AtomicU64::new(0),
    })
}
#[derive(Debug)]
struct FaultLink {
    raw: SharedLink,
    loss: Arc<AtomicBool>,
    sequence: AtomicU64,
}
impl PacketLink for FaultLink {
    fn network(&self) -> NetworkId {
        self.raw.network()
    }
    fn peer(&self) -> iroh::EndpointId {
        self.raw.peer()
    }
    fn max_datagram_size(&self) -> usize {
        self.raw.max_datagram_size()
    }
    fn send(&self, bytes: Bytes) -> Result<(), TransportError> {
        if self.loss.load(Ordering::Relaxed)
            && !self
                .sequence
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(5)
        {
            Ok(())
        } else {
            self.raw.send(bytes)
        }
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        self.raw.recv()
    }
    fn closed(&self) -> BoxFuture<'_, ()> {
        self.raw.closed()
    }
    fn is_closed(&self) -> bool {
        self.raw.is_closed()
    }
    fn close(&self) {
        self.raw.close();
    }
    fn path_description(&self) -> String {
        self.raw.path_description()
    }
}
#[tokio::test]
async fn persistent_runtime_loss_retires_the_pair_and_negotiates_fresh_parameters() {
    let discovery = SharedMemoryDiscovery::new();
    let roots = [TempDir::new().unwrap(), TempDir::new().unwrap()];
    let a = Node::open(roots[0].path(), &discovery, "lossa").await;
    let b = Node::open(roots[1].path(), &discovery, "lossb").await;
    let (name, secret) = network("awg-loss");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.ready(id, 1).await;
    b.ready(id, 1).await;
    exchange(&a, &b, id).await;
    let old = a.transport.overview(id)[0].attempt;
    let mut events = a.agent.subscribe();
    a.loss.store(true, Ordering::Relaxed);
    tsunagi::testing::wait_event(&mut events, |event| match event {
        tsunagi::Event::DataLinkDown {
            network, reason, ..
        } if *network == id && reason.contains("delivery checks") => Some(()),
        _ => None,
    })
    .await;
    a.loss.store(false, Ordering::Relaxed);
    wait_until("fresh AWG profile after runtime loss", || async {
        a.transport
            .overview(id)
            .iter()
            .any(|p| p.attempt != old && !p.closed && !p.path.contains("establishing"))
            .then_some(())
    })
    .await;
    a.ready(id, 1).await;
    b.ready(id, 1).await;
    let initiator = if a.agent.endpoint_id().as_bytes() < b.agent.endpoint_id().as_bytes() {
        &a
    } else {
        &b
    };
    let received = initiator.plugin.overview(id).unwrap().peers[0]
        .tunnel
        .as_ref()
        .unwrap()
        .stats
        .rx_packets;
    let attempt = initiator.transport.overview(id)[0].attempt;
    wait_until(
        "fresh pair delivery checks answered after installation",
        || async {
            let view = initiator.plugin.overview(id)?;
            (view.peers.first()?.tunnel.as_ref()?.stats.rx_packets >= received + 3).then_some(())
        },
    )
    .await;
    assert_eq!(initiator.transport.overview(id)[0].attempt, attempt);
    wait_for_peers(&a.agent, id, 1).await;
    exchange(&a, &b, id).await;
    exchange(&b, &a, id).await;
    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn runtime_loss_falls_back_to_real_iroh_without_interrupting_control_or_ip() {
    let discovery = SharedMemoryDiscovery::new();
    let roots = [TempDir::new().unwrap(), TempDir::new().unwrap()];
    let a = Node::open_with_fallback(roots[0].path(), &discovery, "fallba", true).await;
    let b = Node::open_with_fallback(roots[1].path(), &discovery, "fallbb", true).await;
    let (name, secret) = network("awg-fallback");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.ready(id, 1).await;
    b.ready(id, 1).await;
    exchange(&a, &b, id).await;
    let mut events = a.agent.subscribe();
    a.loss.store(true, Ordering::Relaxed);
    tsunagi::testing::wait_event(&mut events, |event| match event {
        tsunagi::Event::DataLinkDown {
            network, reason, ..
        } if *network == id && reason.contains("delivery checks") => Some(()),
        _ => None,
    })
    .await;
    for node in [&a, &b] {
        wait_until("fallback carrier is wg-quic",||async {
            let status=node.agent.status().await.ok()?;
            let network=status.networks.iter().find(|n|n.network_id==id)?;
            (network.members.iter().any(|m|matches!(&m.data_path,tsunagi::agent::DataPath::Direct{transport} if transport=="wg-quic"))).then_some(())
        }).await;
        wait_for_peers(&node.agent, id, 1).await;
    }
    exchange(&a, &b, id).await;
    exchange(&b, &a, id).await;
    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[tokio::test]
async fn opaque_pair_carrier_fragments_its_full_advertised_capacity() {
    let discovery = SharedMemoryDiscovery::new();
    let roots = [TempDir::new().unwrap(), TempDir::new().unwrap()];
    let mut nodes = Vec::new();
    for root in &roots {
        let identity = tsunagi::storage::StateStore::open(
            tsunagi::StoragePaths::under(root.path()).state_db(),
        )
        .unwrap()
        .load_or_create_device_identity()
        .unwrap();
        let transport = AwgTransport::new(identity.endpoint_id(), Ipv4Addr::LOCALHOST);
        let agent = Agent::spawn(
            config_with(root.path(), &discovery)
                .with_custom_transport(AWG_PROTOCOL, transport.clone()),
        )
        .await
        .unwrap();
        nodes.push((agent, transport));
    }
    let (name, secret) = network("awg-capacity");
    let id = nodes[0].0.join_network(&name, &secret).await.unwrap();
    nodes[1].0.join_network(&name, &secret).await.unwrap();
    for (i, (agent, transport)) in nodes.iter().enumerate() {
        wait_for_peers(agent, id, 1).await;
        // This fixture tests only the transport contract: register the member
        // after the real core has authenticated it, without an IP plugin/TUN.
        transport.allow_peer(id, nodes[1 - i].0.endpoint_id());
    }
    nodes.sort_by_key(|(agent, _)| *agent.endpoint_id().as_bytes());
    let outgoing = nodes[0]
        .1
        .open(id, nodes[1].0.endpoint_id(), AWG_PROTOCOL)
        .await
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), nodes[1].1.next_inbound())
        .await
        .unwrap()
        .unwrap()
        .link;
    for (from, to) in [(&outgoing, &incoming), (&incoming, &outgoing)] {
        let mut bytes = vec![0; from.max_datagram_size()];
        rand::fill(&mut bytes[..]);
        let bytes = Bytes::from(bytes);
        from.send(bytes.clone()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), to.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
        assert!(matches!(
            from.send(Bytes::from(vec![0; from.max_datagram_size() + 1])),
            Err(TransportError::TooLarge { .. })
        ));
    }
    outgoing.close();
    incoming.close();
    for (agent, transport) in nodes {
        transport.shutdown();
        agent.shutdown().await;
    }
}

#[tokio::test]
async fn encrypted_health_checks_fit_a_smaller_peers_configured_interface_mtu() {
    let discovery = SharedMemoryDiscovery::new();
    let roots = [TempDir::new().unwrap(), TempDir::new().unwrap()];
    let a = Node::open_config(roots[0].path(), &discovery, "smalla", false, 1280).await;
    let b = Node::open_config(roots[1].path(), &discovery, "smallb", false, 576).await;
    let (name, secret) = network("awg-small-mtu");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.ready(id, 1).await;
    b.ready(id, 1).await;
    let bytes = packet(a.addr(id), b.addr(id), 576);
    a.tun().push_from_os(bytes.clone());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), b.tun().pop_to_os())
            .await
            .unwrap()
            .unwrap(),
        bytes
    );
    wait_until(
        "encrypted delivery checks answered with a small MTU",
        || async {
            let view = a.plugin.overview(id)?;
            let peer = view.peers.first()?.tunnel.as_ref()?;
            (peer.stats.rx_packets >= 3).then_some(())
        },
    )
    .await;
    for node in [&a, &b] {
        assert_eq!(
            node.plugin.overview(id).unwrap().peers[0]
                .tunnel
                .as_ref()
                .unwrap()
                .stats
                .dropped_oversize,
            0
        );
    }
    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

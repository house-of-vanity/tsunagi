//! Real membership and one internal cipher over each independent external carrier.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use bytes::Bytes;
use iroh::EndpointId;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tsunagi::dataplane::transport::{DataCarrier, PacketTransport, SharedLink, TransportError};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::overlay::{MemoryTun, MemoryTunFactory};
use tsunagi::testing::{config_with, network, wait_for_peers, wait_until};
use tsunagi::{Agent, BoxFuture, NetworkId};
use tsunagi_tcp_tls::{TcpTlsCarrier, TcpTlsTransport};
use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};
use tsunagi_wireguard::{UdpCarrier, UdpTransport};

// Only address selection is constrained to loopback. TLS sockets, identity
// verification, framing, membership and both encryption layers remain real.
#[derive(Debug)]
struct LoopbackTls {
    inner: Arc<TcpTlsTransport>,
    ports: Arc<std::sync::Mutex<Vec<(EndpointId, u16)>>>,
}
impl PacketTransport for LoopbackTls {
    fn name(&self) -> &str {
        "tcp-tls"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        let port = self
            .ports
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| *id == peer)
            .unwrap()
            .1;
        self.inner
            .replace_peer_addrs(peer, vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))]);
        self.inner.open(network, peer, protocol)
    }
}

struct Node {
    _root: TempDir,
    agent: Agent,
    tunnel: Arc<WireguardPlugin>,
    tuns: MemoryTunFactory,
    accept: tokio::task::JoinHandle<()>,
}
impl Node {
    async fn new(
        discovery: &SharedMemoryDiscovery,
        protocol: &str,
        ports: Arc<std::sync::Mutex<Vec<(EndpointId, u16)>>>,
    ) -> Self {
        Self::configured(discovery, &[protocol], ports, true).await
    }
    async fn configured(
        discovery: &SharedMemoryDiscovery,
        protocols: &[&str],
        ports: Arc<std::sync::Mutex<Vec<(EndpointId, u16)>>>,
        register_transport: bool,
    ) -> Self {
        let root = TempDir::new().unwrap();
        let identity = tsunagi::storage::StateStore::open(
            tsunagi::StoragePaths::under(root.path()).state_db(),
        )
        .unwrap()
        .load_or_create_device_identity()
        .unwrap();
        let tunnel = WireguardPlugin::open(
            WireguardConfig::new(root.path().join("cipher"))
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        )
        .await
        .unwrap();
        let tuns = MemoryTunFactory::new();
        let config = config_with(root.path(), discovery)
            .with_interface(Arc::new(tuns.clone()), "carrier-test", 1280)
            .with_tunnel(tunnel.clone());
        let protocol = protocols[0];
        let (agent, accept) = if protocol == "wg" {
            let transport =
                UdpTransport::wireguard(identity.endpoint_id(), Ipv4Addr::LOCALHOST, None);
            let carrier: Arc<dyn DataCarrier> = UdpCarrier::new(transport.clone());
            let mut config = config.with_carrier(carrier);
            if register_transport {
                config = config.with_custom_transport(protocol, transport.clone());
            }
            let agent = Agent::spawn(config).await.unwrap();
            let incoming = agent.clone();
            let accept = tokio::spawn(async move {
                while let Some(link) = transport.next_inbound().await {
                    let _ = incoming.install_inbound_link(link).await;
                }
            });
            (agent, accept)
        } else {
            let transport = Arc::new(
                TcpTlsTransport::bind(&identity, Some(0), None)
                    .await
                    .unwrap(),
            );
            ports
                .lock()
                .unwrap()
                .push((identity.endpoint_id(), transport.bound_port()));
            let carrier: Arc<dyn DataCarrier> = TcpTlsCarrier::new(transport.clone());
            let custom = Arc::new(LoopbackTls {
                inner: transport.clone(),
                ports,
            });
            let mut config = config
                .with_carrier(carrier)
                .with_custom_transport(protocol, custom);
            if protocols.contains(&"wg-quic") {
                config = config.with_carrier(Arc::new(
                    tsunagi::dataplane::transport::iroh_link::IrohCarrier,
                ));
            }
            let agent = Agent::spawn(config).await.unwrap();
            let incoming = agent.clone();
            let accept = tokio::spawn(async move {
                transport
                    .accept_loop(move |link| {
                        let incoming = incoming.clone();
                        tokio::spawn(async move {
                            let _ = incoming.install_inbound_link(link).await;
                        });
                    })
                    .await;
            });
            (agent, accept)
        };
        Self {
            _root: root,
            agent,
            tunnel,
            tuns,
            accept,
        }
    }
    fn tun(&self) -> Arc<MemoryTun> {
        self.tuns
            .device(&self.agent.overlay().unwrap().interface)
            .unwrap()
    }
    fn addr(&self, network: NetworkId) -> Ipv4Addr {
        self.tunnel
            .overview(network)
            .unwrap()
            .overlay_address_v4
            .unwrap()
    }
}

// Real TLS bytes flow through this loopback proxy. Delay one direction so
// authenticated probes can distinguish two otherwise healthy carriers.
async fn delayed_tcp_listener(port: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut streams = tokio::task::JoinSet::new();
        while let Ok((client, _)) = listener.accept().await {
            streams.spawn(async move {
                let server = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
                let (mut from_client, mut to_client) = client.into_split();
                let (mut from_server, mut to_server) = server.into_split();
                let delayed = async {
                    let mut buffer = [0; 8192];
                    loop {
                        let n = from_client.read(&mut buffer).await?;
                        if n == 0 {
                            return Ok::<(), std::io::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(85)).await;
                        to_server.write_all(&buffer[..n]).await?;
                    }
                };
                tokio::select! {
                    res = delayed => res,
                    res = tokio::io::copy(&mut from_server, &mut to_client) => res.map(|_| ()),
                }
            });
        }
    });
    (local_port, task)
}

#[tokio::test]
async fn data_flows_over_the_incumbent_while_a_faster_carrier_is_measured_and_promoted() {
    use tsunagi::agent::{DataPath, Event};
    let discovery = SharedMemoryDiscovery::new();
    let ports = Arc::default();
    let protocols = ["tcp-tls", "wg-quic"];
    let a = Node::configured(&discovery, &protocols, Arc::clone(&ports), true).await;
    let b = Node::configured(&discovery, &protocols, Arc::clone(&ports), true).await;
    let mut proxies = Vec::new();
    let registered = ports.lock().unwrap().clone();
    for (peer, port) in registered {
        let (proxy_port, task) = delayed_tcp_listener(port).await;
        proxies.push(task);
        ports
            .lock()
            .unwrap()
            .iter_mut()
            .find(|(id, _)| *id == peer)
            .unwrap()
            .1 = proxy_port;
    }
    let mut events = a.agent.subscribe();
    let (name, secret) = network("measured-carrier");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    let observations = |node: &Node| {
        let overview = node.tunnel.overview(id)?;
        let tunnel = overview.peers.first()?.tunnel.as_ref()?;
        tunnel.health.is_up().then_some(tunnel.stats.counter_epoch)
    };
    let epochs = wait_until(
        "both endpoints have a single established cipher",
        || async { Some((observations(&a)?, observations(&b)?)) },
    )
    .await;
    let selected = |protocol: &str, status: &tsunagi::NetworkStatus| {
        matches!(status.peers.first().map(|p| &p.data_path),
            Some(DataPath::Direct { transport }) if transport == protocol)
    };
    async fn deliver(source: &Node, destination: &Node, id: NetworkId, tag: u8) {
        let mut packet = vec![0; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&32_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 253;
        packet[12..16].copy_from_slice(&source.addr(id).octets());
        packet[16..20].copy_from_slice(&destination.addr(id).octets());
        packet[20] = tag;
        let packet = Bytes::from(packet);
        source.tun().push_from_os(packet.clone());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), destination.tun().pop_to_os())
                .await
                .unwrap()
                .unwrap(),
            packet
        );
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        wait_until("slow TLS data-link probes are visible", || async {
            let status = a.agent.network_status(id).await.ok()?;
            (selected("tcp-tls", &status) && status.peers.first()?.data_rtt? >= Duration::from_millis(75)).then_some(())
        }).await;
        deliver(&a, &b, id, 1).await;
        tsunagi::testing::wait_event(&mut events, |event| {
            matches!(event, Event::DataLinkUp { network, protocol, .. } if *network == id && protocol == "wg-quic").then_some(())
        }).await;
        for (source, dest) in [(&a, &b), (&b, &a)] {
            assert!(selected("tcp-tls", &source.agent.network_status(id).await.unwrap()));
            deliver(source, dest, id, 2).await;
        }
        wait_until("both endpoints use the faster measured data link", || async {
            let left = a.agent.network_status(id).await.ok()?;
            let right = b.agent.network_status(id).await.ok()?;
            (selected("wg-quic", &left) && selected("wg-quic", &right)).then_some(())
        }).await;
        for (source, dest) in [(&a, &b), (&b, &a)] {
            deliver(source, dest, id, 3).await;
        }
        assert_eq!((observations(&a), observations(&b)), (Some(epochs.0), Some(epochs.1)));
    }).await.expect("comparison must finish with traffic on the existing tunnel");
    a.agent.shutdown().await;
    b.agent.shutdown().await;
    a.accept.abort();
    b.accept.abort();
    for proxy in proxies {
        proxy.abort();
    }
}

#[tokio::test]
async fn missing_native_transport_cannot_silently_turn_wireguard_into_quic() {
    let discovery = SharedMemoryDiscovery::new();
    let ports = Arc::default();
    let a = Node::configured(&discovery, &["wg"], Arc::clone(&ports), false).await;
    let b = Node::configured(&discovery, &["wg"], ports, false).await;
    let (name, secret) = network("no-disguised-quic-fallback");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, id, 1).await;
    let initiator = if a.agent.endpoint_id().as_bytes() < b.agent.endpoint_id().as_bytes() {
        &a
    } else {
        &b
    };
    wait_until(
        "missing carrier implementation is explicitly refused",
        || async {
            let status = initiator.agent.network_status(id).await.ok()?;
            let peer = status.peers.first()?;
            (peer
                .data_error
                .as_deref()
                .is_some_and(|reason| reason.contains("registered"))
                && matches!(peer.data_path, tsunagi::agent::DataPath::None))
            .then_some(())
        },
    )
    .await;
    a.agent.shutdown().await;
    b.agent.shutdown().await;
    a.accept.abort();
    b.accept.abort();
}

#[tokio::test]
async fn wireguard_and_tls_carriers_both_carry_the_same_internal_cipher_and_exact_plaintext_counters()
 {
    for protocol in ["wg", "tcp-tls"] {
        let discovery = SharedMemoryDiscovery::new();
        let ports = Arc::default();
        let a = Node::new(&discovery, protocol, Arc::clone(&ports)).await;
        let b = Node::new(&discovery, protocol, ports).await;
        let (name, secret) = network(protocol);
        let id = a.agent.join_network(&name, &secret).await.unwrap();
        b.agent.join_network(&name, &secret).await.unwrap();
        wait_for_peers(&a.agent, id, 1).await;
        for node in [&a, &b] {
            wait_until("real internal handshake over selected carrier", || async {
                node.tunnel
                    .overview(id)?
                    .peers
                    .first()?
                    .tunnel
                    .as_ref()?
                    .health
                    .is_up()
                    .then_some(())
            })
            .await;
            let status = node.agent.network_status(id).await.unwrap();
            assert_eq!(status.protocols, [protocol]);
            assert!(
                matches!(&status.peers[0].data_path, tsunagi::agent::DataPath::Direct { transport } if transport == protocol)
            );
        }
        for (source, destination) in [(&a, &b), (&b, &a)] {
            let mut total = 0;
            for len in [60, 1097, 1280] {
                let mut packet = vec![0; len];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                packet[8] = 64;
                packet[9] = 253;
                packet[12..16].copy_from_slice(&source.addr(id).octets());
                packet[16..20].copy_from_slice(&destination.addr(id).octets());
                let packet = Bytes::from(packet);
                source.tun().push_from_os(packet.clone());
                assert_eq!(
                    tokio::time::timeout(tsunagi::testing::DEADLINE, destination.tun().pop_to_os())
                        .await
                        .unwrap()
                        .unwrap(),
                    packet
                );
                total += len as u64;
            }
            wait_until(
                "plaintext bytes count once without health probes or nested encryption overhead",
                || async {
                    let tx = source
                        .tunnel
                        .overview(id)?
                        .peers
                        .first()?
                        .tunnel
                        .as_ref()?
                        .stats;
                    let rx = destination
                        .tunnel
                        .overview(id)?
                        .peers
                        .first()?
                        .tunnel
                        .as_ref()?
                        .stats;
                    (tx.tx_bytes == total
                        && rx.rx_bytes == total
                        && tx.tx_packets == 3
                        && rx.rx_packets == 3)
                        .then_some(())
                },
            )
            .await;
        }
        a.agent.shutdown().await;
        b.agent.shutdown().await;
        a.accept.abort();
        b.accept.abort();
    }
}

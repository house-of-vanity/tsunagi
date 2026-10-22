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
        Self::configured(discovery, protocol, ports, true).await
    }
    async fn configured(
        discovery: &SharedMemoryDiscovery,
        protocol: &str,
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
            let agent = Agent::spawn(
                config
                    .with_carrier(carrier)
                    .with_custom_transport(protocol, custom),
            )
            .await
            .unwrap();
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

#[tokio::test]
async fn missing_native_transport_cannot_silently_turn_wireguard_into_quic() {
    let discovery = SharedMemoryDiscovery::new();
    let ports = Arc::default();
    let a = Node::configured(&discovery, "wg", Arc::clone(&ports), false).await;
    let b = Node::configured(&discovery, "wg", ports, false).await;
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

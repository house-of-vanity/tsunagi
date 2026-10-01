#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tsunagi::dataplane::transport::{InboundLink, PacketTransport};
use tsunagi::dataplane::{IpPlugin, PacketSink, PluginContext};
use tsunagi::identity::{DeviceIdentity, NetworkId};
use tsunagi_wireguard::{WireguardConfig, WireguardPlugin, WireguardTransport};

struct TestSink {
    delivered: mpsc::Sender<(NetworkId, iroh::EndpointId, Bytes)>,
}

impl PacketSink for TestSink {
    fn deliver(
        &self,
        network: NetworkId,
        from: iroh::EndpointId,
        packet: Bytes,
    ) -> tsunagi::BoxFuture<'_, ()> {
        let delivered = self.delivered.clone();
        Box::pin(async move {
            let _ = delivered.send((network, from, packet)).await;
        })
    }
}

fn sample_ipv4_packet() -> Bytes {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45; // IPv4, IHL 5
    packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // total len 40
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]); // src 10.0.0.1
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst 10.0.0.2
    Bytes::from(packet)
}

#[tokio::test]
async fn test_wireguard_plugin_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .with_test_writer()
        .try_init();

    let identity_a = DeviceIdentity::generate();
    let peer_a = identity_a.endpoint_id();

    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();

    let network = NetworkId::from_bytes([77u8; 32]);

    let tmp_a = tempfile::tempdir().expect("tmp A");
    let tmp_b = tempfile::tempdir().expect("tmp B");

    // Transports
    let transport_b = Arc::new(
        WireguardTransport::bind(&identity_b, Some(0))
            .await
            .expect("bind B"),
    );
    let port_b = transport_b.bound_port();

    let transport_a = Arc::new(
        WireguardTransport::bind(&identity_a, Some(0))
            .await
            .expect("bind A"),
    );
    let port_a = transport_a.bound_port();

    // Plugins
    let cfg_a = WireguardConfig::new(tmp_a.path());
    let plugin_a = WireguardPlugin::open(cfg_a, Arc::clone(&transport_a))
        .await
        .expect("open plugin A");

    let cfg_b = WireguardConfig::new(tmp_b.path());
    let plugin_b = WireguardPlugin::open(cfg_b, Arc::clone(&transport_b))
        .await
        .expect("open plugin B");

    // Attach sinks
    let (sink_a_tx, mut sink_a_rx) = mpsc::channel(10);
    plugin_a.attach(PluginContext::with_sink(Arc::new(TestSink {
        delivered: sink_a_tx,
    })));

    let (sink_b_tx, mut sink_b_rx) = mpsc::channel(10);
    plugin_b.attach(PluginContext::with_sink(Arc::new(TestSink {
        delivered: sink_b_tx,
    })));

    // Capability exchange
    plugin_a.on_network_activated(network);
    plugin_b.on_network_activated(network);

    let cap_a = loop {
        if let Some(cap) = plugin_a.local_capability(network).expect("cap A") {
            break cap;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let cap_b = loop {
        if let Some(cap) = plugin_b.local_capability(network).expect("cap B") {
            break cap;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    plugin_a
        .on_peer_capability(network, peer_b, &cap_b)
        .expect("A on cap B");
    plugin_b
        .on_peer_capability(network, peer_a, &cap_a)
        .expect("B on cap A");

    // Register loopback address candidates
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    transport_a.set_peer_addr(peer_b, addr_b);

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    transport_b.set_peer_addr(peer_a, addr_a);

    // Spawn accept loop on A
    let transport_a_clone = Arc::clone(&transport_a);
    tokio::spawn(async move {
        transport_a_clone.accept_loop(|_| {}).await;
    });

    // Spawn accept loop on B
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundLink>(1);
    let transport_b_clone = Arc::clone(&transport_b);
    tokio::spawn(async move {
        transport_b_clone
            .accept_loop(move |inbound| {
                let _ = inbound_tx.try_send(inbound);
            })
            .await;
    });

    // Open link from A to B
    let link_a = tokio::time::timeout(
        Duration::from_secs(5),
        transport_a.open(network, peer_b, "wg"),
    )
    .await
    .expect("open should not timeout")
    .expect("open should succeed");

    plugin_a.on_peer_link(network, peer_b, Arc::clone(&link_a));

    // Wait for inbound link on B and hand to plugin B
    let inbound_b = tokio::time::timeout(Duration::from_secs(5), inbound_rx.recv())
        .await
        .expect("accept should not timeout")
        .expect("inbound link should arrive");
    plugin_b.on_peer_link(network, peer_a, inbound_b.link);

    // Wait briefly for WireGuard handshake to complete
    let mut up = false;
    for _ in 0..50 {
        if let Some(overview_a) = plugin_a.overview(network)
            && overview_a.peers.iter().any(|p| p.is_up())
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "WireGuard handshake should complete between peers");

    // Send IP packet from A to B
    let packet_a_to_b = sample_ipv4_packet();
    let sent = plugin_a.carry(network, peer_b, packet_a_to_b.clone());
    assert!(sent, "plugin A carry should succeed");

    let received_b = tokio::time::timeout(Duration::from_secs(5), sink_b_rx.recv())
        .await
        .expect("recv B timeout")
        .expect("recv B option");

    assert_eq!(received_b.0, network);
    assert_eq!(received_b.1, peer_a);
    assert_eq!(received_b.2, packet_a_to_b);

    // Send IP packet from B to A
    let packet_b_to_a = sample_ipv4_packet();
    let sent_reply = plugin_b.carry(network, peer_a, packet_b_to_a.clone());
    assert!(sent_reply, "plugin B carry should succeed");

    let received_a = tokio::time::timeout(Duration::from_secs(5), sink_a_rx.recv())
        .await
        .expect("recv A timeout")
        .expect("recv A option");

    assert_eq!(received_a.0, network);
    assert_eq!(received_a.1, peer_b);
    assert_eq!(received_a.2, packet_b_to_a);
}

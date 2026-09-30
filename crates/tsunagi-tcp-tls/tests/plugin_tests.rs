#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tsunagi::dataplane::transport::{InboundLink, PacketTransport};
use tsunagi::dataplane::{IpPlugin, PacketSink, PluginContext};
use tsunagi::identity::{DeviceIdentity, NetworkId};
use tsunagi_tcp_tls::{TcpTlsCodec, TcpTlsPlugin, TcpTlsTransport};

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

#[tokio::test]
async fn test_tcp_tls_plugin_end_to_end() {
    let identity_a = DeviceIdentity::generate();
    let peer_a = identity_a.endpoint_id();

    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();

    let network = NetworkId::from_bytes([77u8; 32]);

    // Transports
    let transport_b = Arc::new(
        TcpTlsTransport::bind(&identity_b, Some(0), None)
            .await
            .expect("bind B"),
    );
    let port_b = transport_b.bound_port();

    let transport_a = Arc::new(
        TcpTlsTransport::bind(&identity_a, Some(0), None)
            .await
            .expect("bind A"),
    );

    // Codecs and plugins
    let codec_a = TcpTlsCodec::new(peer_a, Arc::clone(&transport_a));
    let plugin_a = Arc::new(TcpTlsPlugin::new(codec_a));

    let codec_b = TcpTlsCodec::new(peer_b, Arc::clone(&transport_b));
    let plugin_b = Arc::new(TcpTlsPlugin::new(codec_b));

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
    let cap_a = plugin_a
        .local_capability(network)
        .expect("cap A")
        .expect("some cap A");
    let cap_b = plugin_b
        .local_capability(network)
        .expect("cap B")
        .expect("some cap B");

    plugin_a
        .on_peer_capability(network, peer_b, &cap_b)
        .expect("A on cap B");
    plugin_b
        .on_peer_capability(network, peer_a, &cap_a)
        .expect("B on cap A");

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

    // Make sure A knows B's loopback address
    transport_a.set_peer_addr(peer_b, format!("127.0.0.1:{port_b}").parse().unwrap());

    // Connect link from A to B
    let link_a = transport_a
        .open(network, peer_b, "tcp-tls")
        .await
        .expect("open link from A");
    let inbound_b = tokio::time::timeout(Duration::from_secs(5), inbound_rx.recv())
        .await
        .expect("recv timeout")
        .expect("recv inbound");
    let link_b = inbound_b.link;

    // Install links into plugins
    plugin_a.on_peer_link(network, peer_b, link_a);
    plugin_b.on_peer_link(network, peer_a, link_b);

    // Carry packet from A to B
    let ip_packet_a = Bytes::from_static(b"4500003c000100004011e0e8c0a80101c0a8010200000000");
    let carried_a = plugin_a.carry(network, peer_b, ip_packet_a.clone());
    assert!(carried_a, "plugin A should carry packet");

    let (net_received, from_peer, delivered_pkt) =
        tokio::time::timeout(Duration::from_secs(3), sink_b_rx.recv())
            .await
            .expect("timeout waiting for delivery on B")
            .expect("packet on B");

    assert_eq!(net_received, network);
    assert_eq!(from_peer, peer_a);
    assert_eq!(delivered_pkt, ip_packet_a);

    // Carry reply packet from B to A
    let ip_packet_b = Bytes::from_static(b"reply-packet-from-b");
    let carried_b = plugin_b.carry(network, peer_a, ip_packet_b.clone());
    assert!(carried_b, "plugin B should carry packet");

    let (net_received, from_peer, delivered_pkt) =
        tokio::time::timeout(Duration::from_secs(3), sink_a_rx.recv())
            .await
            .expect("timeout waiting for delivery on A")
            .expect("packet on A");

    assert_eq!(net_received, network);
    assert_eq!(from_peer, peer_b);
    assert_eq!(delivered_pkt, ip_packet_b);
}

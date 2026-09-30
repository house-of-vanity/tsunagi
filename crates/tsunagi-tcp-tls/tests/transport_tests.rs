#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tsunagi::dataplane::transport::{InboundLink, PacketTransport};
use tsunagi::identity::{DeviceIdentity, NetworkId};
use tsunagi_tcp_tls::TcpTlsTransport;

#[tokio::test]
async fn test_tcp_tls_transport_loopback() {
    let identity_a = DeviceIdentity::generate();
    let peer_a = identity_a.endpoint_id();

    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();

    let network = NetworkId::from_bytes([42u8; 32]);

    // Bind transport B on port 0 (ephemeral)
    let transport_b = Arc::new(
        TcpTlsTransport::bind(&identity_b, Some(0), Some("custom.example.com".to_string()))
            .await
            .expect("bind server should succeed"),
    );
    let port_b = transport_b.bound_port();
    assert!(port_b > 0);
    assert_eq!(transport_b.sni(), "custom.example.com");

    // Bind transport A on port 0 (ephemeral)
    let transport_a = Arc::new(
        TcpTlsTransport::bind(&identity_a, Some(0), Some("custom.example.com".to_string()))
            .await
            .expect("bind client should succeed"),
    );
    assert_eq!(transport_a.sni(), "custom.example.com");

    // Register B's address on transport A
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    transport_a.set_peer_addr(peer_b, addr_b);

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
        transport_a.open(network, peer_b, "tcp-tls"),
    )
    .await
    .expect("open should not timeout")
    .expect("open should succeed");

    // Receive inbound link on B
    let inbound_b = tokio::time::timeout(Duration::from_secs(5), inbound_rx.recv())
        .await
        .expect("accept should not timeout")
        .expect("inbound link should arrive");

    assert_eq!(inbound_b.network, network);
    assert_eq!(inbound_b.peer, peer_a);
    assert_eq!(inbound_b.protocol, "tcp-tls");
    let link_b = inbound_b.link;

    // Send from A to B
    let data_a_to_b = Bytes::from_static(b"packet from A to B");
    link_a.send(data_a_to_b.clone()).expect("send A->B");
    let received_on_b = tokio::time::timeout(Duration::from_secs(2), link_b.recv())
        .await
        .expect("recv B timeout")
        .expect("recv B option");
    assert_eq!(received_on_b, data_a_to_b);

    // Send from B to A
    let data_b_to_a = Bytes::from_static(b"reply from B to A");
    link_b.send(data_b_to_a.clone()).expect("send B->A");
    let received_on_a = tokio::time::timeout(Duration::from_secs(2), link_a.recv())
        .await
        .expect("recv A timeout")
        .expect("recv A option");
    assert_eq!(received_on_a, data_b_to_a);

    // Path descriptions
    assert!(link_a.path_description().contains("tcp-tls"));
    assert!(link_b.path_description().contains("tcp-tls"));
}

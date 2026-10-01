#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tsunagi::dataplane::transport::{InboundLink, PacketTransport};
use tsunagi::identity::{DeviceIdentity, NetworkId};
use tsunagi_wireguard::WireguardTransport;

#[tokio::test]
async fn test_wireguard_transport_loopback() {
    let identity_a = DeviceIdentity::generate();
    let peer_a = identity_a.endpoint_id();

    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();

    let network = NetworkId::from_bytes([42u8; 32]);

    // Bind transport B on port 0 (ephemeral)
    let transport_b = Arc::new(
        WireguardTransport::bind(&identity_b, Some(0))
            .await
            .expect("bind server should succeed"),
    );
    let port_b = transport_b.bound_port();
    assert!(port_b > 0);

    // Bind transport A on port 0 (ephemeral)
    let transport_a = Arc::new(
        WireguardTransport::bind(&identity_a, Some(0))
            .await
            .expect("bind client should succeed"),
    );
    let port_a = transport_a.bound_port();
    assert!(port_a > 0);

    // Register B's address and network on transport A
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    transport_a.set_peer_addr(peer_b, addr_b);
    transport_a.set_peer_network(peer_b, network);

    // Register A's address and network on transport B
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    transport_b.set_peer_addr(peer_a, addr_a);
    transport_b.set_peer_network(peer_a, network);

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

    // Send from A to B to trigger inbound link discovery on B
    let data_a_to_b = Bytes::from_static(b"wireguard packet from A to B");
    link_a.send(data_a_to_b.clone()).expect("send A->B");

    // Receive inbound link on B
    let inbound_b = tokio::time::timeout(Duration::from_secs(5), inbound_rx.recv())
        .await
        .expect("accept should not timeout")
        .expect("inbound link should arrive");

    assert_eq!(inbound_b.network, network);
    assert_eq!(inbound_b.peer, peer_a);
    assert_eq!(inbound_b.protocol, "wg");
    let link_b = inbound_b.link;

    // Check packet received on B
    let received_on_b = tokio::time::timeout(Duration::from_secs(2), link_b.recv())
        .await
        .expect("recv B timeout")
        .expect("recv B option");
    assert_eq!(received_on_b, data_a_to_b);

    // Send from B to A
    let data_b_to_a = Bytes::from_static(b"wireguard packet from B to A");
    link_b.send(data_b_to_a.clone()).expect("send B->A");
    let received_on_a = tokio::time::timeout(Duration::from_secs(2), link_a.recv())
        .await
        .expect("recv A timeout")
        .expect("recv A option");
    assert_eq!(received_on_a, data_b_to_a);

    // Path descriptions
    assert!(link_a.path_description().contains("wireguard via"));
    assert!(link_b.path_description().contains("wireguard via"));
}

#[tokio::test]
async fn test_wireguard_transport_unreachable_probe_times_out() {
    let identity_a = DeviceIdentity::generate();
    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();
    let network = NetworkId::from_bytes([99u8; 32]);

    let transport_a = Arc::new(
        WireguardTransport::bind(&identity_a, Some(0))
            .await
            .expect("bind client should succeed"),
    );

    // Register a non-responsive address for peer B (TEST-NET-1 documentation IP which drops packets)
    let unreachable_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    transport_a.set_peer_addr(peer_b, unreachable_addr);
    transport_a.set_peer_network(peer_b, network);

    // Spawn accept loop on A
    let transport_a_clone = Arc::clone(&transport_a);
    tokio::spawn(async move {
        transport_a_clone.accept_loop(|_| {}).await;
    });

    // Opening to unreachable candidate must fail with Unreachable rather than returning a dead direct link
    let result = transport_a.open(network, peer_b, "wg").await;
    match result {
        Err(tsunagi::dataplane::transport::TransportError::Unreachable(msg)) => {
            assert!(msg.contains("timed out"));
        }
        other => panic!("expected Unreachable error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_wireguard_link_close_and_transport_close_link() {
    let identity_a = DeviceIdentity::generate();
    let peer_a = identity_a.endpoint_id();
    let identity_b = DeviceIdentity::generate();
    let peer_b = identity_b.endpoint_id();
    let network = NetworkId::from_bytes([55u8; 32]);

    let transport_b = Arc::new(
        WireguardTransport::bind(&identity_b, Some(0))
            .await
            .unwrap(),
    );
    let port_b = transport_b.bound_port();

    let transport_a = Arc::new(
        WireguardTransport::bind(&identity_a, Some(0))
            .await
            .unwrap(),
    );
    let port_a = transport_a.bound_port();

    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    transport_a.set_peer_addr(peer_b, addr_b);
    transport_a.set_peer_network(peer_b, network);

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    transport_b.set_peer_addr(peer_a, addr_a);
    transport_b.set_peer_network(peer_a, network);

    let transport_a_clone = Arc::clone(&transport_a);
    tokio::spawn(async move {
        transport_a_clone.accept_loop(|_| {}).await;
    });

    let transport_b_clone = Arc::clone(&transport_b);
    tokio::spawn(async move {
        transport_b_clone.accept_loop(|_| {}).await;
    });

    let link_a = transport_a
        .open(network, peer_b, "wg")
        .await
        .expect("open link A");
    assert!(!link_a.is_closed());

    // Spawn a reader task waiting on recv()
    let link_a_clone = Arc::clone(&link_a);
    let recv_task = tokio::spawn(async move { link_a_clone.recv().await });

    // Explicitly closing via transport.close_link()
    transport_a.close_link(network, peer_b);
    assert!(link_a.is_closed());

    // Wait on closed() notification
    tokio::time::timeout(Duration::from_secs(1), link_a.closed())
        .await
        .expect("link.closed() should resolve promptly");

    // recv() must have returned None
    let recv_res = tokio::time::timeout(Duration::from_secs(1), recv_task)
        .await
        .expect("recv task should complete")
        .expect("task join");
    assert_eq!(recv_res, None);

    // Send after close must return Closed error
    let send_res = link_a.send(Bytes::from_static(b"after close"));
    assert!(matches!(
        send_res,
        Err(tsunagi::dataplane::transport::TransportError::Closed)
    ));
}

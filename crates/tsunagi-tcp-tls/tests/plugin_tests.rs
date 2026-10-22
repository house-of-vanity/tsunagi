//! Bounded TLS carrier announcements contain no end-to-end cipher selection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{net::IpAddr, sync::Arc};
use tsunagi::{
    dataplane::transport::DataCarrier,
    identity::{DeviceIdentity, NetworkId},
};
use tsunagi_tcp_tls::{TcpTlsCarrier, TcpTlsTransport};

#[tokio::test]
async fn tls_capabilities_bound_addresses_and_reject_invalid_ports_and_versions() {
    let identity = DeviceIdentity::generate();
    let peer = DeviceIdentity::generate().endpoint_id();
    let transport = Arc::new(
        TcpTlsTransport::bind(&identity, Some(0), None)
            .await
            .unwrap(),
    );
    let carrier = TcpTlsCarrier::new(transport);
    let network = NetworkId::from_bytes([7; 32]);
    let mut cap = carrier.local_capability(network).unwrap().unwrap();
    assert_eq!(cap.protocol, "tcp-tls");
    let addresses: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(); 33];
    cap.data = postcard::to_allocvec(&(443u16, addresses)).unwrap();
    assert!(carrier.on_peer_capability(network, peer, &cap).is_err());
    cap.data = postcard::to_allocvec(&(0u16, Vec::<IpAddr>::new())).unwrap();
    assert!(carrier.on_peer_capability(network, peer, &cap).is_err());
    cap.data =
        postcard::to_allocvec(&(443u16, vec!["192.0.2.1".parse::<IpAddr>().unwrap()])).unwrap();
    carrier.on_peer_capability(network, peer, &cap).unwrap();
    cap.version += 1;
    assert!(carrier.on_peer_capability(network, peer, &cap).is_err());
}

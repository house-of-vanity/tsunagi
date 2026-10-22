//! Real control authentication and independently encrypted ordinary WG carriers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use bytes::Bytes;
use std::{net::Ipv4Addr, time::Duration};
use tempfile::TempDir;
use tsunagi::{
    Agent,
    dataplane::transport::{PacketTransport, TransportError},
    discovery::SharedMemoryDiscovery,
    identity::DeviceIdentity,
    testing::{config_with, network, wait_for_peers},
};
use tsunagi_wireguard::{UdpTransport, profile::PairProfile};

#[tokio::test]
async fn ordinary_wireguard_carries_opaque_frames_after_real_membership_authentication() {
    let discovery = SharedMemoryDiscovery::new();
    let mut nodes = Vec::new();
    for _ in 0..2 {
        let root = TempDir::new().unwrap();
        let config = config_with(root.path(), &discovery);
        let identity = tsunagi::storage::StateStore::open(config.paths.state_db())
            .unwrap()
            .load_or_create_device_identity()
            .unwrap();
        let transport = UdpTransport::wireguard(identity.endpoint_id(), Ipv4Addr::LOCALHOST, None);
        let agent = Agent::spawn(config.with_custom_transport("wg", transport.clone()))
            .await
            .unwrap();
        nodes.push((root, agent, transport));
    }
    nodes.sort_by_key(|(_, agent, _)| *agent.endpoint_id().as_bytes());
    let (name, secret) = network("outer-wireguard");
    let id = nodes[0].1.join_network(&name, &secret).await.unwrap();
    nodes[1].1.join_network(&name, &secret).await.unwrap();
    for (index, (_, agent, transport)) in nodes.iter().enumerate() {
        wait_for_peers(agent, id, 1).await;
        transport.allow_peer(id, nodes[1 - index].1.endpoint_id());
    }
    let outgoing = nodes[0]
        .2
        .open(id, nodes[1].1.endpoint_id(), "wg")
        .await
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), nodes[1].2.next_inbound())
        .await
        .unwrap()
        .unwrap()
        .link;
    for (from, to) in [(&outgoing, &incoming), (&incoming, &outgoing)] {
        let payload = Bytes::from(vec![0x37; 65_536]);
        from.send(payload.clone()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), to.recv())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        assert!(from.path_description().starts_with("wg UDP via"));
        assert!(matches!(
            from.send(Bytes::from(vec![0; 65_537])),
            Err(TransportError::TooLarge { .. })
        ));
    }
    outgoing.close();
    incoming.close();
    for (_, agent, transport) in nodes {
        transport.shutdown();
        agent.shutdown().await;
    }
}

#[tokio::test]
async fn an_unannounced_peer_cannot_open_or_negotiate_a_wireguard_carrier() {
    let local = DeviceIdentity::generate().endpoint_id();
    let peer = DeviceIdentity::generate().endpoint_id();
    let transport = UdpTransport::wireguard(local, Ipv4Addr::LOCALHOST, None);
    let id = tsunagi::NetworkId::from_bytes([7; 32]);
    assert!(transport.open(id, peer, "wg").await.is_err());
    assert!(transport.on_control(id, peer, "wg", &[0; 40]).is_err());
    transport.shutdown();
}

#[test]
fn ordinary_profiles_preserve_the_wireguard_header_and_emit_no_masking_packets() {
    let profile = PairProfile::wireguard();
    let mut message = vec![0x42; 148];
    message[..4].copy_from_slice(&[1, 0, 0, 0]);
    assert_eq!(profile.encode(&message).unwrap().as_ref(), message);
    assert_eq!(profile.decode(&message).unwrap(), message);
    assert!(profile.signature_packets().is_empty());
    assert!(!profile.is_masked());
}

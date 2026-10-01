#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use tsunagi::identity::NetworkId;
use tsunagi_wireguard::{ANNOUNCEMENT_VERSION, WgAnnouncement, WgPublicKey, WgSecretKey};

#[test]
fn announcement_round_trip() {
    let network = NetworkId::from_bytes([42u8; 32]);
    let key = WgSecretKey::generate().public();
    let local = WgSecretKey::generate().public();

    let addrs: Vec<IpAddr> = vec![
        "192.168.1.100".parse().unwrap(),
        "10.0.0.5".parse().unwrap(),
    ];

    let announcement = WgAnnouncement::new(network, &key, 51820, addrs.clone());
    let encoded = announcement.encode().expect("encode");

    let validated = WgAnnouncement::decode_and_validate(&encoded, network, &local).expect("decode");

    assert_eq!(validated.public_key, key);
    assert_eq!(validated.port, 51820);
    assert_eq!(validated.addrs, addrs);
}

#[test]
fn announcement_rejects_zero_key() {
    let network = NetworkId::from_bytes([42u8; 32]);
    let local = WgSecretKey::generate().public();
    let zero = WgPublicKey::from_bytes([0u8; 32]);

    let announcement = WgAnnouncement::new(network, &zero, 51820, vec![]);
    let encoded = announcement.encode().unwrap();

    let err = WgAnnouncement::decode_and_validate(&encoded, network, &local).unwrap_err();
    assert!(err.to_string().contains("all zeroes"));
}

#[test]
fn announcement_rejects_own_key() {
    let network = NetworkId::from_bytes([42u8; 32]);
    let local = WgSecretKey::generate().public();

    let announcement = WgAnnouncement::new(network, &local, 51820, vec![]);
    let encoded = announcement.encode().unwrap();

    let err = WgAnnouncement::decode_and_validate(&encoded, network, &local).unwrap_err();
    assert!(err.to_string().contains("own WireGuard key"));
}

#[test]
fn announcement_rejects_wrong_network() {
    let network_a = NetworkId::from_bytes([1u8; 32]);
    let network_b = NetworkId::from_bytes([2u8; 32]);
    let key = WgSecretKey::generate().public();
    let local = WgSecretKey::generate().public();

    let announcement = WgAnnouncement::new(network_a, &key, 51820, vec![]);
    let encoded = announcement.encode().unwrap();

    let err = WgAnnouncement::decode_and_validate(&encoded, network_b, &local).unwrap_err();
    assert!(err.to_string().contains("different network"));
}

#[test]
fn announcement_rejects_zero_port() {
    let network = NetworkId::from_bytes([42u8; 32]);
    let key = WgSecretKey::generate().public();
    let local = WgSecretKey::generate().public();

    let announcement = WgAnnouncement {
        version: ANNOUNCEMENT_VERSION,
        public_key: *key.as_bytes(),
        network: *network.as_bytes(),
        port: 0,
        addrs: vec![],
    };
    let encoded = announcement.encode().unwrap();

    let err = WgAnnouncement::decode_and_validate(&encoded, network, &local).unwrap_err();
    assert!(err.to_string().contains("cannot be 0"));
}

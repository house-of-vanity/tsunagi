//! Opt-in tests for the real `wg` / `ip` backend.
//!
//! These are the only tests in this repository that change the host's network,
//! so they are **ignored by default** and are not part of the standard suite.
//!
//! They need Linux, the `wireguard` kernel module, `wg` from wireguard-tools,
//! `ip` from iproute2, and `CAP_NET_ADMIN` (in practice: root):
//!
//! ```text
//! sudo -E cargo test --test wireguard_system -- --ignored --test-threads=1
//! ```
//!
//! Everything they exercise — the command plan, the parsers, the configuration
//! builder and reconciliation — is already covered without root by the unit
//! tests in `src/dataplane/wireguard/` and by `tests/wireguard.rs`. What these
//! add is confirmation that the plan the planner produces is one the real
//! tools accept.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use tsunagi::dataplane::wireguard::wgtool::WgToolBackend;
use tsunagi::dataplane::wireguard::{
    Cidr, InterfaceParams, WgSecretKey, WireguardBackend, build_interface, overlay_address,
};
use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};

/// A name unlikely to collide with anything already on the host.
const TEST_INTERFACE: &str = "tsunagitest0";

fn test_network() -> tsunagi::NetworkId {
    NetworkKeys::derive(
        &NetworkName::new("system-test").unwrap(),
        &NetworkSecret::from_bytes(vec![11u8; 32]).unwrap(),
    )
    .network_id()
}

#[test]
#[ignore = "changes the host's network; needs Linux, wg, ip and CAP_NET_ADMIN"]
fn the_real_backend_applies_reads_back_and_removes_a_configuration() {
    let backend = WgToolBackend::new().expect("the wg-tools backend should be available on Linux");
    let network = test_network();
    let local = WgSecretKey::generate();
    let peer = WgSecretKey::generate().public();

    // Start from a clean slate even if a previous run was interrupted.
    backend.remove(TEST_INTERFACE).unwrap();
    assert_eq!(backend.inspect(TEST_INTERFACE).unwrap(), None);

    let desired = build_interface(
        InterfaceParams {
            network,
            name: TEST_INTERFACE.to_string(),
            private_key: local.clone(),
            listen_port: 51899,
            mtu: Some(1380),
            keepalive: Some(25),
        },
        [peer],
        |_| Some("10.99.0.2:51899".parse::<SocketAddr>().unwrap()),
    );

    backend.apply(&desired).unwrap();

    let observed = backend
        .inspect(TEST_INTERFACE)
        .unwrap()
        .expect("the interface should exist after apply");
    assert_eq!(observed.public_key, local.public());
    assert_eq!(observed.listen_port, 51899);
    assert_eq!(observed.peers.len(), 1);
    assert_eq!(observed.peers[0].public_key, peer);
    assert_eq!(
        observed.peers[0].allowed_ips,
        vec![Cidr::host(overlay_address(network, &peer))]
    );
    assert!(
        observed
            .addresses
            .contains(&Cidr::host(overlay_address(network, &local.public()))),
        "the overlay address should be assigned: {:?}",
        observed.addresses
    );

    // Applying the same configuration again must be a no-op, not a rebuild.
    backend.apply(&desired).unwrap();
    assert_eq!(backend.inspect(TEST_INTERFACE).unwrap(), Some(observed));

    backend.remove(TEST_INTERFACE).unwrap();
    assert_eq!(backend.inspect(TEST_INTERFACE).unwrap(), None);
    // Removing something that is not there is not an error.
    backend.remove(TEST_INTERFACE).unwrap();
}

#[test]
#[ignore = "changes the host's network; needs Linux, wg, ip and CAP_NET_ADMIN"]
fn the_real_backend_refuses_an_interface_it_did_not_create() {
    let backend = WgToolBackend::new().expect("the wg-tools backend should be available on Linux");
    let name = "tsunagitest1";

    // A plain dummy link, not a WireGuard device: something that belongs to
    // somebody else.
    let created = std::process::Command::new("ip")
        .args(["link", "add", "dev", name, "type", "dummy"])
        .status()
        .expect("ip should be available");
    assert!(created.success(), "could not create the dummy link");

    let result = backend.inspect(name);
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "dev", name])
        .status();

    assert!(
        result.is_err(),
        "an interface the plugin did not create must be refused, not adopted"
    );
}

//! The WireGuard data plane, driven over real iroh connections.
//!
//! Everything here is real except the packet interface: real agents, real
//! control plane, real iroh data links, real WireGuard handshakes and
//! encryption from `boringtun`. Only the TUN device is in memory, which is why
//! the whole data plane can be tested with no privileges and without touching
//! the host's network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{config_with, network, settle, wait_event, wait_for_peers, wait_until};
use iroh::EndpointId;
use tempfile::TempDir;
use tsunagi::agent::Event;
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{
    MemoryTun, MemoryTunFactory, WIREGUARD_PROTOCOL, WgAnnouncement, WgSecretKey, WireguardConfig,
    WireguardPlugin, overlay_address, overlay_prefix,
};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkId, NetworkName, NetworkSecret};
use tsunagi::{Agent, NetworkStatus};

/// An agent with a WireGuard plugin backed by an in-memory packet interface.
struct WgAgent {
    dir: TempDir,
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    tuns: MemoryTunFactory,
}

impl WgAgent {
    async fn spawn(discovery: &SharedMemoryDiscovery, tag: &str) -> Self {
        Self::spawn_with(discovery, tag, |config| config).await
    }

    async fn spawn_with(
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let (agent, plugin, tuns) = Self::open(dir.path(), discovery, tag, tune).await;
        Self {
            dir,
            agent,
            plugin,
            tuns,
        }
    }

    async fn open(
        root: &std::path::Path,
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
    ) -> (Agent, Arc<WireguardPlugin>, MemoryTunFactory) {
        let tuns = MemoryTunFactory::new();
        let wg = tune(
            WireguardConfig::new(root.join("wireguard"))
                .with_interface_prefix(tag)
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        );
        let plugin = WireguardPlugin::open(wg, Arc::new(tuns.clone()))
            .await
            .unwrap();
        let agent = Agent::spawn(
            config_with(root, discovery).with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
        )
        .await
        .unwrap();
        (agent, plugin, tuns)
    }

    fn endpoint_id(&self) -> EndpointId {
        self.agent.endpoint_id()
    }

    /// This agent's overlay address in a network.
    async fn overlay(&self, network: NetworkId) -> Ipv6Addr {
        let view = wait_until("the plugin prepared the network", || async {
            self.plugin.overview(network)
        })
        .await;
        match view.overlay_address {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(_) => panic!("the overlay is IPv6"),
        }
    }

    /// The in-memory packet interface for a network.
    async fn tun(&self, network: NetworkId) -> Arc<MemoryTun> {
        let name = wait_until("the packet interface exists", || async {
            let view = self.plugin.overview(network)?;
            self.tuns.device(&view.interface).map(|_| view.interface)
        })
        .await;
        self.tuns.device(&name).unwrap()
    }

    /// Waits until `count` tunnels have completed a WireGuard handshake.
    async fn wait_for_tunnels(&self, network: NetworkId, count: usize) {
        wait_until(
            &format!("{count} established WireGuard tunnels"),
            || async {
                let view = self.plugin.overview(network)?;
                (view.established_peers() == count).then_some(())
            },
        )
        .await;
    }

    async fn shutdown(self) -> TempDir {
        self.agent.shutdown().await;
        self.dir
    }
}

/// Builds a minimal well-formed IPv4 packet.
fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Bytes {
    let total = 20 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.push((4 << 4) | 5); // version 4, header length 5 words
    packet.push(0); // dscp/ecn
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // identification
    packet.extend_from_slice(&[0, 0]); // flags and fragment offset
    packet.push(64); // ttl
    packet.push(253); // an experimental protocol number
    packet.extend_from_slice(&[0, 0]); // checksum, not verified by the overlay
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}

/// Builds a minimal well-formed IPv6 packet.
fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Bytes {
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.push(6 << 4); // version 6
    packet.extend_from_slice(&[0, 0, 0]); // traffic class and flow label
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(59); // "no next header"
    packet.push(64); // hop limit
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}

#[tokio::test]
async fn two_agents_carry_real_ip_packets_through_a_wireguard_tunnel() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-traffic");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, network_id, 1).await;

    // Both tunnels must actually handshake, not merely be configured.
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let addr_a = a.overlay(network_id).await;
    let addr_b = b.overlay(network_id).await;
    assert_ne!(addr_a, addr_b);
    // One shared /64, derived by both sides independently.
    assert_eq!(addr_a.octets()[0..8], addr_b.octets()[0..8]);
    assert_eq!(
        &overlay_prefix(network_id).octets()[0..8],
        &addr_a.octets()[0..8]
    );

    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A real IP packet, encrypted by WireGuard, carried over iroh, decrypted
    // on the other side and handed to that host's packet interface.
    let payload = b"hello over the overlay";
    tun_a.push_from_os(ipv6_packet(addr_a, addr_b, payload));

    let received = tokio::time::timeout(common::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the packet should arrive")
        .expect("the interface should still be open");
    assert_eq!(&received[40..], payload);
    assert_eq!(&received[8..24], &addr_a.octets(), "source preserved");
    assert_eq!(&received[24..40], &addr_b.octets(), "destination preserved");

    // And back the other way.
    tun_b.push_from_os(ipv6_packet(addr_b, addr_a, b"and back"));
    let back = tokio::time::timeout(common::DEADLINE, tun_a.pop_to_os())
        .await
        .expect("the reply should arrive")
        .unwrap();
    assert_eq!(&back[40..], b"and back");

    let view = a.plugin.overview(network_id).unwrap();
    let tunnel = view.peers[0].tunnel.as_ref().unwrap();
    assert!(tunnel.health.is_up());
    assert!(tunnel.stats.tx_packets >= 1);
    assert!(tunnel.stats.rx_packets >= 1);
    assert_eq!(tunnel.stats.dropped_wrong_source, 0);

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_peer_cannot_send_from_an_address_it_does_not_own() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-spoof");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let addr_a = a.overlay(network_id).await;
    let addr_b = b.overlay(network_id).await;
    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A sends a packet claiming to come from a third party's address.
    let someone_else: Ipv6Addr = {
        let mut octets = addr_a.octets();
        octets[15] ^= 0xff;
        Ipv6Addr::from(octets)
    };
    tun_a.push_from_os(ipv6_packet(someone_else, addr_b, b"spoofed"));

    // B must drop it: the source is not the address derived for A's key.
    wait_until("the spoofed packet is dropped", || async {
        let view = b.plugin.overview(network_id)?;
        let tunnel = view.peers.first()?.tunnel.as_ref()?;
        (tunnel.stats.dropped_wrong_source >= 1).then_some(())
    })
    .await;

    // A legitimate packet still goes through, so the tunnel is not broken.
    tun_a.push_from_os(ipv6_packet(addr_a, addr_b, b"honest"));
    let received = tokio::time::timeout(common::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the honest packet should arrive")
        .unwrap();
    assert_eq!(&received[40..], b"honest");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn the_overlay_carries_ipv4_alongside_ipv6() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-dual-stack");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let view_a = a.plugin.overview(network_id).unwrap();
    let view_b = b.plugin.overview(network_id).unwrap();

    let v4_a = view_a.overlay_address_v4.expect("dual stack by default");
    let v4_b = view_b.overlay_address_v4.expect("dual stack by default");
    assert_ne!(v4_a, v4_b);
    // Both inside the configured range.
    for addr in [v4_a, v4_b] {
        assert_eq!(
            u32::from(addr) & 0xffc0_0000,
            u32::from(Ipv4Addr::new(100, 64, 0, 0))
        );
    }
    // Each side derived the other's address identically.
    assert_eq!(view_a.peers[0].overlay_address_v4, Some(v4_b));
    assert_eq!(view_b.peers[0].overlay_address_v4, Some(v4_a));
    assert!(!view_a.peers[0].tunnel.as_ref().unwrap().ipv4_conflict);

    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A real IPv4 packet through the same tunnel.
    tun_a.push_from_os(ipv4_packet(v4_a, v4_b, b"ipv4 over the overlay"));
    let received = tokio::time::timeout(common::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the IPv4 packet should arrive")
        .unwrap();
    assert_eq!(received[0] >> 4, 4, "still an IPv4 packet");
    assert_eq!(&received[12..16], &v4_a.octets());
    assert_eq!(&received[16..20], &v4_b.octets());
    assert_eq!(&received[20..], b"ipv4 over the overlay");

    // IPv6 keeps working on the same tunnel.
    let addr_a = a.overlay(network_id).await;
    let addr_b = b.overlay(network_id).await;
    tun_a.push_from_os(ipv6_packet(addr_a, addr_b, b"and ipv6 too"));
    let received = tokio::time::timeout(common::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the IPv6 packet should arrive")
        .unwrap();
    assert_eq!(received[0] >> 4, 6);
    assert_eq!(&received[40..], b"and ipv6 too");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn an_ipv4_source_a_peer_does_not_own_is_dropped() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-v4-spoof");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let v4_a = a
        .plugin
        .overview(network_id)
        .unwrap()
        .overlay_address_v4
        .unwrap();
    let v4_b = b
        .plugin
        .overview(network_id)
        .unwrap()
        .overlay_address_v4
        .unwrap();
    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A claims an IPv4 address that is not the one derived from its key.
    let forged = Ipv4Addr::from(u32::from(v4_a) ^ 0x0000_00ff);
    tun_a.push_from_os(ipv4_packet(forged, v4_b, b"spoofed v4"));

    wait_until("the spoofed IPv4 packet is dropped", || async {
        let view = b.plugin.overview(network_id)?;
        let tunnel = view.peers.first()?.tunnel.as_ref()?;
        (tunnel.stats.dropped_wrong_source >= 1).then_some(())
    })
    .await;

    // The honest one still gets through.
    tun_a.push_from_os(ipv4_packet(v4_a, v4_b, b"honest v4"));
    let received = tokio::time::timeout(common::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the honest packet should arrive")
        .unwrap();
    assert_eq!(&received[20..], b"honest v4");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn an_ipv6_only_overlay_can_be_asked_for() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-v6-only");

    let a = WgAgent::spawn_with(&discovery, "ta", |config| config.with_ipv4_range(None)).await;
    let b = WgAgent::spawn_with(&discovery, "tb", |config| config.with_ipv4_range(None)).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;

    let view = a.plugin.overview(network_id).unwrap();
    assert_eq!(view.overlay_address_v4, None);
    assert_eq!(view.ipv4_range, None);
    assert_eq!(view.peers[0].overlay_address_v4, None);
    // No IPv4 configured is not a conflict.
    assert!(!view.peers[0].tunnel.as_ref().unwrap().ipv4_conflict);

    // IPv6 is unaffected.
    let addr_a = a.overlay(network_id).await;
    let addr_b = b.overlay(network_id).await;
    a.tun(network_id)
        .await
        .push_from_os(ipv6_packet(addr_a, addr_b, b"v6 only"));
    let received = tokio::time::timeout(common::DEADLINE, b.tun(network_id).await.pop_to_os())
        .await
        .expect("the packet should arrive")
        .unwrap();
    assert_eq!(&received[40..], b"v6 only");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn packets_for_an_unknown_address_are_counted_not_broadcast() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-unroutable");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;

    let addr_a = a.overlay(network_id).await;
    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // Nobody owns this address, so it must not be sent to anybody.
    let nowhere: Ipv6Addr = "fd00:dead:beef::1".parse().unwrap();
    tun_a.push_from_os(ipv6_packet(addr_a, nowhere, b"lost"));

    wait_until("the packet is counted as unroutable", || async {
        let view = a.plugin.overview(network_id)?;
        (view.unroutable_packets >= 1).then_some(())
    })
    .await;

    settle().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), tun_b.pop_to_os())
            .await
            .is_err(),
        "an unroutable packet must not reach another member"
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_mesh_of_three_establishes_every_tunnel() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-mesh");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;
    let c = WgAgent::spawn(&discovery, "tc").await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();

    for agent in [&a, &b, &c] {
        wait_for_peers(&agent.agent, network_id, 2).await;
        // N - 1 tunnels, all handshaken.
        agent.wait_for_tunnels(network_id, 2).await;
    }

    // Everyone agrees on the subnet and nobody configured themselves.
    let mut addresses = Vec::new();
    for agent in [&a, &b, &c] {
        let view = agent.plugin.overview(network_id).unwrap();
        assert_eq!(view.overlay_prefix, IpAddr::V6(overlay_prefix(network_id)));
        assert!(
            view.peers
                .iter()
                .all(|peer| peer.public_key != view.public_key)
        );
        addresses.push(view.overlay_address);
    }
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 3, "every member has its own address");

    // A packet from A reaches C directly, not via B.
    let addr_a = a.overlay(network_id).await;
    let addr_c = c.overlay(network_id).await;
    a.tun(network_id)
        .await
        .push_from_os(ipv6_packet(addr_a, addr_c, b"a to c"));
    let received = tokio::time::timeout(common::DEADLINE, c.tun(network_id).await.pop_to_os())
        .await
        .expect("the packet should arrive")
        .unwrap();
    assert_eq!(&received[40..], b"a to c");

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

#[tokio::test]
async fn a_departing_peer_loses_its_tunnel() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-departure");

    let stayer = WgAgent::spawn(&discovery, "ta").await;
    let leaver = WgAgent::spawn(&discovery, "tb").await;

    let network_id = stayer.agent.join_network(&name, &secret).await.unwrap();
    leaver.agent.join_network(&name, &secret).await.unwrap();
    stayer.wait_for_tunnels(network_id, 1).await;

    let leaver_id = leaver.endpoint_id();
    let mut events = stayer.agent.subscribe();
    leaver.shutdown().await;

    wait_event(&mut events, |event| match event {
        Event::PeerDisconnected { peer, .. } if *peer == leaver_id => Some(()),
        _ => None,
    })
    .await;

    wait_until("the tunnel is removed", || async {
        let view = stayer.plugin.overview(network_id)?;
        view.peers.is_empty().then_some(())
    })
    .await;
    // The interface itself stays; only the peer went.
    assert!(stayer.plugin.overview(network_id).is_some());

    stayer.shutdown().await;
}

#[tokio::test]
async fn two_networks_get_separate_interfaces_keys_and_overlays() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("wg-left");
    let (name_b, secret_b) = network("wg-right");

    let hub = WgAgent::spawn(&discovery, "th").await;
    let left = WgAgent::spawn(&discovery, "tl").await;
    let right = WgAgent::spawn(&discovery, "tr").await;

    let alpha = hub.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = hub.agent.join_network(&name_b, &secret_b).await.unwrap();
    left.agent.join_network(&name_a, &secret_a).await.unwrap();
    right.agent.join_network(&name_b, &secret_b).await.unwrap();

    hub.wait_for_tunnels(alpha, 1).await;
    hub.wait_for_tunnels(beta, 1).await;

    let view_alpha = hub.plugin.overview(alpha).unwrap();
    let view_beta = hub.plugin.overview(beta).unwrap();
    assert_ne!(view_alpha.interface, view_beta.interface);
    assert_ne!(
        view_alpha.public_key, view_beta.public_key,
        "one WireGuard identity per network, not one per host"
    );
    assert_ne!(view_alpha.overlay_prefix, view_beta.overlay_prefix);
    assert_eq!(hub.tuns.devices().len(), 2);

    // Traffic in one overlay never surfaces in the other.
    let hub_alpha = match view_alpha.overlay_address {
        IpAddr::V6(addr) => addr,
        IpAddr::V4(_) => panic!("ipv6"),
    };
    let left_addr = left.overlay(alpha).await;
    hub.tun(alpha)
        .await
        .push_from_os(ipv6_packet(hub_alpha, left_addr, b"alpha only"));
    let seen = tokio::time::timeout(common::DEADLINE, left.tun(alpha).await.pop_to_os())
        .await
        .expect("the packet should arrive")
        .unwrap();
    assert_eq!(&seen[40..], b"alpha only");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            right.tun(beta).await.pop_to_os()
        )
        .await
        .is_err(),
        "the other overlay must see nothing"
    );

    // Deactivating one network removes only its interface.
    hub.agent.deactivate_network(alpha).await.unwrap();
    wait_until("the alpha interface is gone", || async {
        hub.plugin.overview(alpha).is_none().then_some(())
    })
    .await;
    assert!(hub.plugin.overview(beta).is_some());

    hub.shutdown().await;
    left.shutdown().await;
    right.shutdown().await;
}

#[tokio::test]
async fn restarting_keeps_the_wireguard_identity_and_overlay_address() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-restart");

    let peer = WgAgent::spawn(&discovery, "tp").await;
    let subject = WgAgent::spawn(&discovery, "ts").await;

    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    peer.wait_for_tunnels(network_id, 1).await;

    let before = subject.plugin.overview(network_id).unwrap();
    let dir = subject.shutdown().await;

    let (agent, plugin, _tuns) = WgAgent::open(dir.path(), &discovery, "ts", |config| config).await;

    let after = wait_until("the restarted plugin is ready", || async {
        plugin.overview(network_id)
    })
    .await;
    assert_eq!(after.public_key, before.public_key);
    assert_eq!(after.overlay_address, before.overlay_address);
    assert_eq!(after.interface, before.interface);

    // The tunnel comes back on its own.
    wait_until("the tunnel is re-established", || async {
        let view = plugin.overview(network_id)?;
        (view.established_peers() == 1).then_some(())
    })
    .await;

    agent.shutdown().await;
    peer.shutdown().await;
    drop(agent);
    drop(dir);
}

#[tokio::test]
async fn shutdown_removes_every_interface_the_plugin_created() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("wg-teardown-a");
    let (name_b, secret_b) = network("wg-teardown-b");

    let agent = WgAgent::spawn(&discovery, "ta").await;
    let alpha = agent.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = agent.agent.join_network(&name_b, &secret_b).await.unwrap();

    agent.tun(alpha).await;
    agent.tun(beta).await;

    agent.agent.shutdown().await;
    assert!(agent.plugin.overview(alpha).is_none());
    assert!(agent.plugin.overview(beta).is_none());
}

#[tokio::test]
async fn the_core_carries_the_payload_without_interpreting_it() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-opaque");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, network_id, 1).await;

    let capability = wait_until("the peer's capability arrived", || async {
        let status: NetworkStatus = a.agent.network_status(network_id).await.ok()?;
        status
            .peers
            .first()
            .and_then(|peer| peer.capabilities.first().cloned())
    })
    .await;
    assert_eq!(capability.protocol, WIREGUARD_PROTOCOL);

    let view_b = b.plugin.overview(network_id).unwrap();
    let expected = WgAnnouncement::new(network_id, &view_b.public_key)
        .encode()
        .unwrap();
    assert_eq!(capability.data, expected);
    assert!(capability.data.len() < tsunagi::Limits::default().max_capability_data_len);

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_forged_overlay_claim_is_rejected_and_never_reaches_a_tunnel() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("wg-hijack").unwrap();
    let secret = NetworkSecret::generate();

    let victim = WgAgent::spawn(&discovery, "tv").await;
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();
    let victim_address = victim.overlay(network_id).await;

    // A legitimate member — it knows the secret — claims the victim's overlay
    // address with its own WireGuard key.
    let attacker_key = WgSecretKey::generate().public();
    let mut forged = WgAnnouncement::new(network_id, &attacker_key);
    forged.overlay_address = victim_address;

    let forger = Arc::new(ForgingPlugin {
        payload: std::sync::Mutex::new(Some(forged.encode().unwrap())),
    });
    let attacker_dir = TempDir::new().unwrap();
    let attacker = Agent::spawn(
        config_with(attacker_dir.path(), &discovery)
            .with_plugin(forger.clone() as Arc<dyn IpPlugin>),
    )
    .await
    .unwrap();

    let mut events = victim.agent.subscribe();
    attacker.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&victim.agent, network_id, 1).await;

    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError {
            protocol, reason, ..
        } if protocol == WIREGUARD_PROTOCOL => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(reason.contains("does not match"), "unexpected: {reason}");

    settle().await;
    let view = victim.plugin.overview(network_id).unwrap();
    assert!(
        view.peers
            .iter()
            .all(|peer| peer.public_key != attacker_key),
        "a rejected announcement must never become a tunnel"
    );
    assert_eq!(view.overlay_address, IpAddr::V6(victim_address));

    attacker.shutdown().await;
    victim.shutdown().await;
    drop(attacker_dir);
}

/// A plugin that announces whatever bytes it is told to, under the WireGuard
/// protocol id. Used to test what a hostile member can do.
#[derive(Debug)]
struct ForgingPlugin {
    payload: std::sync::Mutex<Option<Vec<u8>>>,
}

impl IpPlugin for ForgingPlugin {
    fn protocol_id(&self) -> &str {
        WIREGUARD_PROTOCOL
    }

    fn local_capability(
        &self,
        _network: NetworkId,
    ) -> Result<Option<tsunagi::dataplane::PluginCapability>, tsunagi::dataplane::PluginError> {
        let payload = match self.payload.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Ok(payload.map(|data| tsunagi::dataplane::PluginCapability {
            protocol: WIREGUARD_PROTOCOL.to_string(),
            version: 1,
            enabled: true,
            data,
        }))
    }

    fn on_peer_capability(
        &self,
        _network: NetworkId,
        _peer: EndpointId,
        _capability: &tsunagi::dataplane::PluginCapability,
    ) -> Result<(), tsunagi::dataplane::PluginError> {
        Ok(())
    }

    fn on_peer_gone(&self, _network: NetworkId, _peer: EndpointId) {}
    fn on_network_deactivated(&self, _network: NetworkId) {}
}

#[tokio::test]
async fn an_mtu_below_the_ipv6_minimum_is_refused() {
    use tsunagi::dataplane::wireguard::{DEFAULT_MTU, MIN_MTU, WIREGUARD_OVERHEAD};

    // Linux disables IPv6 outright on an interface below 1280 bytes, so the
    // overlay address could never be assigned. Catch it here rather than as
    // an obscure RTNETLINK error much later.
    let dir = TempDir::new().unwrap();
    let result = WireguardPlugin::open(
        WireguardConfig::new(dir.path()).with_mtu(MIN_MTU - 1),
        Arc::new(MemoryTunFactory::new()),
    )
    .await;
    match result {
        Err(err) => {
            let text = err.to_string();
            assert!(text.contains("1280"), "unexpected message: {text}");
            assert!(text.contains("IPv6"), "unexpected message: {text}");
        }
        Ok(_) => panic!("an MTU below the IPv6 minimum must be refused"),
    }

    // The default is exactly the minimum, and a link has to carry it plus
    // WireGuard's own overhead.
    assert_eq!(DEFAULT_MTU, MIN_MTU);
    assert_eq!(WIREGUARD_OVERHEAD, 32);
    assert!(
        WireguardPlugin::open(
            WireguardConfig::new(dir.path().join("ok")),
            Arc::new(MemoryTunFactory::new()),
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn the_overlay_address_is_derived_from_the_key_alone() {
    let (name, secret) = network("wg-derivation");
    let id = tsunagi::identity::NetworkKeys::derive(&name, &secret).network_id();
    let key = WgSecretKey::generate().public();
    assert_eq!(overlay_address(id, &key), overlay_address(id, &key));
    assert_ne!(
        overlay_address(id, &key),
        overlay_address(id, &WgSecretKey::generate().public())
    );
}

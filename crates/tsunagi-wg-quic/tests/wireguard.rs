//! The WireGuard data plane, driven over real iroh connections.
//!
//! Everything here is real except the packet interface: real agents, real
//! control plane, real iroh data links, real WireGuard handshakes and
//! encryption from `boringtun`. Only the TUN device is in memory, which is why
//! the whole data plane can be tested with no privileges and without touching
//! the host's network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::EndpointId;
use tempfile::TempDir;
use tsunagi::agent::Event;
use tsunagi::dataplane::IpPlugin;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkId, NetworkName, NetworkSecret};
use tsunagi::overlay::{MemoryTun, MemoryTunFactory};
use tsunagi::state::Ipv4Range;
use tsunagi::testing::{config_with, network, settle, wait_event, wait_for_peers, wait_until};
use tsunagi::{Agent, NetworkStatus};
use tsunagi_wg_quic::{
    WIREGUARD_PROTOCOL, WgAnnouncement, WgSecretKey, WireguardConfig, WireguardPlugin,
};

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
        Self::spawn_full(
            discovery,
            tag,
            tune,
            Some(tsunagi::state::DEFAULT_IPV4_RANGE),
        )
        .await
    }

    /// Starts an agent with an explicit overlay range, or none at all.
    async fn spawn_range(
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        range: Option<Ipv4Range>,
    ) -> Self {
        Self::spawn_full(discovery, tag, |config| config, range).await
    }

    async fn spawn_full(
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
        range: Option<Ipv4Range>,
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let (agent, plugin, tuns) = Self::open_with(dir.path(), discovery, tag, tune, range).await;
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
        Self::open_with(
            root,
            discovery,
            tag,
            tune,
            Some(tsunagi::state::DEFAULT_IPV4_RANGE),
        )
        .await
    }

    async fn open_with(
        root: &std::path::Path,
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
        range: Option<Ipv4Range>,
    ) -> (Agent, Arc<WireguardPlugin>, MemoryTunFactory) {
        let tuns = MemoryTunFactory::new();
        let wg = tune(
            WireguardConfig::new(root.join("wireguard"))
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        );
        let plugin = WireguardPlugin::open(wg).await.unwrap();
        // The interface belongs to the agent now, so the tag names it
        // directly rather than prefixing one per network.
        let agent = Agent::spawn(
            config_with(root, discovery)
                .with_overlay_ipv4_range(range)
                .with_interface(Arc::new(tuns.clone()), tag, 1280)
                .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
        )
        .await
        .unwrap();
        (agent, plugin, tuns)
    }

    fn endpoint_id(&self) -> EndpointId {
        self.agent.endpoint_id()
    }

    /// This agent's overlay address in a network.
    ///
    /// Allocated and signed at the system level, so it appears once the
    /// network has agreed on it rather than the moment the plugin starts.
    async fn overlay(&self, network: NetworkId) -> Ipv4Addr {
        wait_until("the network agreed an overlay address", || async {
            self.plugin.overview(network)?.overlay_address_v4
        })
        .await
    }

    /// The one in-memory packet interface this agent owns.
    ///
    /// Not per network: one agent has one interface, and which network a
    /// packet on it belongs to is decided by its address.
    async fn tun(&self, _network: NetworkId) -> Arc<MemoryTun> {
        let name = wait_until("the packet interface exists", || async {
            self.agent.overlay().map(|overlay| overlay.interface)
        })
        .await;
        self.tuns.device(&name).expect("the device was created")
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
    // One shared range, agreed at the system level and signed by each
    // member, not derived from anything either protocol holds.
    let range = a.plugin.overview(network_id).unwrap().ipv4_range.unwrap();
    assert!(range.contains(addr_a) && range.contains(addr_b));

    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A real IP packet, encrypted by WireGuard, carried over iroh, decrypted
    // on the other side and handed to that host's packet interface.
    let payload = b"hello over the overlay";
    tun_a.push_from_os(ipv4_packet(addr_a, addr_b, payload));

    let received = tokio::time::timeout(tsunagi::testing::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the packet should arrive")
        .expect("the interface should still be open");
    assert_eq!(&received[20..], payload);
    assert_eq!(&received[12..16], &addr_a.octets(), "source preserved");
    assert_eq!(&received[16..20], &addr_b.octets(), "destination preserved");

    // And back the other way.
    tun_b.push_from_os(ipv4_packet(addr_b, addr_a, b"and back"));
    let back = tokio::time::timeout(tsunagi::testing::DEADLINE, tun_a.pop_to_os())
        .await
        .expect("the reply should arrive")
        .unwrap();
    assert_eq!(&back[20..], b"and back");

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
    let someone_else = {
        let mut octets = addr_a.octets();
        octets[3] ^= 0xff;
        Ipv4Addr::from(octets)
    };
    tun_a.push_from_os(ipv4_packet(someone_else, addr_b, b"spoofed"));

    // B must drop it: the source is not the address A holds.
    // Counted on the interface, not on the tunnel: the protocol proved who
    // sent the packet, and whether that member may use the address it chose
    // is a question about a signed claim, which the system level holds.
    wait_until("the spoofed packet is dropped", || async {
        (b.agent.overlay()?.counters.wrong_source >= 1).then_some(())
    })
    .await;

    // A legitimate packet still goes through, so the tunnel is not broken.
    tun_a.push_from_os(ipv4_packet(addr_a, addr_b, b"honest"));
    let received = tokio::time::timeout(tsunagi::testing::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the honest packet should arrive")
        .unwrap();
    assert_eq!(&received[20..], b"honest");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn the_overlay_uses_a_range_the_network_was_told_to_use() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-dual-stack");

    let range = Some("10.77.0.0/16".parse::<Ipv4Range>().unwrap());
    let a = WgAgent::spawn_range(&discovery, "ta", range).await;
    let b = WgAgent::spawn_range(&discovery, "tb", range).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let view_a = a.plugin.overview(network_id).unwrap();
    let view_b = b.plugin.overview(network_id).unwrap();

    let v4_a = view_a.overlay_address_v4.expect("ipv4 was configured");
    let v4_b = view_b.overlay_address_v4.expect("ipv4 was configured");
    assert_ne!(v4_a, v4_b);
    // Both inside the configured range.
    for addr in [v4_a, v4_b] {
        assert_eq!(
            u32::from(addr) & 0xffff_0000,
            u32::from(Ipv4Addr::new(10, 77, 0, 0))
        );
    }
    // Each side learned the other's address from the same signed state.
    assert_eq!(view_a.peers[0].overlay_address_v4, Some(v4_b));
    assert_eq!(view_b.peers[0].overlay_address_v4, Some(v4_a));

    let tun_a = a.tun(network_id).await;
    let tun_b = b.tun(network_id).await;

    // A real IPv4 packet through the same tunnel.
    tun_a.push_from_os(ipv4_packet(v4_a, v4_b, b"ipv4 over the overlay"));
    let received = tokio::time::timeout(tsunagi::testing::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the IPv4 packet should arrive")
        .unwrap();
    assert_eq!(received[0] >> 4, 4, "still an IPv4 packet");
    assert_eq!(&received[12..16], &v4_a.octets());
    assert_eq!(&received[16..20], &v4_b.octets());
    assert_eq!(&received[20..], b"ipv4 over the overlay");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn an_ipv4_source_a_peer_does_not_own_is_dropped() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-v4-spoof");

    let range = Some("10.78.0.0/16".parse::<Ipv4Range>().unwrap());
    let a = WgAgent::spawn_range(&discovery, "ta", range).await;
    let b = WgAgent::spawn_range(&discovery, "tb", range).await;
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
        (b.agent.overlay()?.counters.wrong_source >= 1).then_some(())
    })
    .await;

    // The honest one still gets through.
    tun_a.push_from_os(ipv4_packet(v4_a, v4_b, b"honest v4"));
    let received = tokio::time::timeout(tsunagi::testing::DEADLINE, tun_b.pop_to_os())
        .await
        .expect("the honest packet should arrive")
        .unwrap();
    assert_eq!(&received[20..], b"honest v4");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_joining_member_adopts_the_range_the_network_already_uses() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-range-adopted");

    // The two were started with different ranges. Rather than misroute, they
    // converge on one, and every replica computes the same answer.
    let a = WgAgent::spawn_range(&discovery, "ta", Some("10.80.0.0/16".parse().unwrap())).await;
    let b = WgAgent::spawn_range(&discovery, "tb", Some("10.81.0.0/16".parse().unwrap())).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;
    b.wait_for_tunnels(network_id, 1).await;

    let agreed = wait_until("both settle on one range", || async {
        let one = a.plugin.overview(network_id)?.ipv4_range?;
        let two = b.plugin.overview(network_id)?.ipv4_range?;
        (one == two).then_some(one)
    })
    .await;

    // Whichever won, both hold an address inside it, and they differ.
    let view_a = wait_until("a has an address in the agreed range", || async {
        let view = a.plugin.overview(network_id)?;
        let address = view.overlay_address_v4?;
        agreed.contains(address).then_some(view)
    })
    .await;
    let view_b = wait_until("b has an address in the agreed range", || async {
        let view = b.plugin.overview(network_id)?;
        let address = view.overlay_address_v4?;
        agreed.contains(address).then_some(view)
    })
    .await;
    assert_ne!(view_a.overlay_address_v4, view_b.overlay_address_v4);

    // And each sees the other at the same address it sees for itself.
    let seen_b = wait_until("a sees b's address", || async {
        a.plugin
            .overview(network_id)?
            .peers
            .first()?
            .overlay_address_v4
    })
    .await;
    assert_eq!(Some(seen_b), view_b.overlay_address_v4);

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn an_allocated_address_missing_from_the_host_is_reported() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-missing-address");

    // The in-memory interface never carries the address, which is exactly
    // the situation of a real interface the operator has not configured yet.
    // Left unsaid, packets leave with the wrong source and every peer drops
    // them, which looks like a broken network rather than a missing command.
    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;

    let mut events = a.agent.subscribe();
    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_tunnels(network_id, 1).await;

    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError { reason, .. } if reason.contains("not on any") => Some(reason.clone()),
        _ => None,
    })
    .await;

    let allocated = a
        .plugin
        .overview(network_id)
        .unwrap()
        .overlay_address_v4
        .unwrap();
    assert!(
        reason.contains(&allocated.to_string()),
        "unexpected: {reason}"
    );
    // The agent owns the interface, so it is the agent that notices and the
    // report names the interface the address should have been on.
    assert!(
        reason.contains(&a.agent.overlay().unwrap().interface),
        "must name the interface: {reason}"
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn an_address_is_kept_across_a_restart() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-address-persists");

    let peer = WgAgent::spawn(&discovery, "tp").await;
    let subject = WgAgent::spawn(&discovery, "ts").await;

    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    peer.wait_for_tunnels(network_id, 1).await;

    let before = wait_until("the subject has an address", || async {
        subject.plugin.overview(network_id)?.overlay_address_v4
    })
    .await;
    // The peer agrees about it.
    let seen_before = wait_until("the peer sees it", || async {
        peer.plugin
            .overview(network_id)?
            .peers
            .first()?
            .overlay_address_v4
    })
    .await;
    assert_eq!(seen_before, before);

    // Go away, come back. The address is a signed record, not a derivation
    // and not a session fact, so it survives.
    let dir = subject.shutdown().await;
    let (agent, plugin, _tuns) = WgAgent::open(dir.path(), &discovery, "ts", |config| config).await;

    let after = wait_until("the restarted agent has an address", || async {
        plugin.overview(network_id)?.overlay_address_v4
    })
    .await;
    assert_eq!(
        after, before,
        "a returning participant must reclaim the address it signed for"
    );

    // And the peer still agrees, without having had to do anything.
    let seen_after = wait_until("the peer still agrees", || async {
        let seen = peer
            .plugin
            .overview(network_id)?
            .peers
            .first()?
            .overlay_address_v4?;
        (seen == after).then_some(seen)
    })
    .await;
    assert_eq!(seen_after, after);

    agent.shutdown().await;
    peer.agent.shutdown().await;
    drop(agent);
    drop(dir);
}

#[tokio::test]
async fn three_members_get_three_different_addresses() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-allocation");

    let a = WgAgent::spawn(&discovery, "ta").await;
    let b = WgAgent::spawn(&discovery, "tb").await;
    let c = WgAgent::spawn(&discovery, "tc").await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();

    for agent in [&a, &b, &c] {
        agent.wait_for_tunnels(network_id, 2).await;
    }

    // Everybody ends up knowing all three addresses, and they are distinct.
    let addresses = wait_until("everyone agrees on three addresses", || async {
        let mut all = std::collections::BTreeSet::new();
        for agent in [&a, &b, &c] {
            let view = agent.plugin.overview(network_id)?;
            all.insert(view.overlay_address_v4?);
            for peer in &view.peers {
                all.insert(peer.overlay_address_v4?);
            }
        }
        (all.len() == 3).then_some(all)
    })
    .await;

    let default_range = tsunagi::state::DEFAULT_IPV4_RANGE;
    for address in &addresses {
        assert!(
            default_range.contains(*address),
            "{address} outside the range"
        );
        assert_ne!(address.octets()[3], 0);
        assert_ne!(address.octets()[3], 255);
    }

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
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
    let nowhere: Ipv4Addr = "192.0.2.111".parse().unwrap();
    tun_a.push_from_os(ipv4_packet(addr_a, nowhere, b"lost"));

    wait_until("the packet is counted as unroutable", || async {
        let view = a.plugin.overview(network_id)?;
        let _ = view;
        (a.agent.overlay()?.counters.unroutable >= 1).then_some(())
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
        assert!(
            view.peers
                .iter()
                .all(|peer| peer.public_key != view.public_key)
        );
        addresses.push(agent.overlay(network_id).await);
    }
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 3, "every member has its own address");

    // A packet from A reaches C directly, not via B.
    let addr_a = a.overlay(network_id).await;
    let addr_c = c.overlay(network_id).await;
    a.tun(network_id)
        .await
        .push_from_os(ipv4_packet(addr_a, addr_c, b"a to c"));
    let received = tokio::time::timeout(
        tsunagi::testing::DEADLINE,
        c.tun(network_id).await.pop_to_os(),
    )
    .await
    .expect("the packet should arrive")
    .unwrap();
    assert_eq!(&received[20..], b"a to c");

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
async fn two_networks_share_one_interface_with_keys_and_ranges_of_their_own() {
    // One agent, one interface — so two networks on it must use different
    // ranges, or an address would belong to both. Each network's range is
    // settled by whoever got there first, and the agent adopts what it
    // finds; see the routing table's own tests for the refusal when they
    // overlap.
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("wg-left");
    let (name_b, secret_b) = network("wg-right");
    let beta_range = Some("10.99.0.0/16".parse::<Ipv4Range>().unwrap());

    let hub = WgAgent::spawn(&discovery, "th").await;
    let left = WgAgent::spawn(&discovery, "tl").await;
    let right = WgAgent::spawn_range(&discovery, "tr", beta_range).await;

    // The other members settle each range before the hub joins, so it has
    // something to adopt rather than a default to collide with.
    let alpha = left.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = right.agent.join_network(&name_b, &secret_b).await.unwrap();
    left.overlay(alpha).await;
    right.overlay(beta).await;

    hub.agent.join_network(&name_a, &secret_a).await.unwrap();
    hub.agent.join_network(&name_b, &secret_b).await.unwrap();
    hub.wait_for_tunnels(alpha, 1).await;
    hub.wait_for_tunnels(beta, 1).await;

    assert_ne!(
        hub.plugin.overview(alpha).unwrap().public_key,
        hub.plugin.overview(beta).unwrap().public_key,
        "one WireGuard identity per network, not one per host"
    );
    assert_eq!(
        hub.tuns.devices().len(),
        1,
        "one agent has one interface, whatever it is a member of"
    );

    // Each network's address comes from its own range.
    let hub_alpha = wait_until("the hub settles into alpha's range", || async {
        let address = hub.plugin.overview(alpha)?.overlay_address_v4?;
        tsunagi::state::DEFAULT_IPV4_RANGE
            .contains(address)
            .then_some(address)
    })
    .await;
    let hub_beta = wait_until("the hub settles into beta's range", || async {
        let address = hub.plugin.overview(beta)?.overlay_address_v4?;
        beta_range?.contains(address).then_some(address)
    })
    .await;
    assert_ne!(hub_alpha, hub_beta);

    // Traffic in one overlay never surfaces in the other, though both cross
    // the same interface.
    let left_addr = left.overlay(alpha).await;
    hub.tun(alpha)
        .await
        .push_from_os(ipv4_packet(hub_alpha, left_addr, b"alpha only"));
    let seen = tokio::time::timeout(
        tsunagi::testing::DEADLINE,
        left.tun(alpha).await.pop_to_os(),
    )
    .await
    .expect("the packet should arrive")
    .unwrap();
    assert_eq!(&seen[20..], b"alpha only");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            right.tun(beta).await.pop_to_os()
        )
        .await
        .is_err(),
        "the other overlay must see nothing"
    );

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
async fn an_announcement_for_another_network_never_reaches_a_tunnel() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("wg-hijack").unwrap();
    let secret = NetworkSecret::generate();

    let victim = WgAgent::spawn(&discovery, "tv").await;
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();

    // Addresses are not in an announcement any more, so there is no address
    // to forge. What is left to lie about is which network the key is for —
    // and a capability is scoped to the session it arrived on, so claiming
    // another network's is the shape a confused or hostile member takes.
    let attacker_key = WgSecretKey::generate().public();
    let elsewhere = tsunagi::identity::NetworkKeys::derive(
        &NetworkName::new("somewhere-else").unwrap(),
        &NetworkSecret::generate(),
    )
    .network_id();
    let forged = WgAnnouncement::new(elsewhere, &attacker_key);

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

    // Filtered on the reason: this agent reports other things too, and the
    // first plugin error to arrive is not necessarily this one.
    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError {
            protocol, reason, ..
        } if protocol == WIREGUARD_PROTOCOL && reason.contains("different network") => {
            Some(reason.clone())
        }
        _ => None,
    })
    .await;
    assert!(reason.contains("different network"), "unexpected: {reason}");

    settle().await;
    let view = victim.plugin.overview(network_id).unwrap();
    assert!(
        view.peers
            .iter()
            .all(|peer| peer.public_key != attacker_key),
        "a rejected announcement must never become a tunnel"
    );
    attacker.shutdown().await;
    victim.shutdown().await;
    drop(attacker_dir);
}

#[tokio::test]
async fn a_peer_at_another_protocol_version_gets_no_data_plane_and_keeps_the_control_plane() {
    // Both sides must have the protocol at the same version. There is no
    // middle ground to negotiate: either the words mean the same thing at
    // both ends or they do not.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-version");

    let here = WgAgent::spawn(&discovery, "tvh").await;
    let network_id = here.agent.join_network(&name, &secret).await.unwrap();

    let ahead = Arc::new(FromTheFuture);
    let dir = TempDir::new().unwrap();
    let other = Agent::spawn(
        config_with(dir.path(), &discovery).with_plugin(ahead.clone() as Arc<dyn IpPlugin>),
    )
    .await
    .unwrap();

    let mut events = here.agent.subscribe();
    other.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&here.agent, network_id, 1).await;

    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError { reason, .. } if reason.contains("version") => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(
        reason.contains("control plane is unaffected"),
        "the message should say what still works: {reason}"
    );

    // No tunnel, and no attempt at one.
    settle().await;
    assert!(
        here.plugin.overview(network_id).unwrap().peers.is_empty(),
        "a version that cannot match must not become a tunnel"
    );
    let status = here.agent.network_status(network_id).await.unwrap();
    assert_eq!(status.peers.len(), 1, "the session is up all the same");
    assert!(
        status.peers[0].protocols.is_empty(),
        "nothing was agreed with it: {:?}",
        status.peers[0].protocols
    );

    // And the control plane carries a message to it regardless.
    assert_eq!(
        here.agent
            .broadcast(
                network_id,
                tsunagi::proto::ControlMessage::Ping {
                    seq: 1,
                    payload: b"still talking".to_vec(),
                },
            )
            .await
            .unwrap(),
        1
    );

    other.shutdown().await;
    here.shutdown().await;
    drop(dir);
}

#[tokio::test]
async fn agreement_turns_on_the_protocol_version_and_nothing_else() {
    // A different build is not a different protocol. What is compared is the
    // wire version and the name; everything else about a peer — its release,
    // and whatever opaque payload its announcement carries — has no say.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-same-wire");

    let here = WgAgent::spawn(&discovery, "tsw").await;
    let network_id = here.agent.join_network(&name, &secret).await.unwrap();

    // Announces the right protocol at the right version, with a payload
    // this build has never seen.
    let stranger = Arc::new(ForgingPlugin {
        payload: std::sync::Mutex::new(Some(b"from some other release".to_vec())),
    });
    let dir = TempDir::new().unwrap();
    let other = Agent::spawn(
        config_with(dir.path(), &discovery).with_plugin(stranger.clone() as Arc<dyn IpPlugin>),
    )
    .await
    .unwrap();
    other.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&here.agent, network_id, 1).await;

    // Agreed, because the wire matches. The payload is rejected by the
    // protocol afterwards, which is a separate matter and says nothing about
    // whether the two agreed to talk.
    wait_until("the protocol is agreed with it", || async {
        let status = here.agent.network_status(network_id).await.ok()?;
        status
            .peers
            .first()?
            .protocols
            .contains(&WIREGUARD_PROTOCOL.to_string())
            .then_some(())
    })
    .await;

    other.shutdown().await;
    here.shutdown().await;
    drop(dir);
}

/// A plugin claiming the same protocol at a version this build does not speak.
#[derive(Debug)]
struct FromTheFuture;

impl IpPlugin for FromTheFuture {
    fn protocol_id(&self) -> &str {
        WIREGUARD_PROTOCOL
    }

    fn protocol_version(&self) -> u16 {
        tsunagi_wg_quic::ANNOUNCEMENT_VERSION + 1
    }

    fn local_capability(
        &self,
        _network: NetworkId,
    ) -> Result<Option<tsunagi::dataplane::PluginCapability>, tsunagi::dataplane::PluginError> {
        Ok(Some(tsunagi::dataplane::PluginCapability {
            protocol: WIREGUARD_PROTOCOL.to_string(),
            version: self.protocol_version(),
            enabled: true,
            data: Vec::new(),
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

    /// The same version, so the announcement is looked at rather than
    /// dismissed for the wrong reason.
    fn protocol_version(&self) -> u16 {
        tsunagi_wg_quic::ANNOUNCEMENT_VERSION
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
            // The version it actually speaks, so the payload is examined
            // rather than set aside for the wrong reason.
            version: tsunagi_wg_quic::ANNOUNCEMENT_VERSION,
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
async fn an_mtu_below_what_ipv4_guarantees_is_refused() {
    use tsunagi_wg_quic::{DEFAULT_MTU, MIN_MTU, WIREGUARD_OVERHEAD};

    // 576 bytes is what every IPv4 host must be able to reassemble, so
    // nothing below it is worth offering. The floor used to be 1280 for
    // IPv6's sake; the overlay is IPv4 now and a relayed path with small
    // datagrams can be matched instead of warned about.
    let dir = TempDir::new().unwrap();
    let result =
        WireguardPlugin::open(WireguardConfig::new(dir.path()).with_mtu(MIN_MTU - 1)).await;
    match result {
        Err(err) => {
            let text = err.to_string();
            assert!(text.contains("576"), "unexpected message: {text}");
        }
        Ok(_) => panic!("an MTU below what IPv4 guarantees must be refused"),
    }

    // The default leaves room below it now, which is the point of lowering
    // the floor, and a link has to carry it plus WireGuard's own overhead.
    const { assert!(DEFAULT_MTU > MIN_MTU) };
    assert_eq!(WIREGUARD_OVERHEAD, 32);
    assert!(
        WireguardPlugin::open(WireguardConfig::new(dir.path().join("ok")))
            .await
            .is_ok()
    );
}

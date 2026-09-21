//! The WireGuard data plane plugin, driven over real iroh connections.
//!
//! Every agent here is a real agent with a real control plane. Only the part
//! that would change the host's network is substituted: the plugin runs
//! against [`RecordingBackend`], so the suite needs no root and touches no
//! interfaces, while the key handling, the announcements, the derived
//! addressing, the configuration builder and reconciliation are all the real
//! ones.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{DEADLINE, config_with, network, settle, wait_event, wait_for_peers, wait_until};
use iroh::EndpointId;
use tempfile::TempDir;
use tsunagi::agent::Event;
use tsunagi::config::AgentConfig;
use tsunagi::dataplane::wireguard::{
    AdvertisePolicy, Cidr, InterfaceState, PortPolicy, RecordingBackend, WIREGUARD_PROTOCOL,
    WgAnnouncement, WgPublicKey, WgSecretKey, WireguardConfig, WireguardPlugin, overlay_address,
    overlay_prefix,
};
use tsunagi::dataplane::{IpPlugin, PluginCapability, PluginError};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkId, NetworkName, NetworkSecret};
use tsunagi::{Agent, NetworkStatus};

/// An agent, its WireGuard plugin and the backend that plugin drives.
struct WgAgent {
    dir: TempDir,
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    backend: RecordingBackend,
}

impl WgAgent {
    /// Starts an agent whose WireGuard plugin writes into an in-memory backend.
    ///
    /// Each agent gets its own interface prefix, because the rest of the name
    /// is derived from the network id and these all share one host.
    async fn spawn(discovery: &SharedMemoryDiscovery, tag: &str, advertise: IpAddr) -> Self {
        Self::spawn_with(discovery, tag, advertise, |config| config).await
    }

    async fn spawn_with(
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        advertise: IpAddr,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let (agent, plugin, backend) =
            Self::open(dir.path(), discovery, tag, advertise, tune).await;
        Self {
            dir,
            agent,
            plugin,
            backend,
        }
    }

    async fn open(
        root: &std::path::Path,
        discovery: &SharedMemoryDiscovery,
        tag: &str,
        advertise: IpAddr,
        tune: impl FnOnce(WireguardConfig) -> WireguardConfig,
    ) -> (Agent, Arc<WireguardPlugin>, RecordingBackend) {
        let backend = RecordingBackend::new();
        let wg = tune(
            WireguardConfig::new(root.join("wireguard"))
                .with_interface_prefix(tag)
                .with_advertise(AdvertisePolicy::Explicit(vec![advertise]))
                .with_ports(PortPolicy::Fixed(51820))
                .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
        );
        let plugin = WireguardPlugin::open(wg, Arc::new(backend.clone()))
            .await
            .unwrap();
        let config: AgentConfig =
            config_with(root, discovery).with_plugin(plugin.clone() as Arc<dyn IpPlugin>);
        let agent = Agent::spawn(config).await.unwrap();
        (agent, plugin, backend)
    }

    fn endpoint_id(&self) -> EndpointId {
        self.agent.endpoint_id()
    }

    /// The interface this agent's plugin owns for a network.
    async fn interface(&self, network: NetworkId) -> String {
        wait_until("the plugin prepared the network", || async {
            self.plugin.overview(network).map(|view| view.interface)
        })
        .await
    }

    /// Waits until the applied configuration has exactly `count` peers.
    async fn wait_for_wg_peers(&self, network: NetworkId, count: usize) -> InterfaceState {
        let interface = self.interface(network).await;
        wait_until(
            &format!("{count} WireGuard peers on {interface}"),
            || async {
                let state = self.backend.state(&interface)?;
                (state.peers.len() == count).then_some(state)
            },
        )
        .await
    }

    async fn shutdown(self) -> TempDir {
        self.agent.shutdown().await;
        self.dir
    }
}

fn addr(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// The overlay address a peer should have been given, derived independently.
fn expected_allowed_ips(network: NetworkId, key: &WgPublicKey) -> Vec<Cidr> {
    vec![Cidr::host(overlay_address(network, key))]
}

#[tokio::test]
async fn two_agents_build_each_others_wireguard_configuration() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-pair");

    let a = WgAgent::spawn(&discovery, "ta", addr("10.77.0.1")).await;
    let b = WgAgent::spawn(&discovery, "tb", addr("10.77.0.2")).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, network_id, 1).await;

    let state_a = a.wait_for_wg_peers(network_id, 1).await;
    let state_b = b.wait_for_wg_peers(network_id, 1).await;

    let key_a = a.plugin.overview(network_id).unwrap().public_key;
    let key_b = b.plugin.overview(network_id).unwrap().public_key;
    assert_ne!(key_a, key_b);

    // Each side configured exactly the other, with locally derived AllowedIPs.
    assert_eq!(state_a.peers[0].public_key, key_b);
    assert_eq!(
        state_a.peers[0].allowed_ips,
        expected_allowed_ips(network_id, &key_b)
    );
    assert_eq!(state_b.peers[0].public_key, key_a);
    assert_eq!(
        state_b.peers[0].allowed_ips,
        expected_allowed_ips(network_id, &key_a)
    );

    // The endpoint each side uses is the one the *plugin* advertised, not an
    // iroh address.
    assert_eq!(
        state_a.peers[0].endpoint,
        Some(SocketAddr::new(addr("10.77.0.2"), 51820))
    );
    let iroh_addrs: Vec<IpAddr> = b
        .agent
        .status()
        .await
        .unwrap()
        .bound_sockets
        .iter()
        .map(SocketAddr::ip)
        .collect();
    assert!(
        !iroh_addrs.contains(&addr("10.77.0.2")),
        "the WireGuard endpoint must not come from iroh's addresses"
    );

    // Both derive the same overlay subnet and their own distinct address.
    let view_a = a.plugin.overview(network_id).unwrap();
    let view_b = b.plugin.overview(network_id).unwrap();
    assert_eq!(view_a.overlay_prefix, view_b.overlay_prefix);
    assert_eq!(
        view_a.overlay_prefix,
        IpAddr::V6(overlay_prefix(network_id))
    );
    assert_ne!(view_a.overlay_address, view_b.overlay_address);
    assert_eq!(
        view_a.overlay_address,
        IpAddr::V6(overlay_address(network_id, &key_a))
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_mesh_of_three_gives_every_agent_two_peers() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-mesh");

    let a = WgAgent::spawn(&discovery, "ta", addr("10.77.1.1")).await;
    let b = WgAgent::spawn(&discovery, "tb", addr("10.77.1.2")).await;
    let c = WgAgent::spawn(&discovery, "tc", addr("10.77.1.3")).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();

    for agent in [&a, &b, &c] {
        wait_for_peers(&agent.agent, network_id, 2).await;
        // N - 1 remote peers in the local configuration.
        let state = agent.wait_for_wg_peers(network_id, 2).await;
        assert_eq!(state.listen_port, 51820);
        let own_key = agent.plugin.overview(network_id).unwrap().public_key;
        assert_eq!(state.public_key, own_key);
        assert!(
            state.peers.iter().all(|peer| peer.public_key != own_key),
            "an agent must never configure itself as a peer"
        );
    }

    // Everybody agrees on who is in the overlay and at which address.
    let keys: Vec<WgPublicKey> = [&a, &b, &c]
        .iter()
        .map(|agent| agent.plugin.overview(network_id).unwrap().public_key)
        .collect();
    for agent in [&a, &b, &c] {
        let own = agent.plugin.overview(network_id).unwrap().public_key;
        let state = agent
            .backend
            .state(&agent.interface(network_id).await)
            .unwrap();
        for peer in &state.peers {
            assert!(keys.contains(&peer.public_key));
            assert_eq!(
                peer.allowed_ips,
                expected_allowed_ips(network_id, &peer.public_key)
            );
            assert_ne!(peer.public_key, own);
        }
    }

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

#[tokio::test]
async fn a_departing_peer_is_removed_from_the_configuration() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-departure");

    let stayer = WgAgent::spawn(&discovery, "ta", addr("10.77.2.1")).await;
    let leaver = WgAgent::spawn(&discovery, "tb", addr("10.77.2.2")).await;

    let network_id = stayer.agent.join_network(&name, &secret).await.unwrap();
    leaver.agent.join_network(&name, &secret).await.unwrap();
    stayer.wait_for_wg_peers(network_id, 1).await;

    let leaver_id = leaver.endpoint_id();
    let mut events = stayer.agent.subscribe();
    leaver.shutdown().await;

    wait_event(&mut events, |event| match event {
        Event::PeerDisconnected { peer, .. } if *peer == leaver_id => Some(()),
        _ => None,
    })
    .await;

    // The interface stays, the peer goes.
    let state = stayer.wait_for_wg_peers(network_id, 0).await;
    assert!(state.peers.is_empty());
    assert_eq!(
        state.public_key,
        stayer.plugin.overview(network_id).unwrap().public_key
    );

    stayer.shutdown().await;
}

#[tokio::test]
async fn two_networks_get_separate_interfaces_keys_and_overlays() {
    let discovery = SharedMemoryDiscovery::new();
    let (name_a, secret_a) = network("wg-left");
    let (name_b, secret_b) = network("wg-right");

    let hub = WgAgent::spawn(&discovery, "th", addr("10.77.3.1")).await;
    let left = WgAgent::spawn(&discovery, "tl", addr("10.77.3.2")).await;
    let right = WgAgent::spawn(&discovery, "tr", addr("10.77.3.3")).await;

    let alpha = hub.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = hub.agent.join_network(&name_b, &secret_b).await.unwrap();
    left.agent.join_network(&name_a, &secret_a).await.unwrap();
    right.agent.join_network(&name_b, &secret_b).await.unwrap();

    hub.wait_for_wg_peers(alpha, 1).await;
    hub.wait_for_wg_peers(beta, 1).await;

    let view_alpha = hub.plugin.overview(alpha).unwrap();
    let view_beta = hub.plugin.overview(beta).unwrap();

    assert_ne!(view_alpha.interface, view_beta.interface);
    assert_ne!(
        view_alpha.public_key, view_beta.public_key,
        "one identity per network, not one per host"
    );
    assert_ne!(view_alpha.overlay_prefix, view_beta.overlay_prefix);
    assert_eq!(hub.backend.interfaces().len(), 2);

    // Neither interface knows anything about the other network's member.
    let left_key = left.plugin.overview(alpha).unwrap().public_key;
    let right_key = right.plugin.overview(beta).unwrap().public_key;
    let state_alpha = hub.backend.state(&view_alpha.interface).unwrap();
    let state_beta = hub.backend.state(&view_beta.interface).unwrap();
    assert_eq!(state_alpha.peers[0].public_key, left_key);
    assert_eq!(state_beta.peers[0].public_key, right_key);
    assert!(state_alpha.peers.iter().all(|p| p.public_key != right_key));
    assert!(state_beta.peers.iter().all(|p| p.public_key != left_key));

    // Deactivating one network removes only its interface.
    hub.agent.deactivate_network(alpha).await.unwrap();
    wait_until("the alpha interface is gone", || async {
        hub.backend
            .state(&view_alpha.interface)
            .is_none()
            .then_some(())
    })
    .await;
    assert!(hub.backend.state(&view_beta.interface).is_some());

    hub.shutdown().await;
    left.shutdown().await;
    right.shutdown().await;
}

#[tokio::test]
async fn reconciliation_repairs_a_configuration_edited_by_hand() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-drift");

    let a = WgAgent::spawn(&discovery, "ta", addr("10.77.4.1")).await;
    let b = WgAgent::spawn(&discovery, "tb", addr("10.77.4.2")).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();

    let good = a.wait_for_wg_peers(network_id, 1).await;
    let interface = a.interface(network_id).await;

    // Someone edits the interface: the peer's allowed prefix is widened to
    // everything and a bogus address is added.
    let mut tampered = good.clone();
    tampered.peers[0].allowed_ips = vec![Cidr::new(addr("::"), 0).unwrap()];
    tampered
        .addresses
        .push(Cidr::new(addr("192.0.2.1"), 32).unwrap());
    a.backend.inject_drift(&interface, tampered.clone());
    assert_ne!(a.backend.state(&interface).unwrap(), good);

    // The periodic reconcile puts it back without anybody asking.
    let repaired = wait_until("the drift is corrected", || async {
        let state = a.backend.state(&interface)?;
        (state == good).then_some(state)
    })
    .await;
    assert_eq!(repaired.peers[0].allowed_ips, good.peers[0].allowed_ips);
    assert!(
        !repaired
            .addresses
            .contains(&Cidr::new(addr("192.0.2.1"), 32).unwrap())
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_data_plane_failure_does_not_stop_the_control_plane() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-failure");

    let a = WgAgent::spawn(&discovery, "ta", addr("10.77.5.1")).await;
    let b = WgAgent::spawn(&discovery, "tb", addr("10.77.5.2")).await;

    let mut events = a.agent.subscribe();
    a.backend
        .fail_next_apply("simulated: no permission to configure the device");

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();

    // The failure is surfaced on the agent's event stream.
    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError {
            network,
            protocol,
            reason,
        } if *network == network_id && protocol == WIREGUARD_PROTOCOL => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(reason.contains("simulated"), "unexpected reason: {reason}");

    // The control plane is untouched: peers stay authenticated and messages
    // keep flowing.
    wait_for_peers(&a.agent, network_id, 1).await;
    a.agent
        .send(
            network_id,
            b.endpoint_id(),
            tsunagi::proto::ControlMessage::Ping {
                seq: 1,
                payload: b"alive".to_vec(),
            },
        )
        .await
        .unwrap();
    wait_event(&mut events, |event| match event {
        Event::MessageReceived {
            message: tsunagi::proto::ControlMessage::Pong { seq: 1, .. },
            ..
        } => Some(()),
        _ => None,
    })
    .await;

    // And the plugin retries, so the interface converges anyway.
    a.wait_for_wg_peers(network_id, 1).await;
    let status: NetworkStatus = a.agent.network_status(network_id).await.unwrap();
    assert!(status.metrics.plugin_errors >= 1);

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn restarting_keeps_the_wireguard_identity_and_overlay_address() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-restart");

    let peer = WgAgent::spawn(&discovery, "tp", addr("10.77.6.9")).await;
    let subject = WgAgent::spawn(&discovery, "ts", addr("10.77.6.1")).await;

    let network_id = peer.agent.join_network(&name, &secret).await.unwrap();
    subject.agent.join_network(&name, &secret).await.unwrap();
    peer.wait_for_wg_peers(network_id, 1).await;

    let before = subject.plugin.overview(network_id).unwrap();
    let dir = subject.shutdown().await;

    let (agent, plugin, backend) =
        WgAgent::open(dir.path(), &discovery, "ts", addr("10.77.6.1"), |config| {
            config
        })
        .await;

    let after = wait_until("the restarted plugin is ready", || async {
        plugin.overview(network_id)
    })
    .await;
    assert_eq!(
        after.public_key, before.public_key,
        "the WireGuard key must survive a restart"
    );
    assert_eq!(after.overlay_address, before.overlay_address);
    assert_eq!(after.interface, before.interface);

    // The peer reconnects and both configurations come back.
    wait_for_peers(&agent, network_id, 1).await;
    wait_until("the restarted interface has its peer", || async {
        backend
            .state(&after.interface)
            .filter(|state| state.peers.len() == 1)
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

    let agent = WgAgent::spawn(&discovery, "ta", addr("10.77.7.1")).await;
    let alpha = agent.agent.join_network(&name_a, &secret_a).await.unwrap();
    let beta = agent.agent.join_network(&name_b, &secret_b).await.unwrap();

    agent.interface(alpha).await;
    agent.interface(beta).await;
    wait_until("both interfaces exist", || async {
        (agent.backend.interfaces().len() == 2).then_some(())
    })
    .await;

    agent.agent.shutdown().await;
    assert!(
        agent.backend.interfaces().is_empty(),
        "a clean shutdown must not leave interfaces behind: {:?}",
        agent.backend.interfaces()
    );
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
    ) -> Result<Option<PluginCapability>, PluginError> {
        let payload = match self.payload.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Ok(payload.map(|data| PluginCapability {
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
        _capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    fn on_peer_gone(&self, _network: NetworkId, _peer: EndpointId) {}
    fn on_network_deactivated(&self, _network: NetworkId) {}
}

#[tokio::test]
async fn a_member_cannot_claim_another_members_overlay_address() {
    let discovery = SharedMemoryDiscovery::new();
    let name = NetworkName::new("wg-hijack").unwrap();
    let secret = NetworkSecret::generate();

    let victim = WgAgent::spawn(&discovery, "tv", addr("10.77.8.1")).await;
    let network_id = victim.agent.join_network(&name, &secret).await.unwrap();
    let victim_view = wait_until("the victim is ready", || async {
        victim.plugin.overview(network_id)
    })
    .await;

    // The attacker knows the secret — it is a legitimate member — and tries to
    // take over the victim's overlay address with its own WireGuard key.
    let attacker_key = WgSecretKey::generate().public();
    let mut forged = WgAnnouncement::new(network_id, &attacker_key, 51820, Vec::new());
    let IpAddr::V6(victim_address) = victim_view.overlay_address else {
        panic!("overlay addresses are IPv6");
    };
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

    // The victim rejects the claim and says why.
    let reason = wait_event(&mut events, |event| match event {
        Event::PluginError {
            protocol, reason, ..
        } if protocol == WIREGUARD_PROTOCOL => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(
        reason.contains("does not match"),
        "unexpected reason: {reason}"
    );

    // Nothing was configured for the attacker, and the victim keeps its own
    // address.
    settle().await;
    let interface = victim.interface(network_id).await;
    let state = victim.backend.state(&interface);
    assert!(
        state
            .map(|state| state
                .peers
                .iter()
                .all(|peer| peer.public_key != attacker_key))
            .unwrap_or(true),
        "a rejected announcement must not reach the configuration"
    );
    assert_eq!(
        victim.plugin.overview(network_id).unwrap().overlay_address,
        victim_view.overlay_address
    );

    attacker.shutdown().await;
    victim.shutdown().await;
    drop(attacker_dir);
}

#[tokio::test]
async fn the_core_carries_the_payload_without_interpreting_it() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-opaque");

    let a = WgAgent::spawn(&discovery, "ta", addr("10.77.9.1")).await;
    let b = WgAgent::spawn(&discovery, "tb", addr("10.77.9.2")).await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    a.wait_for_wg_peers(network_id, 1).await;

    // What the control plane stored for the peer is exactly the bytes the
    // peer's plugin produced, and the core never looked inside.
    let capability = wait_until("the peer's capability arrived", || async {
        let status = a.agent.network_status(network_id).await.ok()?;
        status
            .peers
            .first()
            .and_then(|peer| peer.capabilities.first().cloned())
    })
    .await;
    assert_eq!(capability.protocol, WIREGUARD_PROTOCOL);
    assert!(capability.enabled);

    let view_b = b.plugin.overview(network_id).unwrap();
    let expected = WgAnnouncement::new(
        network_id,
        &view_b.public_key,
        view_b.listen_port,
        view_b.advertised.clone(),
    )
    .encode()
    .unwrap();
    assert_eq!(capability.data, expected);

    // And the payload stays well inside the control protocol's bound.
    assert!(capability.data.len() < tsunagi::Limits::default().max_capability_data_len);

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn local_interface_advertising_produces_usable_endpoints() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-advertise");

    let agent = WgAgent::spawn_with(&discovery, "ta", addr("10.77.10.1"), |config| {
        config.with_advertise(AdvertisePolicy::LocalInterfaces)
    })
    .await;
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();

    let view = wait_until("the plugin is ready", || async {
        agent.plugin.overview(network_id)
    })
    .await;

    // Whatever this host has, nothing loopback, unspecified or link-local may
    // be advertised, and every entry carries the WireGuard port.
    for endpoint in &view.advertised {
        assert_eq!(endpoint.port(), view.listen_port);
        assert!(!endpoint.ip().is_loopback());
        assert!(!endpoint.ip().is_unspecified());
    }
    assert!(view.advertised.len() <= 8, "the list stays bounded");

    agent.shutdown().await;
}

#[tokio::test]
async fn the_plugin_converges_within_the_test_deadline() {
    // A guard against the announce/re-announce handshake regressing into
    // something that only converges on the slow periodic timer.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("wg-timing");

    let a = WgAgent::spawn_with(&discovery, "ta", addr("10.77.11.1"), |config| {
        // A deliberately slow periodic reconcile: convergence must come from
        // the event path, not from the timer.
        config.with_reconcile(Duration::from_millis(20), DEADLINE * 2)
    })
    .await;
    let b = WgAgent::spawn_with(&discovery, "tb", addr("10.77.11.2"), |config| {
        config.with_reconcile(Duration::from_millis(20), DEADLINE * 2)
    })
    .await;

    let network_id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();

    a.wait_for_wg_peers(network_id, 1).await;
    b.wait_for_wg_peers(network_id, 1).await;

    a.shutdown().await;
    b.shutdown().await;
}

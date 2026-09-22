//! The local control interface: a client asking a running agent for status.
//!
//! Uses a real Unix socket on a temporary path, the real agent and the real
//! WireGuard data plane, so what a `tsunagi status` client would see is what
//! is checked here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tsunagi::dataplane::IpPlugin;
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::ipc::{ControlSocket, request_status};
use tsunagi::ipc::{StatusReport, control_socket_path};
use tsunagi::overlay::MemoryTunFactory;
use tsunagi::testing::{config_with, network, wait_for_peers, wait_until};
use tsunagi::{Agent, BoxFuture};
use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};

/// Builds the report the way the binary does, from the agent plus the plugin.
fn source(agent: Agent, plugin: Arc<WireguardPlugin>) -> Arc<dyn tsunagi::ipc::ReportSource> {
    Arc::new(move || -> BoxFuture<'static, StatusReport> {
        let agent = agent.clone();
        let plugin = Arc::clone(&plugin);
        Box::pin(async move {
            let status = agent.status().await.unwrap();
            let networks = status
                .networks
                .iter()
                .map(|net| tsunagi::ipc::NetworkReport {
                    name: net.name.to_string(),
                    network_id: net.network_id.to_string(),
                    active: true,
                    peers: net
                        .peers
                        .iter()
                        .map(|peer| tsunagi::ipc::PeerReport {
                            endpoint_id: peer.endpoint_id.to_string(),
                            hostname: peer.hostname.clone(),
                            transport: format!("{:?}", peer.transport),
                            rtt_ms: peer.rtt.map(|rtt| rtt.as_millis() as u64),
                        })
                        .collect(),
                    overlay: plugin.overview(net.network_id).map(|view| {
                        tsunagi::ipc::OverlayReport {
                            // The interface belongs to the agent now.
                            interface: agent
                                .overlay()
                                .map_or_else(String::new, |overlay| overlay.interface),
                            mtu: agent.overlay().map_or(0, |overlay| overlay.mtu),
                            address: view.overlay_address_v4.map(|a| a.to_string()),
                            prefix_len: view.ipv4_range.map_or(0, |range| range.prefix_len),
                            peers: view
                                .peers
                                .iter()
                                .map(|peer| tsunagi::ipc::OverlayPeerReport {
                                    public_key: peer.public_key.to_string(),
                                    address: peer.overlay_address_v4.map(|a| a.to_string()),
                                    handshake_secs_ago: peer
                                        .tunnel
                                        .as_ref()
                                        .and_then(|t| t.health.since_handshake)
                                        .map(|since| since.as_secs()),
                                    ..Default::default()
                                })
                                .collect(),
                            ..Default::default()
                        }
                    }),
                    ..Default::default()
                })
                .collect();
            StatusReport {
                endpoint_id: status.endpoint_id.to_string(),
                hostname: status.hostname.clone(),
                bound_sockets: status
                    .bound_sockets
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                cache_healthy: status.cache_healthy,
                networks,
                dns: None,
            }
        })
    })
}

#[tokio::test]
async fn a_client_sees_the_agent_and_its_overlay() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("control-socket");

    let dir_a = TempDir::new().unwrap();
    let tuns = MemoryTunFactory::new();
    let plugin = WireguardPlugin::open(
        WireguardConfig::new(dir_a.path().join("wg"))
            .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
    )
    .await
    .unwrap();
    let agent = Agent::spawn(
        config_with(dir_a.path(), &discovery)
            .with_interface(Arc::new(tuns), "tca0", 1280)
            .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
    )
    .await
    .unwrap();

    let dir_b = TempDir::new().unwrap();
    let plugin_b = WireguardPlugin::open(
        WireguardConfig::new(dir_b.path().join("wg"))
            .with_reconcile(Duration::from_millis(20), Duration::from_millis(250)),
    )
    .await
    .unwrap();
    let agent_b = Agent::spawn(
        config_with(dir_b.path(), &discovery)
            .with_interface(Arc::new(MemoryTunFactory::new()), "tcb0", 1280)
            .with_plugin(plugin_b.clone() as Arc<dyn IpPlugin>),
    )
    .await
    .unwrap();

    let network_id = agent.join_network(&name, &secret).await.unwrap();
    agent_b.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&agent, network_id, 1).await;

    // A short path: a Unix socket address is limited to about 100 bytes.
    let socket_path = dir_a.path().join("agent.sock");
    let control = ControlSocket::bind(&socket_path, source(agent.clone(), plugin.clone()))
        .await
        .unwrap();

    let report = wait_until("the overlay is reported as up", || {
        let socket_path = socket_path.clone();
        async move {
            let report = request_status(&socket_path).await.ok()?;
            let overlay = report.networks.first()?.overlay.as_ref()?;
            overlay
                .peers
                .iter()
                .any(|peer| peer.is_up())
                .then_some(report)
        }
    })
    .await;

    assert_eq!(report.endpoint_id, agent.endpoint_id().to_string());
    assert_eq!(report.networks.len(), 1);
    let net = &report.networks[0];
    assert_eq!(net.network_id, network_id.to_string());
    assert_eq!(net.peers.len(), 1);
    assert_eq!(net.peers[0].endpoint_id, agent_b.endpoint_id().to_string());

    let overlay = net.overlay.as_ref().unwrap();
    assert!(overlay.interface.starts_with("tca"));
    assert_eq!(overlay.mtu, 1280);
    assert_eq!(overlay.peers.len(), 1);

    // The report carries what a reader needs, in structured form: how it is
    // laid out is the CLI's business and is tested there.
    assert_eq!(report.endpoint_id, agent.endpoint_id().to_string());
    assert_eq!(
        overlay.peers.iter().filter(|peer| peer.is_up()).count(),
        1,
        "the tunnel is up: {:?}",
        overlay.peers
    );
    assert!(overlay.address.is_some());

    control.shutdown().await;
    assert!(!socket_path.exists(), "the socket is removed on shutdown");

    // With nothing listening, a client gets an error rather than hanging.
    assert!(request_status(&socket_path).await.is_err());

    agent.shutdown().await;
    agent_b.shutdown().await;
}

#[tokio::test]
async fn a_leftover_socket_file_is_replaced_but_a_live_one_is_not() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.sock");

    let empty: Arc<dyn tsunagi::ipc::ReportSource> =
        Arc::new(|| -> BoxFuture<'static, StatusReport> {
            Box::pin(async { StatusReport::default() })
        });

    // A file with nobody listening is a leftover from a crash.
    std::fs::write(&path, b"stale").unwrap();
    let first = ControlSocket::bind(&path, Arc::clone(&empty))
        .await
        .unwrap();
    assert!(request_status(&path).await.is_ok());

    // A live socket is not stolen from the agent that owns it.
    let second = ControlSocket::bind(&path, Arc::clone(&empty)).await;
    assert!(
        matches!(second, Err(tsunagi::Error::StateLocked { .. })),
        "a second agent must not take over a live control socket"
    );

    first.shutdown().await;
}

#[test]
fn the_socket_path_is_derived_and_short_enough() {
    let deep = std::path::PathBuf::from(
        "/home/someone/.local/share/with/a/very/deeply/nested/directory/that/goes/on/and/on/and/on/tsunagi/state",
    );
    let path = control_socket_path(&deep);

    // A Unix socket address is limited to roughly 100 bytes, so a deep state
    // directory must not produce a path that cannot be bound.
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        assert!(
            path.as_os_str().len() < 100,
            "derived path is {} bytes: {}",
            path.as_os_str().len(),
            path.display()
        );
    }

    // Deterministic, and different state directories never share a socket.
    assert_eq!(path, control_socket_path(&deep));
    assert_ne!(
        path,
        control_socket_path(&std::path::PathBuf::from("/somewhere/else"))
    );
}

/// A source that can also leave, the way the binary's one does.
#[derive(Debug)]
struct Control(Agent);

impl tsunagi::ipc::ReportSource for Control {
    fn report(&self) -> BoxFuture<'_, StatusReport> {
        Box::pin(async move { StatusReport::default() })
    }

    fn join(
        &self,
        name: String,
        secret: String,
        _broadcast: Option<bool>,
    ) -> BoxFuture<'_, Result<tsunagi::ipc::JoinedReport, String>> {
        Box::pin(async move {
            let name = tsunagi::identity::NetworkName::new(&name).map_err(|e| e.to_string())?;
            let secret =
                tsunagi::identity::NetworkSecret::decode(&secret).map_err(|e| e.to_string())?;
            let already = self
                .0
                .list_networks()
                .await
                .map_err(|err| err.to_string())?
                .iter()
                .any(|other| other.name == name);
            let network_id = self
                .0
                .join_network(&name, &secret)
                .await
                .map_err(|err| err.to_string())?;
            Ok(tsunagi::ipc::JoinedReport {
                name: name.as_str().to_string(),
                network_id: network_id.to_string(),
                already_configured: already,
                name_shared_with: None,
            })
        })
    }

    fn leave(&self, network_id: String) -> BoxFuture<'_, Result<tsunagi::ipc::LeftReport, String>> {
        Box::pin(async move {
            let wanted: tsunagi::NetworkId = network_id.parse().map_err(|_| "not an id")?;
            let name = self
                .0
                .list_networks()
                .await
                .map_err(|err| err.to_string())?
                .into_iter()
                .find(|network| network.network_id == wanted)
                .map(|network| network.name.as_str().to_string())
                .ok_or("not a network this agent is in")?;
            let outcome = self
                .0
                .leave_network(wanted)
                .await
                .map_err(|err| err.to_string())?;
            Ok(tsunagi::ipc::LeftReport {
                name,
                announced: outcome.announced,
                peers_told: outcome.peers_told as u32,
            })
        })
    }
}

#[tokio::test]
async fn a_client_can_leave_a_network_through_the_running_agent() {
    // The release can only be published by the agent that is running, and
    // only while its sessions are up, so leaving goes over this socket
    // rather than being done behind its back in the state store.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("control-leave");

    let dir = TempDir::new().unwrap();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    let other = TempDir::new().unwrap();
    let peer = Agent::spawn(config_with(other.path(), &discovery))
        .await
        .unwrap();
    let network_id = agent.join_network(&name, &secret).await.unwrap();
    peer.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&agent, network_id, 1).await;

    let socket_path = dir.path().join("control.sock");
    let control = ControlSocket::bind(&socket_path, Arc::new(Control(agent.clone())))
        .await
        .unwrap();

    let report = tsunagi::ipc::leave_network(&socket_path, &network_id.to_string())
        .await
        .unwrap();
    assert_eq!(report.name, name.as_str());
    assert!(report.announced);
    assert_eq!(report.peers_told, 1);
    assert!(agent.list_networks().await.unwrap().is_empty());

    // Asking again names the state it is in rather than failing obscurely.
    let err = tsunagi::ipc::leave_network(&socket_path, &network_id.to_string())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a network"), "{err}");

    control.shutdown().await;
    agent.shutdown().await;
    peer.shutdown().await;
}

#[tokio::test]
async fn a_client_can_add_a_network_to_a_running_agent() {
    // One agent per identity, and it may be in several networks at once —
    // but the state directory belongs to that one live agent, so a second
    // `up` cannot add a network to it. Without this there was no way at
    // all: you could leave a network while running, but not join one.
    let discovery = SharedMemoryDiscovery::new();
    let (first, first_secret) = network("control-join-one");
    let (second, second_secret) = network("control-join-two");

    let dir = TempDir::new().unwrap();
    let agent = Agent::spawn(config_with(dir.path(), &discovery))
        .await
        .unwrap();
    agent.join_network(&first, &first_secret).await.unwrap();

    let socket_path = dir.path().join("control.sock");
    let control = ControlSocket::bind(&socket_path, Arc::new(Control(agent.clone())))
        .await
        .unwrap();

    let report = tsunagi::ipc::join_network(
        &socket_path,
        second.as_str(),
        second_secret.encode().as_str(),
    )
    .await
    .unwrap();
    assert_eq!(report.name, second.as_str());
    assert!(!report.already_configured);

    // Running, not merely written down: it is in the agent's own list and
    // answering for status straight away, on the same identity.
    let joined: tsunagi::NetworkId = report.network_id.parse().unwrap();
    assert!(agent.is_active(joined).await);
    assert_eq!(agent.list_networks().await.unwrap().len(), 2);
    assert!(agent.network_status(joined).await.is_ok());

    // Joining the same one again is not an error, and says which it was.
    let again = tsunagi::ipc::join_network(
        &socket_path,
        second.as_str(),
        second_secret.encode().as_str(),
    )
    .await
    .unwrap();
    assert!(again.already_configured);
    assert_eq!(again.network_id, report.network_id);

    // A secret that is not one is refused rather than stored.
    let err = tsunagi::ipc::join_network(&socket_path, "rubbish", "not-a-secret")
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
    assert_eq!(agent.list_networks().await.unwrap().len(), 2);

    control.shutdown().await;
    agent.shutdown().await;
}

//! Actions and status for the service-owned Rust agent.
use std::{sync::Arc, time::Instant};
use tokio::sync::{mpsc, watch};
use tsunagi::{
    Agent, NetworkName, NetworkSecret,
    ipc::{PrivilegeReport, ProtocolReport, StatusReport},
    vip::VipStatus,
};
use tsunagi_ui::client::Command;
use tsunagi_wg_quic::WireguardPlugin;
use zeroize::Zeroizing;

/// A platform notification or user gesture.
pub enum Request {
    /// A command from the same form used by the tray.
    Action(Command),
    /// The physical network changed.
    NetworkChanged,
    /// Disable only the exit identified by the notification the user tapped.
    DisconnectExit {
        /// Network id captured in the immutable action.
        network: String,
        /// Endpoint id captured at the same time.
        peer: String,
    },
}

/// A configured default route stays visible if its remote peer goes offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitNotice {
    /// Active network identity for the notification action.
    pub network: String,
    /// Selected remote device identity.
    pub peer: String,
    /// Human-readable mesh name.
    pub network_name: String,
    /// Same name shown in the exit chooser.
    pub name: String,
    /// Whether the peer still offers its exit.
    pub online: bool,
}

/// Only an active network with a selected remote exit needs an ongoing notice.
pub fn exit_notice(report: &StatusReport) -> Option<ExitNotice> {
    report.networks.iter().filter(|n| n.active).find_map(|n| {
        let peer = n.exit.via.as_ref()?;
        Some(ExitNotice {
            network: n.network_id.clone(),
            peer: peer.clone(),
            network_name: n.name.clone(),
            name: tsunagi_ui::devices::name_of(n, peer),
            online: n.exit.via_online,
        })
    })
}

/// Actions are serialized in the service command loop. An old PendingIntent cannot
/// clear a replacement exit selected in this or another network.
pub async fn disconnect_exit(
    agent: &Agent,
    network: &str,
    peer: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let network = network.parse()?;
    let peer = peer.parse()?;
    if agent.is_active(network).await && agent.network_status(network).await?.exit_via == Some(peer)
    {
        agent.set_exit_via(network, None).await?;
    }
    Ok(())
}

/// Private reply delivered only to the UI that requested the action.
pub enum Outcome {
    /// The agent has applied the action.
    Applied,
    /// Revisions returned by a successful signed write.
    Saved(Vec<VipStatus>),
    /// A user-requested, single-use clipboard export.
    Clipboard(Zeroizing<String>),
}

/// Delivery channel for a request.
pub type Reply = tokio::sync::oneshot::Sender<Result<Outcome, String>>;
/// Pending acknowledgement of a UI action.
pub type Response = tokio::sync::oneshot::Receiver<Result<Outcome, String>>;

/// Execute exactly the selection and revision supplied by the form.
pub async fn apply(
    command: Command,
    agent: &Agent,
) -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    match command {
        Command::Join { name, secret } => {
            agent
                .join_network(&NetworkName::new(name)?, &NetworkSecret::decode(&secret)?)
                .await?;
        }
        Command::SetActive { network_id, active } => {
            let id = network_id.parse()?;
            if active {
                agent.switch_network(id).await?;
            } else {
                agent.pause_network(id).await?;
            }
        }
        Command::Leave { network_id } => {
            agent.leave_network(network_id.parse()?).await?;
        }
        Command::SetBroadcast {
            network_id,
            enabled,
        } => agent.set_broadcast(network_id.parse()?, enabled).await?,
        Command::SetProtocols {
            network_id,
            protocols,
        } => agent.set_protocols(network_id.parse()?, protocols).await?,
        Command::SetHostname(hostname) => {
            agent.set_hostname(&hostname).await?;
        }
        Command::ForgetNode {
            network_id,
            peer,
            expected_version,
        } => {
            agent
                .forget_node(network_id.parse()?, peer.parse()?, expected_version)
                .await?;
        }
        Command::SetExitNode { network_id, peer } => {
            agent
                .set_exit_via(network_id.parse()?, peer.map(|p| p.parse()).transpose()?)
                .await?
        }
        Command::SetExitOffer { .. } => {
            return Err("This phone can only use a remote exit node.".into());
        }
        Command::SaveVip {
            network_id,
            config,
            expected,
            delete,
            ..
        } => {
            return Ok(Outcome::Saved(
                agent
                    .save_vip(network_id.parse()?, config, expected, delete)
                    .await?,
            ));
        }
        Command::CopySecret { network_id } => {
            return Ok(Outcome::Clipboard(
                agent.network_secret(network_id.parse()?).await?.encode(),
            ));
        }
    }
    Ok(Outcome::Applied)
}

/// State visible to an activity which may be recreated while the service runs.
#[derive(Clone, Default)]
pub enum State {
    /// The user can start the VPN.
    #[default]
    Off,
    /// Opening the endpoint or waiting for connectivity.
    Starting,
    /// The last complete snapshot and its monotonic observation time.
    Ready(Arc<StatusReport>, Instant),
    /// Actionable startup or status error.
    Error(String),
}

/// Build the same network and counter reports used by the desktop client.
pub async fn report(
    agent: &Agent,
    wg: Option<&WireguardPlugin>,
    dns: &crate::dns::Resolver,
) -> tsunagi::Result<StatusReport> {
    let status = agent.status().await?;
    let overlay = agent.overlay();
    Ok(StatusReport {
        networks: tsunagi_runtime::report::networks(&status, overlay.as_ref(), wg),
        overlay_config_error: overlay.and_then(|state| state.address_error),
        dns: Some(dns.refresh(&status.networks)),
        endpoint_id: status.endpoint_id.to_string(),
        hostname: status.hostname,
        bound_sockets: status
            .bound_sockets
            .iter()
            .map(ToString::to_string)
            .collect(),
        cache_healthy: status.cache_healthy,
        available_protocols: tsunagi_runtime::PROTOCOLS
            .iter()
            .map(|spec| ProtocolReport {
                name: spec.name.into(),
                summary: spec.summary.into(),
            })
            .collect(),
        protocols: tsunagi_runtime::PROTOCOLS
            .iter()
            .map(|spec| format!("{} v{}", spec.name, spec.version))
            .collect(),
        privilege: PrivilegeReport::Available,
        version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    })
}

/// Drive the agent until Android stops this service instance.
pub async fn serve(
    agent: Agent,
    wg: Arc<WireguardPlugin>,
    dns: crate::dns::Resolver,
    mut commands: mpsc::Receiver<(Request, Reply)>,
    state: &watch::Sender<State>,
    mut stop: watch::Receiver<bool>,
    mut publish_exit: impl FnMut(Option<&ExitNotice>),
) {
    let mut poll = tokio::time::interval(std::time::Duration::from_secs(2));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut published_exit = None;
    loop {
        let reply = tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => break,
            command = commands.recv() => {
                let Some((request, reply)) = command else { break };
                let result = match request {
                    Request::Action(cmd) => {
                        if matches!(cmd, Command::Join { .. } | Command::Leave { .. } | Command::SetActive { .. }) {
                            dns.replace(None);
                        }
                        apply(cmd, &agent).await.map_err(|e| e.to_string())
                    }
                    Request::NetworkChanged => {
                        agent.endpoint().network_change().await;
                        agent.recheck().await;
                        Ok(Outcome::Applied)
                    }
                    Request::DisconnectExit {network, peer} => disconnect_exit(&agent, &network, &peer).await
                        .map(|()| Outcome::Applied).map_err(|e| e.to_string()),
                };
                Some((reply, result))
            }
            _ = poll.tick() => None,
        };
        state.send_replace(match report(&agent, Some(&wg), &dns).await {
            Ok(report) => {
                let notice = exit_notice(&report);
                if published_exit.as_ref() != Some(&notice) {
                    publish_exit(notice.as_ref());
                    published_exit = Some(notice);
                }
                State::Ready(Arc::new(report), Instant::now())
            }
            Err(error) => State::Error(error.to_string()),
        });
        if let Some((reply, outcome)) = reply {
            let _ = reply.send(outcome);
        }
    }
    agent.shutdown().await;
}

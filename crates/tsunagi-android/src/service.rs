//! Actions and status for the service-owned Rust agent.
use std::{sync::Arc, time::Instant};
use tokio::sync::{mpsc, watch};
use tsunagi::{
    Agent, NetworkName, NetworkSecret,
    ipc::{DnsReport, PrivilegeReport, StatusReport},
    vip::VipStatus,
};
use tsunagi_ui::client::Command;
use tsunagi_wg_quic::WireguardPlugin;
use zeroize::Zeroizing;

/// A platform notification or user gesture.
pub enum Request {
    /// A visible monitor requested its own fresh observation interval.
    WatchTraffic,
    /// A command from the same form used by the tray.
    Action(Command),
    /// The visible activity requested current counters.
    Refresh,
    /// The physical network changed.
    NetworkChanged,
    /// Disable only the exit identified by the notification the user tapped.
    DisconnectExit {
        /// Network id captured in the immutable action.
        network: String,
        /// Endpoint id captured at the same time.
        peer: String,
    },
    /// Restore a remembered network/peer pair only while no other exit is selected.
    RestoreExit {
        /// Network saved at the last successful selection.
        network: String,
        /// Peer used in that network.
        peer: String,
    },
}

/// The latest service lifecycle and cost of the physical network Android selected.
#[derive(Clone, Copy, Default)]
pub struct ServiceSignals {
    /// End this instance.
    pub stopped: bool,
    /// Android reports that data on the current underlay may be billed.
    pub metered: bool,
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

async fn restore_exit(agent: &Agent, network: &str, peer: &str) -> Result<Outcome, String> {
    let network = network.parse().map_err(|_| "Invalid saved network ID")?;
    let peer = peer.parse().map_err(|_| "Invalid saved peer ID")?;
    let status = agent.status().await.map_err(|e| e.to_string())?;
    for n in &status.networks {
        if n.state == tsunagi::agent::NetworkState::Active
            && let Some(current) = n.exit_via
        {
            return if n.network_id == network && current == peer {
                Ok(Outcome::Applied)
            } else {
                Err("Another exit is already selected".into())
            };
        }
    }
    agent
        .set_exit_via(network, Some(peer))
        .await
        .map_err(|e| e.to_string())?;
    Ok(Outcome::Applied)
}

// On cold start the first snapshot often precedes peer discovery. Wait on the
// service's roster notifications, outside the command loop, then let the usual
// serialized command validate the selection again before touching the route.
#[cfg(any(target_os = "android", test))]
pub(crate) async fn wait_for_exit_offer(
    state: &mut watch::Receiver<State>,
    network: &str,
    peer: &str,
) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            match &*state.borrow_and_update() {
                State::Ready(report, _) => {
                    let n = report
                        .networks
                        .iter()
                        .find(|n| n.network_id == network && n.active)
                        .ok_or("The saved exit network is no longer active")?;
                    if report
                        .networks
                        .iter()
                        .any(|n| n.active && n.exit.via.is_some())
                        || n.peers.iter().any(|p| p.endpoint_id == peer && p.exit_node)
                    {
                        return Ok(());
                    }
                }
                State::Off => return Err("Tsunagi Agent stopped".into()),
                State::Error(error) => return Err(error.clone()),
                State::Starting => {}
            }
            state.changed().await.map_err(|_| "Tsunagi Agent stopped")?;
        }
    })
    .await
    .map_err(|_| "The saved peer is offline or no longer offers an exit")?
}

/// Private reply delivered only to the UI that requested the action.
pub enum Outcome {
    /// Owned by one traffic screen and dropped when capture stops.
    Traffic(tsunagi::traffic::TrafficSubscription),
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
    apply_on_link(command, agent, false).await
}

async fn apply_on_link(
    command: Command,
    agent: &Agent,
    metered: bool,
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
        Command::StartSpeedTest { network_id, peer } => {
            agent
                .start_speed_test(
                    network_id.parse()?,
                    peer.map(|p| p.parse()).transpose()?,
                    metered,
                )
                .await?;
        }
        Command::StopSpeedTest { network_id } => agent.stop_speed_test(network_id.parse()?),
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
    snapshot(agent, wg, dns, None).await
}

async fn snapshot(
    agent: &Agent,
    wg: Option<&WireguardPlugin>,
    dns: &crate::dns::Resolver,
    cached_zones: Option<DnsReport>,
) -> tsunagi::Result<StatusReport> {
    let status = agent.status().await?;
    let overlay = agent.overlay();
    Ok(StatusReport {
        networks: tsunagi_runtime::report::networks(&status, overlay.as_ref(), wg),
        overlay_config_error: overlay.and_then(|state| state.address_error),
        dns: Some(dns.with_listener(cached_zones.unwrap_or_else(|| dns.refresh(&status.networks)))),
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
            .map(|spec| spec.report())
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
    mut signals: watch::Receiver<ServiceSignals>,
    mut publish_exit: impl FnMut(Option<&ExitNotice>),
) {
    let mut roster = agent.watch_roster();
    roster.mark_changed(); // Load the initial zones before waiting for any actions.
    let mut cached_zones = None;
    let mut retry = false;
    let mut published_exit = None;
    let mut link = *signals.borrow_and_update();
    agent.set_speed_test_metered(link.metered);
    loop {
        if link.stopped {
            break;
        }
        let (reply, mut refresh_zones) = tokio::select! {
            biased;
            changed = signals.changed() => {
                if changed.is_err() { break; }
                link = *signals.borrow_and_update();
                agent.set_speed_test_metered(link.metered);
                continue;
            }
            command = commands.recv() => {
                let Some((request, reply)) = command else { break };
                let refresh_zones = !matches!(request, Request::Refresh);
                let result = match request {
                    Request::WatchTraffic => {
                        let _ = reply.send(agent.subscribe_traffic().map(Outcome::Traffic));
                        continue;
                    }
                    Request::Refresh => Ok(Outcome::Applied),
                    Request::Action(cmd) => {
                        if matches!(cmd, Command::Join { .. } | Command::Leave { .. } | Command::SetActive { .. }) {
                            dns.replace(None);
                        }
                        apply_on_link(cmd, &agent, link.metered).await.map_err(|e| e.to_string())
                    }
                    Request::NetworkChanged => {
                        agent.endpoint().network_change().await;
                        agent.recheck().await;
                        Ok(Outcome::Applied)
                    }
                    Request::DisconnectExit {network, peer} => disconnect_exit(&agent, &network, &peer).await
                        .map(|()| Outcome::Applied).map_err(|e| e.to_string()),
                    Request::RestoreExit {network, peer} => restore_exit(&agent, &network, &peer).await,
                };
                (Some((reply, result)), refresh_zones)
            }
            changed = roster.changed() => {
                if changed.is_err() { break; }
                (None, true)
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)), if retry => (None, true),
        };
        // A command may itself have changed the roster. Consume notifications
        // before taking the snapshot so changes during the read stay pending.
        refresh_zones |= roster.has_changed().unwrap_or(false);
        if refresh_zones {
            roster.borrow_and_update();
            cached_zones = None;
        }
        state.send_replace(
            match snapshot(&agent, Some(&wg), &dns, cached_zones.take()).await {
                Ok(report) => {
                    retry = false;
                    cached_zones.clone_from(&report.dns);
                    let notice = exit_notice(&report);
                    if published_exit.as_ref() != Some(&notice) {
                        publish_exit(notice.as_ref());
                        published_exit = Some(notice);
                    }
                    State::Ready(Arc::new(report), Instant::now())
                }
                Err(error) => {
                    retry = true;
                    State::Error(error.to_string())
                }
            },
        );
        if let Some((reply, outcome)) = reply {
            let _ = reply.send(outcome);
        }
    }
    agent.shutdown().await;
}

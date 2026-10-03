//! What the tray icon shows: whether the agent has anybody to talk to, and
//! whether this device sends its traffic through an exit node.
//!
//! The tray process has no window and no event loop of its own to poll from,
//! so a thread asks the agent on an interval and hands each answer to a
//! callback, which puts it where the platform wants it.

use std::time::Duration;

use tsunagi::ipc::{self, StatusReport};

use crate::agent::resolve_socket;

/// How often the agent is asked.
const INTERVAL: Duration = Duration::from_secs(3);

/// What the icon says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    /// Nobody is connected, or the agent cannot be reached, or the exit node
    /// this device uses is gone, which blocks its traffic.
    Disconnected,
    /// Connected, nothing out of the ordinary.
    Connected,
    /// This device's traffic leaves through an exit node, and that works.
    ExitNode,
}

impl Health {
    /// The state a status report amounts to; `None` is an agent that did not
    /// answer.
    pub(crate) fn of(report: Option<&StatusReport>) -> Self {
        let Some(report) = report else {
            return Self::Disconnected;
        };
        if !report
            .networks
            .iter()
            .any(|network| !network.peers.is_empty())
        {
            return Self::Disconnected;
        }
        match report
            .networks
            .iter()
            .find(|network| network.exit.via.is_some())
        {
            Some(network) if network.exit.via_online => Self::ExitNode,
            Some(_) => Self::Disconnected,
            None => Self::Connected,
        }
    }

    /// The tooltip of the icon.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "tsunagi: not connected",
            Self::Connected => "tsunagi: connected",
            Self::ExitNode => "tsunagi: using an exit node",
        }
    }
}

/// Starts asking the agent, and calls `notify` with every answer.
pub(crate) fn spawn(notify: impl Fn(Health) + Send + 'static) {
    let spawned = std::thread::Builder::new()
        .name("tray-status".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            loop {
                let report = runtime.block_on(async {
                    tokio::time::timeout(INTERVAL, ipc::request_status(resolve_socket()))
                        .await
                        .ok()
                        .and_then(Result::ok)
                });
                notify(Health::of(report.as_ref()));
                std::thread::sleep(INTERVAL);
            }
        });
    if let Err(err) = spawned {
        eprintln!("cannot watch the agent for the tray icon: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsunagi::ipc::{ExitReport, NetworkReport, PeerReport};

    fn network(peers: usize, exit: ExitReport) -> NetworkReport {
        NetworkReport {
            peers: vec![PeerReport::default(); peers],
            exit,
            ..Default::default()
        }
    }

    fn report(networks: Vec<NetworkReport>) -> StatusReport {
        StatusReport {
            networks,
            ..Default::default()
        }
    }

    #[test]
    fn no_agent_or_nobody_connected_is_the_red_state() {
        assert_eq!(Health::of(None), Health::Disconnected);
        assert_eq!(Health::of(Some(&report(vec![]))), Health::Disconnected);
        assert_eq!(
            Health::of(Some(&report(vec![network(0, ExitReport::default())]))),
            Health::Disconnected
        );
    }

    #[test]
    fn a_connection_in_any_network_is_the_blue_state() {
        let status = report(vec![
            network(0, ExitReport::default()),
            network(2, ExitReport::default()),
        ]);
        assert_eq!(Health::of(Some(&status)), Health::Connected);
    }

    #[test]
    fn an_exit_node_in_use_is_green_while_it_works_and_red_once_it_is_gone() {
        let using = |online| ExitReport {
            via: Some("abc".into()),
            via_online: online,
            ..Default::default()
        };
        assert_eq!(
            Health::of(Some(&report(vec![network(1, using(true))]))),
            Health::ExitNode
        );
        assert_eq!(
            Health::of(Some(&report(vec![network(1, using(false))]))),
            Health::Disconnected
        );
    }
}

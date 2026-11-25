//! Commands and observations shared by both graphical clients.
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tsunagi::ipc::{SpeedPhase, SpeedReport, StatusReport};

/// A request from the UI to the agent.
pub enum Command {
    /// Commit one complete VIP draft if its revision is current.
    SaveVip {
        /// Local acknowledgement token for this Save.
        token: String,
        /// Exact network identity.
        network_id: String,
        /// Complete edited configuration.
        config: tsunagi::vip::VipConfig,
        /// Revision originally opened in the form.
        expected: Option<String>,
        /// Retire this revision when saved.
        delete: bool,
    },
    /// Retire the exact offline-node claim selected in the devices window.
    ForgetNode {
        /// Exact network identity.
        network_id: String,
        /// Selected member identity.
        peer: String,
        /// Observed claim version.
        expected_version: u64,
    },
    /// Replace the network's enabled protocols in preference order.
    SetProtocols {
        /// Exact network identity.
        network_id: String,
        /// Enabled transports in preference order.
        protocols: Vec<String>,
    },
    /// Stop serving a network, or start serving it again.
    SetActive {
        /// Exact network identity.
        network_id: String,
        /// Whether to run the network.
        active: bool,
    },
    /// Turn local broadcast participation on or off for a network.
    SetBroadcast {
        /// Exact network identity.
        network_id: String,
        /// Requested local setting.
        enabled: bool,
    },
    /// Offer this device as an exit node in a network, or stop.
    SetExitOffer {
        /// Exact network identity.
        network_id: String,
        /// Requested local setting.
        enabled: bool,
    },
    /// Send all this device's internet traffic through a member of a
    /// network, or (`None`) back the ordinary way.
    SetExitNode {
        /// Exact network identity.
        network_id: String,
        /// Selected member identity.
        peer: Option<String>,
    },
    /// Measure one peer, or all compatible online exits in sequence.
    StartSpeedTest {
        /// Exact network identity.
        network_id: String,
        /// Exact peer identity, or all exits when absent.
        peer: Option<String>,
    },
    /// Cancel this network's current test and any queued exits.
    StopSpeedTest {
        /// Exact network identity.
        network_id: String,
    },
    /// Join a network, or start one already configured.
    Join {
        /// Network name.
        name: String,
        /// Locally supplied join secret.
        secret: zeroize::Zeroizing<String>,
    },
    /// Leave a network entirely.
    Leave {
        /// Exact network identity.
        network_id: String,
    },
    /// Change the hostname this device announces.
    SetHostname(String),
    /// Fetch a network's shared secret and place it on the clipboard.
    CopySecret {
        /// Exact network identity.
        network_id: String,
    },
}

/// Response to one revision-checked VIP write.
#[derive(Clone)]
pub struct VipSaveResult {
    /// Request being acknowledged.
    pub token: String,
    /// Current VIPs or the error for this draft.
    pub result: Result<Vec<tsunagi::vip::VipStatus>, String>,
}
/// Current observations and last command outcome from a local agent.
#[derive(Clone, Default)]
pub struct Snapshot {
    /// Most recent saved draft.
    pub vip_result: Option<VipSaveResult>,
    /// The last status, or the reason it could not be read (agent down, no
    /// permission on the socket, …).
    pub status: Option<Result<std::sync::Arc<StatusReport>, String>>,
    /// The outcome of the most recent command, for a transient banner.
    pub last_action: Option<Result<String, String>>,
    /// Whether a command is currently being executed.
    pub busy: bool,
    /// Bumped each time `status` is refreshed, so the UI can tell new data from
    /// a repaint of the same data and sample traffic rates only on change.
    pub generation: u64,
    /// When this status was read, for computing rates between refreshes.
    pub at: Option<Instant>,
    /// The socket the last request went to.
    pub socket: PathBuf,
}

/// Delivers a user gesture to the owning worker without blocking the UI.
pub trait Client {
    /// Queue an action from a form.
    fn send(&self, command: Command);
    /// An earlier action is waiting for an acknowledgement.
    fn busy(&self) -> bool;
}

pub(crate) fn speed_running(report: &SpeedReport) -> bool {
    report.batch.is_some()
        || report.peers.values().any(|peer| {
            matches!(
                peer.phase,
                SpeedPhase::Queued
                    | SpeedPhase::Preparing
                    | SpeedPhase::Download
                    | SpeedPhase::Upload
            )
        })
}

/// Poll more frequently while showing a short, live speed measurement.
pub fn status_poll_interval(report: Option<&StatusReport>) -> Duration {
    if report.is_some_and(|r| r.networks.iter().any(|n| speed_running(&n.speed))) {
        Duration::from_millis(250)
    } else {
        Duration::from_secs(2)
    }
}

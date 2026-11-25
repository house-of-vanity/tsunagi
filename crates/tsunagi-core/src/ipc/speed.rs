//! Local presentation of receiver-measured peer throughput.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Tests last requested on this device, scoped to one network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedReport {
    /// Progress of the current sequential exit-node test.
    pub batch: Option<SpeedBatchReport>,
    /// Per-peer progress or the last local result, keyed by endpoint ID.
    pub peers: BTreeMap<String, SpeedPeerReport>,
    /// Currently connected peers advertising the same diagnostic wire version.
    pub capable: Vec<String>,
}

/// Progress of an exit-node batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedBatchReport {
    /// Number of peers that have finished, including failures.
    pub done: u32,
    /// Number selected when the batch started.
    pub total: u32,
}

/// A receiver-confirmed rate in decimal bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedRate {
    /// Measured bits per second.
    pub bps: u64,
    /// The test reached its budget before establishing a throughput ceiling.
    pub lower_bound: bool,
}

/// Locally observed phase of one diagnostic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeedPhase {
    /// Waiting behind another exit in the same batch.
    #[default]
    Queued,
    /// Negotiating over the authenticated control session.
    Preparing,
    /// Receiving test data.
    Download,
    /// Sending test data.
    Upload,
    /// Measurement is complete.
    Done,
    /// The test could not produce a result, with an explanation for the user.
    Failed(String),
    /// The test was stopped.
    Cancelled,
}

/// A single live or completed diagnostic on this device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedPeerReport {
    /// Current or terminal phase.
    pub phase: SpeedPhase,
    /// Download rate from the remote peer.
    pub down: Option<SpeedRate>,
    /// Upload rate to the remote peer.
    pub up: Option<SpeedRate>,
    /// Time since the individual test began.
    pub elapsed_ms: u32,
    /// Unique payload bytes received across both directions.
    pub bytes: u64,
    /// Wall-clock time of the most recent update, for display only.
    pub measured_at_unix_secs: u64,
    /// Data path at the start of the measurement, when known.
    pub path: Option<String>,
}

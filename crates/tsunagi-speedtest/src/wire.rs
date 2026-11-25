use crate::NORMAL_BYTES;
use crate::packet::{MAX_MTU, MIN_MTU};
use serde::{Deserialize, Serialize};

/// Both endpoints name directions from the initiating user's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// From the responding peer to the initiator.
    Download,
    /// From the initiator to the responding peer.
    Upload,
}

/// What the received samples establish about the path.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quality {
    /// Measurement in progress.
    #[default]
    Measuring,
    /// The receiver confirmed a stable rate after the probe reached the path's limit.
    Measured,
    /// Sustained delivery at this rate was established before the time or byte budget ended.
    AtLeast,
    /// No full observation window was available.
    Insufficient,
}

/// Useful probe payload received in one direction.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reading {
    /// Delivered bits per second, if there was enough evidence to calculate a rate.
    pub bps: Option<u64>,
    /// Unique, received probe payload bytes, excluding IPv4 and diagnostic headers.
    pub bytes: u32,
    /// Meaning of the reported rate.
    pub quality: Quality,
}

/// Lifecycle of a single bidirectional test.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// Negotiating a test.
    #[default]
    Starting,
    /// Receiving from the peer.
    Download,
    /// Sending to the peer.
    Upload,
    /// Both direction reports were exchanged.
    Complete,
    /// A participant cancelled this test.
    Cancelled,
    /// The other endpoint is already testing.
    Busy,
    /// A participant failed to finish before the deadline.
    TimedOut,
    /// The transport failed, configuration was invalid, or a peer sent inconsistent results.
    Failed,
}

/// A snapshot suitable for status or a live display.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Current phase or final outcome.
    pub state: State,
    /// Peer to initiator.
    pub down: Reading,
    /// Initiator to peer.
    pub up: Reading,
}

impl Progress {
    pub(crate) fn at(&mut self, direction: Direction) -> &mut Reading {
        match direction {
            Direction::Download => &mut self.down,
            Direction::Upload => &mut self.up,
        }
    }
}

/// Request to start one measurement under both peers' local limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Start {
    /// Fresh random identifier selected by the initiator.
    pub id: u64,
    /// Maximum diagnostic IPv4 bytes to send per direction.
    pub byte_limit: u32,
    /// Maximum complete IPv4 datagram size supported by the initiating endpoint.
    pub mtu: u16,
}

/// Receiver-clock observation at one offered rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feedback {
    pub(crate) stage: u8,
    pub(crate) bps: u64,
    pub(crate) lost_per_mille: u16,
    pub(crate) bytes: u32,
    pub(crate) echo_us: u32,
}

/// Bounded records carried by the authenticated, reliable control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    /// Request a test between these two peers.
    Start(Start),
    /// Negotiated maximum datagram size and per-direction budget.
    Accepted {
        /// Test identifier.
        id: u64,
        /// Per-direction budget in IPv4 bytes.
        byte_limit: u32,
        /// Size of every probe datagram.
        mtu: u16,
    },
    /// The responder already has an active test.
    Busy {
        /// Test identifier.
        id: u64,
    },
    /// Receiver has installed its data sink before the sender begins.
    Ready {
        /// Test identifier.
        id: u64,
        /// Direction about to start.
        direction: Direction,
    },
    /// Observed goodput and loss over a full interval of the receiver's clock.
    Feedback {
        /// Test identifier.
        id: u64,
        /// Direction being measured.
        direction: Direction,
        /// Receiver's observation.
        sample: Feedback,
    },
    /// The sender has stopped issuing probes and shares the result of its rate search.
    End {
        /// Test identifier.
        id: u64,
        /// Direction ending.
        direction: Direction,
        /// Number of IPv4 datagrams issued by the sender.
        packets: u32,
        /// Rate search result based on receiver feedback.
        reading: Reading,
    },
    /// Final delivery numbers after draining late probes.
    Report {
        /// Test identifier.
        id: u64,
        /// Direction completed.
        direction: Direction,
        /// Agreed result for this direction.
        reading: Reading,
    },
    /// End the exchange early in either direction.
    Cancel {
        /// Test identifier.
        id: u64,
    },
}

pub(crate) const MAX_BPS: u64 = 8_000_000_000;
const MAX_RECORD: usize = 64;

impl Control {
    /// Identifier used to bind the record to an already authenticated peer and session.
    pub fn id(&self) -> u64 {
        match *self {
            Self::Start(start) => start.id,
            Self::Accepted { id, .. }
            | Self::Busy { id }
            | Self::Ready { id, .. }
            | Self::Feedback { id, .. }
            | Self::End { id, .. }
            | Self::Report { id, .. }
            | Self::Cancel { id } => id,
        }
    }

    /// Encode a control record into its compact version-one representation.
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    /// Parse exactly one version-one record. Trailing bytes and values outside the protocol limits are rejected.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_RECORD {
            return None;
        }
        let (control, rest) = postcard::take_from_bytes::<Self>(bytes).ok()?;
        (rest.is_empty() && control.valid()).then_some(control)
    }

    pub(crate) fn valid(self) -> bool {
        match self {
            Self::Start(Start {
                byte_limit, mtu, ..
            })
            | Self::Accepted {
                byte_limit, mtu, ..
            } => (1..=NORMAL_BYTES).contains(&byte_limit) && (MIN_MTU..=MAX_MTU).contains(&mtu),
            Self::Feedback { sample, .. } => {
                sample.bps <= MAX_BPS
                    && sample.lost_per_mille <= 1000
                    && sample.bytes <= NORMAL_BYTES
                    && sample.echo_us <= 5_000_000
            }
            Self::End {
                packets, reading, ..
            } => packets <= NORMAL_BYTES / u32::from(MIN_MTU) && valid_result(reading),
            Self::Report { reading, .. } => valid_result(reading),
            Self::Busy { .. } | Self::Ready { .. } | Self::Cancel { .. } => true,
        }
    }
}

fn valid_result(reading: Reading) -> bool {
    reading.bytes <= NORMAL_BYTES
        && match reading.quality {
            Quality::Insufficient => reading.bps.is_none(),
            Quality::Measured | Quality::AtLeast => {
                reading.bytes > 0 && reading.bps.is_some_and(|v| (1..=MAX_BPS).contains(&v))
            }
            Quality::Measuring => false,
        }
}

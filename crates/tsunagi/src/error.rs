//! Error types for the whole library.
//!
//! The library never panics on untrusted network input: every decoding and
//! validation failure is represented as a [`ProtocolError`] and surfaced as a
//! rejected message or session, never as a process abort.

use std::path::PathBuf;

use crate::identity::NetworkId;

/// Convenient result alias used across the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top level error type of the library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The supplied network name does not satisfy the documented rules.
    #[error("invalid network name: {0}")]
    InvalidNetworkName(&'static str),

    /// The supplied network secret does not satisfy the documented rules.
    ///
    /// The secret itself is never included in the message.
    #[error("invalid network secret: {0}")]
    InvalidNetworkSecret(&'static str),

    /// A textual identifier could not be parsed.
    #[error("invalid {kind}: {reason}")]
    InvalidEncoding {
        /// What was being parsed, e.g. `network id`.
        kind: &'static str,
        /// Why parsing failed.
        reason: &'static str,
    },

    /// The mandatory state directory is already owned by another live agent.
    ///
    /// This is an ownership lock, not a "file exists" check.
    #[error("state directory {path} is owned by another running agent instance")]
    StateLocked {
        /// Directory that could not be locked.
        path: PathBuf,
    },

    /// The mandatory state store is unusable. It is never silently recreated.
    #[error("mandatory state store at {path} is unusable and was NOT reset: {reason}")]
    StateCorrupted {
        /// Path of the unusable store.
        path: PathBuf,
        /// Human readable reason, free of secrets.
        reason: String,
    },

    /// The mandatory state store has a schema this build cannot handle.
    #[error(
        "state store schema version {found} is not supported by this build (supported: {supported})"
    )]
    UnsupportedSchema {
        /// Version found on disk.
        found: i64,
        /// Version this build writes.
        supported: i64,
    },

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// A filesystem operation failed.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path involved in the failure.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Binding or driving the iroh endpoint failed.
    #[error("iroh endpoint error: {0}")]
    Endpoint(String),

    /// A control protocol violation.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The requested network is not currently active on this agent.
    #[error("network {0} is not active")]
    NetworkNotActive(NetworkId),

    /// The requested network is already active on this agent.
    #[error("network {0} is already active")]
    NetworkAlreadyActive(NetworkId),

    /// The requested network is not configured in the state store.
    #[error("network {0} is not configured")]
    NetworkUnknown(NetworkId),

    /// No session with that peer exists in the given network.
    #[error("no authenticated session with peer {peer} in network {network}")]
    NoSuchPeer {
        /// Network the lookup was scoped to.
        network: NetworkId,
        /// Peer that was looked up, short form.
        peer: String,
    },

    /// The agent is shutting down or already stopped.
    #[error("agent is stopped")]
    Stopped,

    /// Something that had to answer in bounded time did not.
    ///
    /// Reported instead of waited out: an agent that has wedged must not
    /// leave a command hanging with nothing on screen and no way out.
    #[error("{what} did not answer in time")]
    Timeout {
        /// What was asked, phrased so the message stands on its own.
        what: String,
    },

    /// Discovery backend failure. Never fatal for the agent.
    #[error("discovery error: {0}")]
    Discovery(String),
}

/// Errors produced while speaking the control protocol.
///
/// These always result in rejecting a single message or a single session. They
/// never stop other networks, other peers, or the agent itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The peer announced an unsupported control protocol version.
    #[error("unsupported control protocol version {found} (this build speaks {supported})")]
    UnsupportedVersion {
        /// Version announced by the peer.
        found: u16,
        /// Version this build speaks.
        supported: u16,
    },

    /// A frame header announced more bytes than the configured limit allows.
    ///
    /// Checked *before* any buffer of that size is allocated.
    #[error("frame of {announced} bytes exceeds the {limit} byte limit")]
    FrameTooLarge {
        /// Length announced in the frame header.
        announced: u64,
        /// Configured limit.
        limit: usize,
    },

    /// A frame could not be decoded.
    #[error("malformed frame: {0}")]
    Malformed(&'static str),

    /// The stream ended before a complete frame was read.
    #[error("stream closed while reading a frame")]
    StreamClosed,

    /// An underlying stream read or write failed.
    #[error("stream error: {0}")]
    Stream(String),

    /// The peer failed to prove knowledge of the derived network secret.
    #[error("network authentication failed")]
    AuthenticationFailed,

    /// The peer asked for a network this agent does not have active.
    #[error("peer requested an unknown or inactive network")]
    UnknownNetwork,

    /// A message carried a network id different from the session's network.
    #[error("message network id does not match the authenticated session network")]
    NetworkMismatch,

    /// A regular control message arrived before the handshake completed.
    #[error("control message received before authentication completed")]
    NotAuthenticated,

    /// A handshake step did not complete within the configured timeout.
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// A field exceeded its configured bound.
    #[error("field `{field}` exceeds its limit ({len} > {limit})")]
    FieldTooLarge {
        /// Name of the offending field.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Configured limit.
        limit: usize,
    },

    /// The connection is not usable for deriving channel binding material.
    #[error("connection does not provide TLS exporter material: {0}")]
    NoChannelBinding(String),
}

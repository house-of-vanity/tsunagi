//! Tsunagi: a proof-of-concept agent for small private mesh networks.
//!
//! See `README.md` for the exact scope of this proof of concept, and
//! `docs/architecture.md` / `docs/protocol.md` for the design.
//!
//! # Shape of the library
//!
//! * [`identity`] — persistent device identity and deterministic network space
//!   identity.
//! * [`storage`] — mandatory state (`state.sqlite`) and separately disposable
//!   cache (`cache.sqlite`).
//! * [`discovery`] — pluggable sources of *candidate* addresses. Candidates are
//!   never trusted peers.
//! * [`proto`] — the control protocol: framing, messages, handshake.
//! * [`net`] — the iroh connectivity adapter and its observability surface.
//! * [`agent`] — the runtime: agent lifecycle, per-network runtimes, reconnect.
//! * [`dataplane`] — the contract IP plugins satisfy, the packet transport,
//!   and the WireGuard data plane.
//! * [`state`] — signed records that outlive a session, and the rules for
//!   merging them between replicas.
//! * [`ipc`] — the local control interface a command line tool talks to. An
//!   adapter over the public API; the core does not know it exists.
//!
//! # What this library deliberately does not do
//!
//! It never starts a global tokio runtime, never installs a global tracing
//! subscriber, never handles process signals, never forks and never calls
//! `process::exit`. Several independent agents can run in one process.
//!
//! Only control messages travel over iroh. User IP traffic is not tunnelled
//! through it.

#![deny(rustdoc::broken_intra_doc_links)]

/// A boxed future, used where a trait must stay object safe.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub mod agent;
pub mod config;
pub mod dataplane;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod ipc;
pub mod net;
pub mod proto;
pub mod state;
pub mod storage;

pub use agent::{Agent, AgentStatus, Event, NetworkStatus, PeerStatus};
pub use config::{AgentConfig, Limits, ReconnectPolicy, StoragePaths, TransportPolicy};
pub use error::{Error, ProtocolError, Result};
pub use identity::{
    DeviceIdentity, DiscoveryKey, NetworkDescriptor, NetworkId, NetworkName, NetworkSecret,
};

/// Re-exported iroh types that appear in this crate's public API.
pub mod iroh_types {
    pub use iroh::{EndpointAddr, EndpointId, RelayUrl};
}

#[doc(hidden)]
pub mod test_support {
    //! Internals exposed for this crate's own negative tests.
    //!
    //! **Not part of the stable API.** It exists so the integration tests can
    //! hand-craft handshakes — a valid proof to replay on another connection, a
    //! message sent before authentication, an oversized frame — which is the
    //! only way to test those rejections against a real agent.

    use iroh::endpoint::Connection;

    use crate::error::ProtocolError;
    use crate::identity::NetworkKeys;
    use crate::proto::handshake;

    /// Exposes the derived handshake authentication key.
    pub fn auth_key(keys: &NetworkKeys) -> [u8; 32] {
        *keys.auth_key()
    }

    /// Derives this connection's channel binding material.
    pub fn channel_binding(
        conn: &Connection,
        network_id: &[u8; 32],
    ) -> Result<[u8; 32], ProtocolError> {
        handshake::channel_binding_for_test(conn, network_id)
    }

    /// Computes a handshake proof for the given role.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_proof(
        auth_key: &[u8; 32],
        role: &str,
        version: u16,
        network_id: &[u8; 32],
        initiator: &[u8; 32],
        responder: &[u8; 32],
        channel_binding: &[u8],
        nonce_initiator: &[u8; 16],
        nonce_responder: &[u8; 16],
    ) -> [u8; 32] {
        handshake::proof_for_test(
            auth_key,
            role,
            version,
            network_id,
            initiator,
            responder,
            channel_binding,
            nonce_initiator,
            nonce_responder,
        )
    }
}

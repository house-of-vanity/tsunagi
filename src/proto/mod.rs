//! The control protocol: framing, messages and the network membership
//! handshake.
//!
//! Only control messages travel over iroh. User IP traffic is never tunnelled
//! through this protocol.
//!
//! Layering, outermost first:
//!
//! 1. iroh/QUIC connection with ALPN [`message::ALPN`] — endpoint
//!    authentication, confidentiality and integrity.
//! 2. One bidirectional stream per session, carrying length-prefixed frames
//!    ([`frame`]).
//! 3. The [`handshake`], which must complete before anything else is accepted.
//! 4. [`message::Envelope`]s carrying [`message::ControlMessage`]s, each
//!    re-checked against the session's network id.
//!
//! Nothing here adds its own encryption on top of iroh.
//!
//! # The data plane speaks a different protocol
//!
//! IP plugin packets never travel on a control connection. They use their own
//! ALPN, [`message::DATA_ALPN`], with the same membership handshake followed by
//! [`message::DataOpen`]. Keeping them apart is what lets the data plane's
//! transport be replaced without touching anything above.

pub mod frame;
pub mod handshake;
pub mod message;

pub use frame::{read_frame, write_frame};
pub use handshake::{HandshakeOutcome, Role};
pub use message::{
    ALPN, Announcement, AuthProof, ControlMessage, DATA_ALPN, DataOpen, DataOpenAck, Envelope,
    Hello, HelloAck, PROTOCOL_VERSION,
};

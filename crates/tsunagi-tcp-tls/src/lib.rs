//! TCP TLS 1.3 carrier for opaque, independently encrypted mesh datagrams.
pub mod candidates;
pub mod cert;
pub mod plugin;
pub mod transport;
pub use plugin::{
    TCP_TLS_PROTOCOL, TCP_TLS_VERSION, TcpCarrier, TcpTlsCarrier, TcpTlsConfig, local_ip_candidates,
};
pub use transport::TcpTlsTransport;

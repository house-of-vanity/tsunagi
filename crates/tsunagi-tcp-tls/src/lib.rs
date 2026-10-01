//! The `tcp-tls` protocol: TCP with TLS 1.3 on port 443 with Noise E2EE.

pub mod cert;
pub mod crypto;
pub mod plugin;
pub mod transport;

pub use plugin::{
    TCP_TLS_PROTOCOL, TCP_TLS_VERSION, TcpTlsCodec, TcpTlsConfig, TcpTlsPlugin, local_ip_candidates,
};
pub use transport::TcpTlsTransport;

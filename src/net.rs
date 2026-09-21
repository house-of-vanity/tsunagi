//! The iroh connectivity adapter and its observability surface.
//!
//! This module builds and owns the [`Endpoint`], and turns iroh's runtime
//! information into plain owned snapshots that the rest of the library and the
//! library's users can read.
//!
//! # Honest reporting
//!
//! Three different things are kept distinct and never conflated:
//!
//! * an **unverified candidate** — something discovery handed us
//!   ([`crate::discovery::Candidate`]);
//! * an **observed address** — an address this endpoint believes it has
//!   ([`EndpointSnapshot::observed_addrs`]);
//! * a **verified path** — a network path QUIC has actually validated and is
//!   using or can use ([`PathInfo`]).
//!
//! A value that is not available is reported as `None`. It is never invented.
//!
//! An iroh address is an address for *iroh*. It must not be assumed to be usable
//! by any other protocol; a future WireGuard plugin is expected to collect its
//! own reachability data.

use std::net::SocketAddr;
use std::time::Duration;

use iroh::endpoint::{
    Connection, ConnectionStats, PortmapperConfig, RecvStream, SendStream, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode};

use crate::config::{AgentConfig, TransportPolicy};
use crate::error::{Error, Result};
use crate::identity::DeviceIdentity;
use crate::proto::message::{ALPN, DATA_ALPN};

/// A network path address as reported by iroh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAddr {
    /// A direct IP path.
    Ip(SocketAddr),
    /// A path through a relay server.
    Relay(String),
    /// A custom transport iroh reported but this crate does not model.
    Other(String),
}

/// One verified network path of a connection.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Remote address of the path.
    pub remote: PathAddr,
    /// Local address of the path, when the OS reports one.
    pub local: Option<String>,
    /// Whether QUIC currently transmits application data over this path.
    pub is_selected: bool,
    /// Round-trip time estimate for this path.
    pub rtt: Duration,
}

impl PathInfo {
    /// Whether this is a direct IP path.
    pub fn is_direct(&self) -> bool {
        matches!(self.remote, PathAddr::Ip(_))
    }

    /// Whether this path goes through a relay.
    pub fn is_relay(&self) -> bool {
        matches!(self.remote, PathAddr::Relay(_))
    }
}

/// How a connection currently reaches its peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// A direct IP path is selected.
    Direct,
    /// A relay path is selected.
    Relay,
    /// iroh has not reported a selected path yet.
    Unknown,
}

/// Counters for one connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionCounters {
    /// UDP bytes sent on this connection.
    pub udp_tx_bytes: u64,
    /// UDP bytes received on this connection.
    pub udp_rx_bytes: u64,
    /// UDP datagrams sent.
    pub udp_tx_datagrams: u64,
    /// UDP datagrams received.
    pub udp_rx_datagrams: u64,
    /// Packets declared lost.
    pub lost_packets: u64,
}

impl From<ConnectionStats> for ConnectionCounters {
    fn from(stats: ConnectionStats) -> Self {
        Self {
            udp_tx_bytes: stats.udp_tx.bytes,
            udp_rx_bytes: stats.udp_rx.bytes,
            udp_tx_datagrams: stats.udp_tx.datagrams,
            udp_rx_datagrams: stats.udp_rx.datagrams,
            lost_packets: stats.lost_packets,
        }
    }
}

/// An owned snapshot of one live connection.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    /// Authenticated endpoint id of the remote side.
    pub remote_id: EndpointId,
    /// Verified paths, as reported by iroh at snapshot time.
    pub paths: Vec<PathInfo>,
    /// How the connection currently reaches the peer.
    pub transport: TransportKind,
    /// RTT of the selected path, when there is one.
    pub rtt: Option<Duration>,
    /// Per-connection counters.
    pub counters: ConnectionCounters,
}

/// Snapshot of this endpoint, independent of any particular network.
#[derive(Debug, Clone)]
pub struct EndpointSnapshot {
    /// This endpoint's id.
    pub endpoint_id: EndpointId,
    /// Sockets actually bound locally.
    pub bound_sockets: Vec<SocketAddr>,
    /// Addresses iroh believes this endpoint is reachable at.
    ///
    /// These are *observed*, not verified by any remote peer.
    pub observed_addrs: Vec<PathAddr>,
    /// Relay URLs this endpoint currently considers usable, if any.
    pub relay_urls: Vec<String>,
}

fn path_addr(addr: &iroh::TransportAddr) -> PathAddr {
    match addr {
        iroh::TransportAddr::Ip(socket) => PathAddr::Ip(*socket),
        iroh::TransportAddr::Relay(url) => PathAddr::Relay(url.to_string()),
        other => PathAddr::Other(format!("{other:?}")),
    }
}

/// Builds an owned snapshot of a live connection.
pub fn snapshot_connection(conn: &Connection) -> ConnectionSnapshot {
    let mut paths = Vec::new();
    let mut transport = TransportKind::Unknown;
    let mut rtt = None;

    for path in conn.paths().iter() {
        let info = PathInfo {
            remote: path_addr(path.remote_addr()),
            local: local_addr_string(path.local_addr()),
            is_selected: path.is_selected(),
            rtt: path.rtt(),
        };
        if info.is_selected {
            transport = if info.is_relay() {
                TransportKind::Relay
            } else if info.is_direct() {
                TransportKind::Direct
            } else {
                TransportKind::Unknown
            };
            rtt = Some(info.rtt);
        }
        paths.push(info);
    }

    ConnectionSnapshot {
        remote_id: conn.remote_id(),
        paths,
        transport,
        rtt,
        counters: conn.stats().into(),
    }
}

fn local_addr_string(addr: &iroh::endpoint::LocalTransportAddr) -> Option<String> {
    match addr {
        iroh::endpoint::LocalTransportAddr::Ip(Some(ip)) => Some(ip.to_string()),
        iroh::endpoint::LocalTransportAddr::Ip(None) => None,
        iroh::endpoint::LocalTransportAddr::Relay(url) => Some(url.to_string()),
        iroh::endpoint::LocalTransportAddr::Custom(Some(custom)) => Some(format!("{custom:?}")),
        iroh::endpoint::LocalTransportAddr::Custom(None) => None,
        _ => None,
    }
}

/// Thin wrapper around the iroh endpoint.
///
/// The endpoint serves two ALPNs: the control protocol and the data plane.
/// They are separate connections with separate congestion control, so a busy
/// or broken data plane cannot disturb control traffic.
#[derive(Debug, Clone)]
pub struct EndpointAdapter {
    endpoint: Endpoint,
}

impl EndpointAdapter {
    /// Binds an endpoint according to `config`, reusing the persistent device key.
    pub async fn bind(config: &AgentConfig, identity: &DeviceIdentity) -> Result<Self> {
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(identity.secret_key())
            .alpns(vec![ALPN.to_vec(), DATA_ALPN.to_vec()]);

        builder = match config.transport {
            TransportPolicy::LocalOnly => builder
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .portmapper_config(PortmapperConfig::Disabled)
                .net_report_config(iroh::NetReportConfig::minimal()),
            TransportPolicy::DirectOnly => builder.preset(presets::N0DisableRelay),
            TransportPolicy::N0Defaults => builder.preset(presets::N0),
        };

        if !config.bind_addrs.is_empty() {
            builder = builder.clear_ip_transports();
            for addr in &config.bind_addrs {
                builder = builder
                    .bind_addr(*addr)
                    .map_err(|err| Error::Endpoint(format!("invalid bind address: {err}")))?;
            }
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|err| Error::Endpoint(format!("cannot bind endpoint: {err}")))?;

        Ok(Self { endpoint })
    }

    /// The underlying iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This endpoint's id.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// This endpoint's dialable address, as currently known.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Builds an address containing only the locally bound sockets.
    ///
    /// Useful when address lookup and relays are disabled and peers must be
    /// given literal addresses.
    pub fn loopback_addr(&self) -> EndpointAddr {
        self.endpoint
            .bound_sockets()
            .into_iter()
            .fold(EndpointAddr::new(self.endpoint.id()), |addr, socket| {
                addr.with_ip_addr(socket)
            })
    }

    /// Snapshot of endpoint-level information.
    pub fn snapshot(&self) -> EndpointSnapshot {
        let addr = self.endpoint.addr();
        let mut observed = Vec::new();
        let mut relays = Vec::new();
        for socket in addr.ip_addrs() {
            observed.push(PathAddr::Ip(*socket));
        }
        for url in addr.relay_urls() {
            relays.push(url.to_string());
            observed.push(PathAddr::Relay(url.to_string()));
        }
        EndpointSnapshot {
            endpoint_id: self.endpoint.id(),
            bound_sockets: self.endpoint.bound_sockets(),
            observed_addrs: observed,
            relay_urls: relays,
        }
    }

    /// Dials a candidate and opens the control stream.
    pub async fn connect(
        &self,
        addr: EndpointAddr,
    ) -> Result<(Connection, SendStream, RecvStream), Error> {
        let conn = self
            .endpoint
            .connect(addr, ALPN)
            .await
            .map_err(|err| Error::Endpoint(format!("connect failed: {err}")))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|err| Error::Endpoint(format!("cannot open control stream: {err}")))?;
        Ok((conn, send, recv))
    }

    /// Closes the endpoint and waits for it to finish.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

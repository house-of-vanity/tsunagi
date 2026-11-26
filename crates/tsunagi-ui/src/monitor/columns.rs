//! Fields shared by the table, its column chooser and the history ordering.
use super::{Names, endpoints, role_name};
use rusqlite::types::Value;
use std::net::Ipv4Addr;
use tsunagi::traffic::{Flow, FlowKey, IpDetail};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Column {
    Peer,
    Network,
    Near,
    Far,
    Protocol,
    Role,
    Sent,
    Received,
    SendRate,
    ReceiveRate,
    SentPackets,
    ReceivedPackets,
    Seen,
    PeerId,
}

impl Column {
    pub fn title(self) -> &'static str {
        match self {
            Self::Peer => "Peer",
            Self::Network => "Network",
            Self::Near => "Endpoint A",
            Self::Far => "Endpoint B",
            Self::Protocol => "Protocol",
            Self::Role => "Role",
            Self::Sent => "Sent",
            Self::Received => "Received",
            Self::SendRate => "TX rate",
            Self::ReceiveRate => "RX rate",
            Self::SentPackets => "TX packets",
            Self::ReceivedPackets => "RX packets",
            Self::Seen => "Last seen",
            Self::PeerId => "Peer ID",
        }
    }
    pub fn hint(self) -> &'static str {
        match self {
            Self::Peer => "Authenticated peer",
            Self::Network => "Tsunagi network",
            Self::Near => "Agent-side endpoint, or the first endpoint of an encrypted relay",
            Self::Far => "Peer-side endpoint, or the second endpoint of an encrypted relay",
            Self::Protocol => "IP protocol or transport session",
            Self::Role => "How this agent handles the traffic",
            Self::Sent => "Total bytes sent from A to B",
            Self::Received => "Total bytes received from B to A",
            Self::SendRate => "Bytes per second from A to B",
            Self::ReceiveRate => "Bytes per second from B to A",
            Self::SentPackets => "Packets sent from A to B",
            Self::ReceivedPackets => "Packets received from B to A",
            Self::Seen => "Time since the last observation",
            Self::PeerId => "Public peer ID. Select a value to copy it.",
        }
    }
    pub fn descending_first(self) -> bool {
        matches!(
            self,
            Self::Sent
                | Self::Received
                | Self::SendRate
                | Self::ReceiveRate
                | Self::SentPackets
                | Self::ReceivedPackets
                | Self::Seen
        )
    }
    pub fn sql(self) -> &'static str {
        match self {
            Self::Sent => "tx",
            Self::Received => "rx",
            Self::SendRate => "tx_rate",
            Self::ReceiveRate => "rx_rate",
            Self::SentPackets => "ntx",
            Self::ReceivedPackets => "nrx",
            Self::Seen => "last",
            Self::PeerId => "peer",
            _ => "flow_label(key)",
        }
    }
    pub fn uses_names(self) -> bool {
        matches!(self, Self::Peer | Self::Network | Self::Near | Self::Far)
    }
    pub fn ip_endpoint(self, key: &FlowKey) -> Option<(Ipv4Addr, Option<u16>)> {
        let Flow::Ip {
            near, far, detail, ..
        } = key.flow
        else {
            return None;
        };
        let ip = match self {
            Self::Near => near,
            Self::Far => far,
            _ => return None,
        };
        let port = match detail {
            IpDetail::Ports(a, b) => Some(if self == Self::Near { a } else { b }),
            _ => None,
        };
        Some((ip.into(), port))
    }
    // SQLite indexes this value only while sorting by a descriptive column.
    // Numeric IPv4 address and port order is independent of their spelling.
    pub fn label_key(self, key: &FlowKey, names: &Names) -> Value {
        if let Some((ip, port)) = self.ip_endpoint(key) {
            let port = port.map_or(0, |p| i64::from(p) + 1);
            return Value::Integer((i64::from(u32::from(ip)) << 17) + port);
        }
        let label = match self {
            Self::Peer => names.peer(&key.network, &key.peer),
            Self::Network => names.network(&key.network),
            Self::Near => endpoints(key, names).0,
            Self::Far => endpoints(key, names).1,
            Self::Protocol => endpoints(key, names).2,
            Self::Role => role_name(key.role).into(),
            _ => return Value::Null,
        };
        Value::Text(label.to_lowercase())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Sort {
    pub column: Column,
    pub descending: bool,
}
impl Default for Sort {
    fn default() -> Self {
        Self {
            column: Column::Seen,
            descending: true,
        }
    }
}
impl Sort {
    pub fn select(&mut self, column: Column) {
        self.descending = if self.column == column {
            !self.descending
        } else {
            column.descending_first()
        };
        self.column = column;
    }
}

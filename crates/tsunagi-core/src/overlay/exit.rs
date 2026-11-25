//! Exit-node host rules: what makes this device an exit node for others, and
//! what sends this device's own traffic through one.
//!
//! The packet side lives in [`super::router`]; this is the side the operating
//! system sees. It is kept apart from the broadcast rules, which have a
//! different lifetime and different tags.

/// Plaintext IP bytes carried through the client's currently selected internet exit.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExitTraffic {
    /// Bytes accepted by the carrier for off-mesh destinations.
    pub tx_bytes: u64,
    /// Internet reply bytes delivered to the local interface.
    pub rx_bytes: u64,
}

/// How one set of host rules went.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSetReport {
    /// Whether every step took.
    pub ok: bool,
    /// One line: what is in place, or what is missing and why.
    pub detail: String,
}

/// What the host rules of one network's exit-node settings are doing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitRulesReport {
    /// Masquerading and forwarding for members' traffic, when this agent
    /// offers itself as an exit node here. `None` means none are wanted.
    pub offer: Option<RuleSetReport>,
    /// Whether the kernel forwards packets for the overlay interface.
    ///
    /// `Some(false)` means kernel forwarding is off. `None` when unavailable
    /// or when the exit forwards through physical sockets.
    pub forwarding: Option<bool>,
    /// The routes that send this device's traffic through its exit node.
    /// `None` means it uses none through this network.
    pub client: Option<RuleSetReport>,
}

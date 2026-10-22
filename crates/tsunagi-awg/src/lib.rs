//! Amnezia-masked UDP carrier using the independent per-neighbour WireGuard engine.
pub use tsunagi_wireguard::{
    AWG_PROTOCOL, AWG_WIRE_VERSION, PairOverview, UdpCarrier as AwgPlugin,
    UdpTransport as AwgTransport, profile,
};

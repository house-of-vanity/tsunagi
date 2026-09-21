//! The WireGuard data plane plugin.
//!
//! WireGuard is the first IP plugin. It creates real IP connectivity between
//! participants, while the control plane keeps doing what it does: agreeing on
//! who is in the network and carrying each participant's opaque announcement.
//!
//! The two planes stay separate:
//!
//! * **No user IP traffic goes through iroh.** iroh carries this plugin's
//!   announcements and nothing else; the packets themselves travel over
//!   WireGuard's own UDP sockets.
//! * **An iroh address is not a WireGuard address.** The plugin gathers its
//!   own reachability and advertises that.
//! * **The core never parses these announcements.** It moves a bounded opaque
//!   blob; only [`announcement`] interprets it.
//! * **Keys are separate.** The plugin has its own key per network, in its own
//!   store, unrelated to the iroh device key and to the network secret.
//!
//! # How a mesh forms
//!
//! Every participant derives its own overlay address from the network id and
//! its own WireGuard public key ([`overlay`]), so no coordinator hands out
//! addresses. Because that derivation is public, each agent computes every
//! peer's `AllowedIPs` itself instead of believing what the peer claims — a
//! member cannot route another member's traffic to itself.
//!
//! Each agent then builds its own local configuration with one peer entry per
//! other participant ([`config`]) and hands it to a [`backend`]. The
//! [`backend::RecordingBackend`] applies it in memory, which is what the test
//! suite uses; [`wgtool::WgToolBackend`] drives the real `wg` and `ip` tools
//! and needs Linux with `CAP_NET_ADMIN`.
//!
//! See `docs/wireguard.md` for the full picture.

pub mod announcement;
pub mod backend;
pub mod config;
pub mod keys;
pub mod overlay;
pub mod plugin;
pub mod store;
pub mod wgtool;

pub use announcement::{ValidatedAnnouncement, WgAnnouncement};
pub use backend::{BackendCall, RecordingBackend, WireguardBackend};
pub use config::{
    Cidr, InterfaceConfig, InterfaceParams, InterfaceState, PeerConfig, PeerState, PortPolicy,
    build_interface, interface_name,
};
pub use keys::{WgPublicKey, WgSecretKey};
pub use overlay::{overlay_address, overlay_prefix};
pub use plugin::{
    AdvertisePolicy, NetworkOverview, PeerOverview, WIREGUARD_PROTOCOL, WireguardConfig,
    WireguardPlugin,
};
pub use store::WgKeyStore;
pub use wgtool::{WgToolBackend, plan_apply, plan_remove};

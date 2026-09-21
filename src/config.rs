//! Library configuration.
//!
//! Everything the agent needs is passed in explicitly. The library reads no
//! environment variables, installs no global state and picks no default
//! directories behind the caller's back — [`StoragePaths::user_default`] exists
//! but must be called on purpose.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::dataplane::SharedPlugin;
use crate::discovery::NetworkDiscovery;
use crate::error::{Error, Result};

/// Qualifier/organisation/application triple used for platform directories.
const APP_NAME: &str = "tsunagi";

/// Where the two stores live.
///
/// The mandatory state and the disposable cache are separate both logically and
/// physically, so that the cache can be deleted at any time without touching
/// identity or network configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePaths {
    /// Directory holding `state.sqlite` and the ownership lock.
    pub state_dir: PathBuf,
    /// Directory holding `cache.sqlite`.
    pub cache_dir: PathBuf,
}

impl StoragePaths {
    /// Uses explicit directories. Tests always use temporary directories.
    pub fn new(state_dir: impl Into<PathBuf>, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            cache_dir: cache_dir.into(),
        }
    }

    /// Puts both stores under one root, in `state/` and `cache/` subdirectories.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
        }
    }

    /// The per-user platform directories.
    ///
    /// A future system service can supply its own paths instead.
    pub fn user_default() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("", "", APP_NAME).ok_or_else(|| {
            Error::Storage("no valid home directory for platform config paths".into())
        })?;
        Ok(Self {
            state_dir: dirs.data_dir().to_path_buf(),
            cache_dir: dirs.cache_dir().to_path_buf(),
        })
    }

    /// Path of the mandatory state database.
    pub fn state_db(&self) -> PathBuf {
        self.state_dir.join("state.sqlite")
    }

    /// Path of the disposable cache database.
    pub fn cache_db(&self) -> PathBuf {
        self.cache_dir.join("cache.sqlite")
    }

    /// Path of the ownership lock file.
    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("state.lock")
    }
}

/// How the iroh endpoint is allowed to reach the outside world.
///
/// The default is [`TransportPolicy::LocalOnly`] so that a plain
/// `AgentConfig::new(...)` never reaches the internet by accident. Callers that
/// want public connectivity must opt in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportPolicy {
    /// No relays, no address lookup service, no port mapping.
    ///
    /// Suitable for tests and for fully local deployments.
    #[default]
    LocalOnly,
    /// Public address lookup, but no relays.
    ///
    /// Enables iroh's DNS/pkarr address lookup against the public service run
    /// by Number 0 (the company behind iroh) at `dns.iroh.link`. This endpoint
    /// publishes a signed record of its own addresses there, so peers can dial
    /// it by endpoint id alone.
    DirectOnly,
    /// iroh's standard behaviour: public address lookup plus public relays.
    ///
    /// Maps to iroh's own `presets::N0`. As well as the address lookup above,
    /// it uses Number 0's public relay servers as a fallback when a direct
    /// path cannot be hole punched. They are fine for development and carry no
    /// availability guarantee.
    N0Defaults,
}

/// Bounds applied to everything that comes off the network.
///
/// Each of these is enforced before memory is allocated for the corresponding
/// object where that is possible (notably [`Limits::max_frame_len`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted control frame payload, in bytes.
    pub max_frame_len: usize,
    /// Largest accepted hostname, in bytes.
    pub max_hostname_len: usize,
    /// Largest number of plugin capabilities in one announcement.
    pub max_capabilities: usize,
    /// Largest opaque plugin payload, in bytes.
    pub max_capability_data_len: usize,
    /// Largest accepted echo payload in a ping/pong exchange, in bytes.
    pub max_echo_payload_len: usize,
    /// Largest accepted free-text reason string, in bytes.
    pub max_reason_len: usize,
    /// Deadline for the whole handshake.
    pub handshake_timeout: Duration,
    /// Deadline for one outbound dial attempt.
    pub dial_timeout: Duration,
    /// Deadline for writing one control frame.
    ///
    /// Liveness of an established session is delegated to QUIC: iroh configures
    /// keep-alives and an idle timeout, so a dead peer surfaces as a read error
    /// rather than needing a protocol-level heartbeat here.
    pub write_timeout: Duration,
    /// Maximum simultaneous outbound dials per network.
    pub max_concurrent_dials: usize,
    /// Maximum simultaneous authenticated sessions per network.
    pub max_sessions_per_network: usize,
    /// Maximum simultaneous inbound connections being handshaken.
    pub max_inbound_handshakes: usize,
    /// Capacity of a session's outbound queue, providing backpressure.
    pub session_send_queue: usize,
    /// Capacity of the event broadcast channel.
    pub event_buffer: usize,
    /// Maximum address hints kept per peer in the cache.
    pub max_hints_per_peer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_len: 64 * 1024,
            max_hostname_len: 255,
            max_capabilities: 16,
            max_capability_data_len: 4 * 1024,
            max_echo_payload_len: 4 * 1024,
            max_reason_len: 256,
            handshake_timeout: Duration::from_secs(10),
            dial_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(30),
            max_concurrent_dials: 8,
            max_sessions_per_network: 64,
            max_inbound_handshakes: 32,
            session_send_queue: 64,
            event_buffer: 512,
            max_hints_per_peer: 8,
        }
    }
}

/// Bounded exponential backoff with jitter for reconnect attempts.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconnectPolicy {
    /// Delay before the first retry.
    pub initial_delay: Duration,
    /// Upper bound on the delay.
    pub max_delay: Duration,
    /// Multiplier applied after each failed attempt.
    pub factor: f64,
    /// Fraction of the delay applied as random jitter, in `0.0..=1.0`.
    pub jitter: f64,
    /// Give up on a peer after this many consecutive failures until it is seen
    /// again by discovery. `None` means never give up while the network is up.
    pub max_consecutive_failures: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            factor: 2.0,
            jitter: 0.3,
            max_consecutive_failures: None,
        }
    }
}

impl ReconnectPolicy {
    /// Delay to wait before retry number `attempt` (1-based), with jitter.
    pub(crate) fn delay_for(&self, attempt: u32) -> Duration {
        let exp = self.factor.powi(attempt.saturating_sub(1).min(32) as i32);
        let base = self.initial_delay.as_secs_f64() * exp;
        let capped = base.min(self.max_delay.as_secs_f64());
        let jitter = self.jitter.clamp(0.0, 1.0);
        let factor = 1.0 - jitter + jitter * 2.0 * rand::random::<f64>();
        Duration::from_secs_f64((capped * factor).max(0.0))
    }
}

/// Everything needed to start an [`crate::Agent`].
#[derive(Clone)]
pub struct AgentConfig {
    /// Where the mandatory state and the disposable cache live.
    pub paths: StoragePaths,
    /// Explicit local bind addresses. Empty means iroh's defaults.
    ///
    /// Tests bind to `127.0.0.1:0` so each agent gets a dynamic port.
    pub bind_addrs: Vec<SocketAddr>,
    /// How much external connectivity machinery the endpoint may use.
    pub transport: TransportPolicy,
    /// Hostname announced to peers. `None` keeps whatever the state store holds,
    /// falling back to the OS hostname and finally to a short endpoint id.
    pub hostname: Option<String>,
    /// Discovery backend. `None` disables discovery-driven dialling; static
    /// bootstrap candidates still work.
    pub discovery: Option<Arc<dyn NetworkDiscovery>>,
    /// How often each active network re-runs discovery and re-evaluates dials.
    pub discovery_interval: Duration,
    /// Bounds applied to network input.
    pub limits: Limits,
    /// Reconnect backoff policy.
    pub reconnect: ReconnectPolicy,
    /// IP plugins whose capabilities are announced and dispatched.
    pub plugins: Vec<SharedPlugin>,
}

impl AgentConfig {
    /// Creates a configuration with local-only transport and default limits.
    pub fn new(paths: StoragePaths) -> Self {
        Self {
            paths,
            bind_addrs: Vec::new(),
            transport: TransportPolicy::default(),
            hostname: None,
            discovery: None,
            discovery_interval: Duration::from_secs(5),
            limits: Limits::default(),
            reconnect: ReconnectPolicy::default(),
            plugins: Vec::new(),
        }
    }

    /// Binds to loopback with a dynamic port. Used by the test suite.
    pub fn with_loopback_bind(mut self) -> Self {
        self.bind_addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
        ];
        self
    }

    /// Sets an explicit list of bind addresses.
    pub fn with_bind_addrs(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.bind_addrs = addrs.into_iter().collect();
        self
    }

    /// Sets the transport policy.
    pub fn with_transport(mut self, transport: TransportPolicy) -> Self {
        self.transport = transport;
        self
    }

    /// Sets the discovery backend.
    pub fn with_discovery(mut self, discovery: Arc<dyn NetworkDiscovery>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Sets how often discovery runs.
    pub fn with_discovery_interval(mut self, interval: Duration) -> Self {
        self.discovery_interval = interval;
        self
    }

    /// Sets the announced hostname.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Registers an IP plugin.
    pub fn with_plugin(mut self, plugin: SharedPlugin) -> Self {
        self.plugins.push(plugin);
        self
    }

    /// Replaces the limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the reconnect policy.
    pub fn with_reconnect(mut self, reconnect: ReconnectPolicy) -> Self {
        self.reconnect = reconnect;
        self
    }
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("paths", &self.paths)
            .field("bind_addrs", &self.bind_addrs)
            .field("transport", &self.transport)
            .field("hostname", &self.hostname)
            .field("discovery", &self.discovery.as_ref().map(|d| d.name()))
            .field("discovery_interval", &self.discovery_interval)
            .field("limits", &self.limits)
            .field("reconnect", &self.reconnect)
            .field(
                "plugins",
                &self
                    .plugins
                    .iter()
                    .map(|p| p.protocol_id().to_string())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

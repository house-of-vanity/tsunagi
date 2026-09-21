//! The `tsunagi` command line agent.
//!
//! This binary owns everything the library deliberately refuses to do: it
//! starts the tokio runtime, installs a logging subscriber and handles
//! Ctrl-C. The library itself does none of that.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tsunagi::agent::Event;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::dataplane::IpPlugin;
use tsunagi::discovery::{CompositeDiscovery, NetworkDiscovery, StaticBootstrap};
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::iroh_types::EndpointAddr;
use tsunagi::overlay::{MemoryTunFactory, TunFactory};
use tsunagi::state::Ipv4Range;
use tsunagi::{Agent, NetworkId};
use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};

/// A small agent for private mesh networks.
#[derive(Debug, Parser)]
#[command(name = "tsunagi", version, about, long_about = None)]
struct Cli {
    /// Log filter, for example `info` or `tsunagi=debug`.
    #[arg(long, global = true, env = "TSUNAGI_LOG", default_value = "warn")]
    log: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Shows this device's identity and secrets, and changes them.
    ///
    /// Every item follows the same shape: name it to see it, name it with a
    /// value to change it.
    Id(IdArgs),
    /// Joins a network and runs until interrupted.
    // Boxed: it is much larger than the other variants, and every command
    // but this one would otherwise pay for its size. A `//` comment, not a
    // `///` one, or clap would print it as help.
    Up(Box<UpArgs>),
    /// Reports this device, what the agent is doing, and what this host can do.
    Status(StatusArgs),
    /// Shows the protocols this build can carry packets with.
    Protocols,
}

#[derive(Debug, Args)]
struct IdArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long, global = true)]
    control_socket: Option<PathBuf>,

    #[command(subcommand)]
    action: Option<IdAction>,
}

#[derive(Debug, Subcommand)]
enum IdAction {
    /// Shows the name this device answers to, or changes it.
    Hostname {
        /// The new name. Omit it to see the current one.
        name: Option<String>,
    },
    /// Shows the key this device signs with.
    Key {
        #[command(subcommand)]
        action: Option<KeyAction>,
    },
    /// Shows the secret of every network this device has joined.
    Secret {
        #[command(subcommand)]
        action: Option<SecretAction>,
    },
}

#[derive(Debug, Subcommand)]
enum KeyAction {
    /// Replaces the signing key with a fresh one.
    ///
    /// This device becomes a different member. The outgoing key gives up the
    /// addresses and names it held on the way out, so they are freed rather
    /// than reserved to a key nobody has. Requires the agent to be stopped.
    Rotate,
}

#[derive(Debug, Subcommand)]
enum SecretAction {
    /// Prints a fresh random secret, for a network that does not exist yet.
    Generate,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long)]
    control_socket: Option<PathBuf>,
}

/// Resolves the IPv4 overlay range from the flag.
///
/// Absent means the built-in default. A network that already settled on
/// another range wins over both.
fn resolve_ipv4_range(
    range: Option<&String>,
) -> Result<Option<Ipv4Range>, Box<dyn std::error::Error>> {
    match range {
        Some(text) if text.eq_ignore_ascii_case("none") => Ok(None),
        Some(text) => Ok(Some(
            text.parse::<Ipv4Range>()
                .map_err(|err| format!("--ipv4-range {text}: {err}"))?,
        )),
        None => Ok(Some(tsunagi::state::DEFAULT_IPV4_RANGE)),
    }
}

#[derive(Debug, Args, Clone)]
struct PathArgs {
    // Global, so they may be written before or after a subcommand. A
    // sub-subcommand that silently rejected the flag its parent accepts is
    // the kind of inconsistency that makes a tool feel arbitrary.
    /// Directory for the mandatory state. Defaults to the platform location.
    #[arg(long, env = "TSUNAGI_STATE_DIR", global = true)]
    state_dir: Option<PathBuf>,
    /// Directory for the disposable cache. Defaults to the platform location.
    #[arg(long, env = "TSUNAGI_CACHE_DIR", global = true)]
    cache_dir: Option<PathBuf>,
}

impl PathArgs {
    fn resolve(&self) -> Result<StoragePaths, tsunagi::Error> {
        let mut paths = StoragePaths::user_default()?;
        if let Some(dir) = &self.state_dir {
            paths.state_dir = dir.clone();
        }
        if let Some(dir) = &self.cache_dir {
            paths.cache_dir = dir.clone();
        }
        Ok(paths)
    }
}

/// How much external connectivity machinery the endpoint may use.
///
/// `direct` and `relay` publish this endpoint's addresses, keyed by its
/// endpoint id, to the public lookup service run by Number 0 — the company
/// behind iroh — at `dns.iroh.link`, and resolve peers through it. That is
/// what makes `--peer <endpoint-id>` work without an address.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Reach {
    /// Loopback and the local network only. Publishes nothing.
    Local,
    /// Public address lookup, direct paths only, no relays.
    Direct,
    /// Public address lookup plus public relay fallback. The default.
    #[value(alias = "n0")]
    Relay,
}

impl From<Reach> for TransportPolicy {
    fn from(value: Reach) -> Self {
        match value {
            Reach::Local => TransportPolicy::LocalOnly,
            Reach::Direct => TransportPolicy::DirectOnly,
            Reach::Relay => TransportPolicy::N0Defaults,
        }
    }
}

#[derive(Debug, Args)]
struct UpArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Network name. Must be identical on every participant.
    #[arg(long, short = 'n')]
    network: String,

    /// The shared secret, as printed by `tsunagi secret`.
    #[arg(
        long,
        short = 's',
        env = "TSUNAGI_SECRET",
        conflicts_with = "secret_file"
    )]
    secret: Option<String>,

    /// Read the shared secret from a file instead of the command line.
    #[arg(long)]
    secret_file: Option<PathBuf>,

    /// Hostname to announce. Defaults to the machine's.
    #[arg(long, help_heading = "System")]
    hostname: Option<String>,

    /// How much of iroh's reachability to use.
    ///
    /// About how the *control plane* finds peers, not about which protocol
    /// carries packets — that is `--protocol`.
    #[arg(long, value_enum, default_value_t = Reach::Relay, help_heading = "System")]
    reach: Reach,

    /// A peer to contact, as `<endpoint-id>` or `<endpoint-id>@<ip:port>,...`.
    ///
    /// One agent needs to know another to begin with. Repeat for several.
    #[arg(long = "peer", value_name = "PEER", help_heading = "System")]
    peers: Vec<String>,

    /// Local address to bind. Repeat for several; defaults to iroh's choice.
    #[arg(long = "bind", value_name = "ADDR", help_heading = "System")]
    binds: Vec<SocketAddr>,

    /// Name of the overlay interface. One agent has one, whatever carries it.
    #[arg(
        long,
        default_value = "tsun0",
        value_name = "NAME",
        help_heading = "System"
    )]
    interface: String,

    /// Largest packet the overlay carries, at least 576.
    #[arg(long, value_name = "BYTES", help_heading = "System")]
    mtu: Option<u32>,

    /// Do not create a real network interface.
    ///
    /// Tunnels still run and handshake, so a mesh can be verified with no
    /// privileges; traffic just does not reach the operating system.
    #[arg(long, help_heading = "System")]
    no_tun: bool,

    /// Protocols to carry packets with, best first.
    ///
    /// A pair of peers uses one they both have at the same wire version. A
    /// peer with none in common keeps its control plane and gets no data
    /// plane. `none` runs the control plane alone.
    #[arg(
        long = "protocol",
        value_name = "LIST",
        value_delimiter = ',',
        default_value = "wg-quic",
        help_heading = "Transport"
    )]
    protocols: Vec<String>,

    /// A protocol setting, as `key=value` or `protocol:key=value`.
    ///
    /// Repeat for several. `tsunagi protocols` lists what each one takes.
    #[arg(
        short = 'o',
        long = "protocol-option",
        value_name = "KEY=VALUE",
        help_heading = "Transport"
    )]
    protocol_options: Vec<String>,

    /// IPv4 overlay range, as `address/prefix`, or `none` to disable IPv4.
    ///
    /// Defaults to 10.13.37.0/24. Only the first member to join decides:
    /// a network that has already settled on a range wins, and a joining
    /// agent adopts what it finds. Addresses are allocated from it and
    /// recorded in signed state, so each member keeps its own across
    /// restarts and long absences.
    #[arg(long, value_name = "CIDR", help_heading = "System")]
    ipv4_range: Option<String>,

    /// Serve a local DNS zone for this network's members.
    ///
    /// Members resolve as `<hostname>.<zone>`, from signed state, so a
    /// member that is switched off still resolves. IPv4 only.
    #[arg(long, help_heading = "System")]
    dns: bool,

    /// The zone to answer for. Defaults to the network name.
    #[arg(long, value_name = "NAME", help_heading = "System")]
    dns_zone: Option<String>,

    /// Port for the local DNS server.
    #[arg(long, default_value_t = 5354, help_heading = "System")]
    dns_port: u16,

    /// How often to print a status summary, in seconds. Zero disables it.
    #[arg(long, default_value_t = 15)]
    status_interval: u64,

    /// Control socket to serve. Derived from the state directory by default.
    #[arg(long)]
    control_socket: Option<PathBuf>,
}

/// Reads the shared secret from an argument or a file.
fn load_secret(
    secret: Option<&str>,
    secret_file: Option<&std::path::Path>,
) -> Result<NetworkSecret, Box<dyn std::error::Error>> {
    let text = match (secret, secret_file) {
        (Some(secret), _) => secret.to_string(),
        (None, Some(path)) => std::fs::read_to_string(path)?,
        (None, None) => {
            return Err("provide --secret, --secret-file or TSUNAGI_SECRET".into());
        }
    };
    let text = text.trim();
    // The canonical form is preferred, but a raw high-entropy value is
    // accepted so an existing secret can be reused.
    match NetworkSecret::decode(text) {
        Ok(secret) => Ok(secret),
        Err(_) => Ok(NetworkSecret::from_bytes(text.as_bytes().to_vec())?),
    }
}

/// Parses `<endpoint-id>` or `<endpoint-id>@<ip:port>,<ip:port>`.
fn parse_peer(text: &str) -> Result<EndpointAddr, String> {
    let (id_text, addr_text) = match text.split_once('@') {
        Some((id, addrs)) => (id, Some(addrs)),
        None => (text, None),
    };
    let id: tsunagi::iroh_types::EndpointId = id_text
        .parse()
        .map_err(|err| format!("`{id_text}` is not an endpoint id: {err}"))?;
    let mut addr = EndpointAddr::new(id);
    if let Some(addrs) = addr_text {
        for entry in addrs.split(',') {
            let socket: SocketAddr = entry
                .trim()
                .parse()
                .map_err(|err| format!("`{entry}` is not an address: {err}"))?;
            addr = addr.with_ip_addr(socket);
        }
    }
    Ok(addr)
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log))
        .with_writer(std::io::stderr)
        .init();

    // The library never starts a runtime; this binary owns it.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("cannot start the async runtime: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli.command)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Id(args) => id(args).await,
        Command::Up(args) => up(*args).await,
        Command::Status(args) => status(args).await,
        Command::Protocols => show_protocols(),
    }
}

/// Path of the local control socket for a state directory.
fn control_socket(paths: &StoragePaths, override_path: Option<&PathBuf>) -> PathBuf {
    match override_path {
        Some(path) => path.clone(),
        None => tsunagi::ipc::control_socket_path(&paths.state_dir),
    }
}

/// What could be learned about this device, and from where.
///
/// A running agent is authoritative and live, so it is asked first. With no
/// agent there is still plenty to say: the mandatory state store holds the
/// identity and the configured networks, and reading it takes no directory
/// lock — so asking who this device is never collides with the agent that is
/// being asked about, and never needs one to be running.
enum Observed {
    /// A running agent answered over the control socket.
    Agent(Box<tsunagi::ipc::StatusReport>),
    /// Read from the state store, because the agent could not be asked.
    Stored {
        endpoint_id: Option<String>,
        hostname: Option<String>,
        /// Why the agent could not be asked.
        why: String,
        /// Whether a socket was there at all.
        ///
        /// Nothing running is an ordinary state and gets said plainly. A
        /// socket that is there and will not answer is a fault.
        socket_present: bool,
    },
}

/// Asks the agent, and falls back to the state store.
async fn observe(paths: &StoragePaths, socket: &std::path::Path) -> Observed {
    let socket_present = socket.exists();
    let why = if socket_present {
        match tsunagi::ipc::unix::request_status(socket).await {
            Ok(report) => return Observed::Agent(Box::new(report)),
            Err(err) => format!("{err}"),
        }
    } else {
        "no control socket for this state directory".to_string()
    };

    // Read-only, and deliberately tolerant: a state directory that has never
    // been used is not an error, it just has nothing to report yet.
    let (endpoint_id, hostname) = match tsunagi::storage::StateStore::open(paths.state_db()) {
        Ok(store) => (
            store
                .device_identity()
                .ok()
                .flatten()
                .map(|identity| identity.endpoint_id().to_string()),
            store.hostname().ok().flatten(),
        ),
        Err(_) => (None, None),
    };
    Observed::Stored {
        endpoint_id,
        hostname,
        why,
        socket_present,
    }
}

/// The `device` section: who this is and where it keeps things.
fn device_section(paths: &StoragePaths, observed: &Observed) -> report::Section {
    use report::{Health, Row, Section};

    let mut device = Section::new("device");
    let (endpoint_id, hostname) = match observed {
        Observed::Agent(report) => (
            Some(report.endpoint_id.clone()),
            Some(report.hostname.clone()),
        ),
        Observed::Stored {
            endpoint_id,
            hostname,
            ..
        } => (endpoint_id.clone(), hostname.clone()),
    };

    device.push(match endpoint_id {
        Some(id) => Row::new(Health::Info, "endpoint id", id),
        None => Row::new(Health::Info, "endpoint id", "not created yet")
            .with_note("generated the first time an agent starts here"),
    });
    if let Some(hostname) = hostname {
        device.push(Row::new(Health::Info, "hostname", hostname));
    }
    device.push(Row::new(
        Health::Info,
        "state directory",
        paths.state_dir.display().to_string(),
    ));
    device.push(Row::new(
        Health::Info,
        "cache directory",
        paths.cache_dir.display().to_string(),
    ));
    device
}

/// The networks this device belongs to, named but not described.
///
/// No secrets: this is part of `status`, and a status report is somewhere a
/// secret must never appear. `tsunagi id secret` is the place that shows one,
/// because asking for it there is deliberate.
fn configured_networks_section(paths: &StoragePaths) -> report::Section {
    use report::{Health, Row, Section};

    let mut section = Section::new("networks");
    let networks = stored_networks(paths);
    if networks.is_empty() {
        section.push(Row::new(Health::Info, "none", "no network has been joined"));
    }
    for network in &networks {
        section.push(Row::new(
            Health::Info,
            network.name.as_str(),
            format!(
                "{}{}",
                network.network_id,
                if network.auto_start {
                    "  (auto-start)"
                } else {
                    ""
                }
            ),
        ));
    }
    section
}

/// What the local DNS service is doing, for `status` to report.
#[derive(Debug, Clone, Default)]
struct DnsState {
    zone: String,
    listening: Option<SocketAddr>,
    bind_error: Option<String>,
    publish_error: Option<String>,
    publish_remedy: Option<String>,
    zone_warning: Option<String>,
    names: u32,
}

/// The local DNS service: a server, and an attempt to tell the OS about it.
///
/// The two are deliberately independent. The server comes up whether or not
/// the resolver can be configured, because a resolver the user can point at
/// by hand is worth more than nothing, and the reason it was not configured
/// is reported rather than swallowed.
struct DnsService {
    state: Arc<std::sync::Mutex<DnsState>>,
    publisher: Arc<dyn tsunagi::dns::DnsPublisher>,
    task: tokio::task::JoinHandle<()>,
}

impl DnsService {
    /// Stops answering and undoes what was told to the resolver.
    async fn shutdown(self) {
        self.task.abort();
        if let Err(err) = self.publisher.revert().await {
            tracing::debug!(%err, "cannot undo the resolver setting");
        }
    }
}

/// Picks the publisher for this platform.
fn dns_publisher() -> Arc<dyn tsunagi::dns::DnsPublisher> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(tsunagi::dns::publish::ResolvedPublisher::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(tsunagi::dns::publish::UnsupportedPublisher::new())
    }
}

/// Starts the DNS service for one network and keeps it in step with state.
fn spawn_dns(
    agent: Agent,
    network: NetworkId,
    zone: tsunagi::dns::ZoneName,
    port: u16,
) -> DnsService {
    use tsunagi::dns::{DnsServer, SharedZone, Zone, listen_addresses};

    let state = Arc::new(std::sync::Mutex::new(DnsState {
        zone: zone.as_str().to_string(),
        zone_warning: zone.collision(),
        ..DnsState::default()
    }));
    let publisher = dns_publisher();

    let task = {
        let state = Arc::clone(&state);
        let publisher = Arc::clone(&publisher);
        tokio::spawn(async move {
            let shared = SharedZone::new(Zone::new(zone.clone(), []));
            // Held for its `Drop`, which stops the server: the value is
            // never read, but letting it go is what closes the socket.
            let mut _server: Option<DnsServer> = None;
            let mut bound: Option<SocketAddr> = None;
            // What was tried last time, not what was got. Comparing against
            // what was got would rebind on every tick whenever the preferred
            // address is one that cannot be bound, closing the port each
            // time for no reason.
            let mut attempted: Vec<SocketAddr> = Vec::new();
            let mut published: Option<tsunagi::dns::Published> = None;
            // A condition that persists is worth saying once, not every
            // pass; and a refusal will not lift without somebody acting, so
            // hammering at it two seconds apart is pure noise.
            let mut reported: Option<String> = None;
            let mut retry_after: Option<tokio::time::Instant> = None;
            let mut recipe_shown = false;
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));

            loop {
                ticker.tick().await;
                let Ok(status) = agent.network_status(network).await else {
                    continue;
                };

                // Names come from signed state, so a member that is away is
                // in here too.
                let members = status.members.iter().filter_map(|member| {
                    Some((member.hostname.clone()?, member.overlay_address_v4?))
                });
                let fresh = Zone::new(zone.clone(), members);
                let names = fresh.len() as u32;
                shared.set(fresh);

                // Listen where the resolver will be told to ask, which is an
                // address on the overlay interface when there is one.
                let own = agent.endpoint_id();
                let overlay = status
                    .members
                    .iter()
                    .find(|member| member.endpoint_id == own)
                    .and_then(|member| member.overlay_address_v4);
                // The interface belongs to the agent, so the resolver
                // setting attaches to that one and not to a protocol's.
                let interface = agent
                    .overlay()
                    .map(|overlay| overlay.interface)
                    .filter(|name| !name.is_empty());
                let wanted = listen_addresses(overlay, port);
                if attempted != wanted {
                    attempted = wanted.clone();
                    // Dropping the old one first releases the port, so the
                    // rebind is not racing itself.
                    _server = None;
                    let mut last: Option<std::io::Error> = None;
                    bound = None;
                    for candidate in &wanted {
                        match DnsServer::bind(*candidate, shared.clone()).await {
                            Ok(fresh) => {
                                tracing::info!(
                                    address = %fresh.local_addr(),
                                    zone = %zone.as_str(),
                                    "dns listening"
                                );
                                bound = Some(fresh.local_addr());
                                _server = Some(fresh);
                                break;
                            }
                            Err(err) => last = Some(err),
                        }
                    }
                    let bind_error = bound.is_none().then(|| {
                        last.map_or_else(
                            || "no address to listen on".to_string(),
                            |err| err.to_string(),
                        )
                    });
                    update(&state, |state| {
                        state.listening = bound;
                        state.bind_error = bind_error;
                    });
                    // The address moved, so whatever the resolver was told
                    // is now wrong.
                    published = None;
                }

                let Some(address) = bound else { continue };
                let Some(interface) = interface else {
                    update(&state, |state| {
                        state.publish_error = Some(
                            "there is no overlay interface to attach the resolver setting to"
                                .to_string(),
                        );
                        state.publish_remedy = None;
                    });
                    update(&state, |state| state.names = names);
                    continue;
                };

                let want_published = tsunagi::dns::Published {
                    interface,
                    server: address,
                    domains: vec![zone.as_str().to_string()],
                };
                let due = retry_after.is_none_or(|at| tokio::time::Instant::now() >= at);
                if published.as_ref() != Some(&want_published) && due {
                    match publisher.apply(&want_published).await {
                        Ok(()) => {
                            tracing::info!(
                                zone = %zone.as_str(),
                                interface = %want_published.interface,
                                "the system resolver was told where to ask"
                            );
                            published = Some(want_published);
                            reported = None;
                            retry_after = None;
                            update(&state, |state| {
                                state.publish_error = None;
                                state.publish_remedy = None;
                            });
                        }
                        Err(err) => {
                            // Not fatal, by design: the server keeps
                            // answering and the user is told what is missing.
                            let text = err.to_string();
                            if reported.as_deref() != Some(text.as_str()) {
                                tracing::warn!("cannot configure the system resolver: {text}");
                                if err.needs_a_human() && !recipe_shown {
                                    recipe_shown = true;
                                    tracing::warn!(
                                        "systemd-resolved asks polkit, and polkit decides by \
                                         user rather than by capability, so this cannot be done \
                                         from inside the agent. To grant it once:\n\n{}\n",
                                        tsunagi::dns::publish::polkit_recipe(&current_user())
                                    );
                                }
                                reported = Some(text.clone());
                            }
                            // Backed off, and further for something only a
                            // person can change.
                            let wait = if err.needs_a_human() { 300 } else { 15 };
                            retry_after = Some(
                                tokio::time::Instant::now() + std::time::Duration::from_secs(wait),
                            );
                            let remedy = err.remedy().map(str::to_string);
                            update(&state, |state| {
                                state.publish_error = Some(text);
                                state.publish_remedy = remedy;
                            });
                        }
                    }
                }
                update(&state, |state| state.names = names);
            }
        })
    };

    DnsService {
        state,
        publisher,
        task,
    }
}

fn update(state: &Arc<std::sync::Mutex<DnsState>>, edit: impl FnOnce(&mut DnsState)) {
    match state.lock() {
        Ok(mut guard) => edit(&mut guard),
        Err(poisoned) => edit(&mut poisoned.into_inner()),
    }
}

/// What a protocol is called, what it speaks, and what it takes.
///
/// A registry rather than a lookup on the plugins themselves, because
/// `tsunagi protocols` has to answer before anything is constructed, and
/// because this is the list `--protocol` resolves against.
struct ProtocolSpec {
    /// The name on the wire, which is what peers compare.
    name: &'static str,
    /// The wire version. Not the software version: two peers on different
    /// builds carry traffic for each other as long as this matches.
    version: u16,
    /// One line about what it is.
    summary: &'static str,
    /// The settings it accepts.
    options: &'static [tsunagi::dataplane::ProtocolOption],
}

/// Every protocol this build has.
const PROTOCOLS: &[ProtocolSpec] = &[ProtocolSpec {
    name: tsunagi_wg_quic::WIREGUARD_PROTOCOL,
    version: tsunagi_wg_quic::ANNOUNCEMENT_VERSION,
    summary: "WireGuard's cryptography carried in iroh's QUIC datagrams, so it \
              crosses NAT and survives where plain WireGuard is blocked",
    options: WireguardPlugin::OPTIONS,
}];

/// One `-o` setting, and the protocol it was aimed at.
struct Setting {
    /// `Some` when written as `protocol:key=value`.
    protocol: Option<String>,
    key: String,
    value: String,
}

/// Parses `-o` settings, which are `key=value` or `protocol:key=value`.
fn parse_settings(raw: &[String]) -> Result<Vec<Setting>, Box<dyn std::error::Error>> {
    raw.iter()
        .map(|entry| {
            let (left, value) = entry
                .split_once('=')
                .ok_or_else(|| format!("`{entry}` is not a setting; write it as key=value"))?;
            let (protocol, key) = match left.split_once(':') {
                Some((protocol, key)) => (Some(protocol.to_string()), key),
                None => (None, left),
            };
            if key.is_empty() {
                return Err(format!("`{entry}` has no key").into());
            }
            Ok(Setting {
                protocol,
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

/// The settings meant for one protocol, refusing any that fit nowhere.
fn settings_for(spec: &ProtocolSpec, settings: &[Setting]) -> Vec<(String, String)> {
    let mut taken = Vec::new();
    for setting in settings {
        let aimed_here = match &setting.protocol {
            Some(name) => name == spec.name,
            // Unqualified settings go to whichever protocol declares the
            // key. With one selected that is the obvious reading; with
            // several, write `protocol:key=value`.
            None => spec.options.iter().any(|option| option.key == setting.key),
        };
        if aimed_here {
            taken.push((setting.key.clone(), setting.value.clone()));
        }
    }
    taken
}

/// Shows the protocols this build has, and what each one takes.
fn show_protocols() -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let mut out = Report::new();
    for spec in PROTOCOLS {
        let mut section = Section::new(format!("{}  (wire version {})", spec.name, spec.version));
        section.push(Row::new(Health::Info, "what", spec.summary));
        if spec.options.is_empty() {
            section.push(Row::new(Health::Info, "settings", "none"));
        }
        for option in spec.options {
            section.push(
                Row::new(
                    Health::Info,
                    format!("-o {}={}", option.key, option.value),
                    option.help,
                )
                .with_note(match option.default {
                    Some(default) => format!("default {default}"),
                    None => "no default".to_string(),
                }),
            );
        }
        out.push(section);
    }
    print_report("tsunagi protocols", &out)
}

/// Serves the local control socket from the running agent.
///
/// A struct rather than a closure because this end both answers questions and
/// accepts changes, and a change has to reach the agent itself: writing one
/// into the store behind its back would be overwritten by the next thing it
/// published.
struct AgentControl {
    agent: Agent,
    plugin: Option<Arc<WireguardPlugin>>,
    dns: Option<Arc<std::sync::Mutex<DnsState>>>,
}

impl tsunagi::ipc::unix::ReportSource for AgentControl {
    fn report(&self) -> tsunagi::BoxFuture<'_, tsunagi::ipc::StatusReport> {
        Box::pin(async move {
            let dns = self.dns.as_ref().map(|state| match state.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            });
            build_report(&self.agent, self.plugin.as_deref(), dns).await
        })
    }

    fn set_hostname(&self, hostname: String) -> tsunagi::BoxFuture<'_, Result<String, String>> {
        Box::pin(async move {
            self.agent
                .set_hostname(&hostname)
                .await
                .map_err(|err| err.to_string())
        })
    }
}

/// The networks this device has joined, read straight from the store.
///
/// Secrets live only in the mandatory state, never in a status report and
/// never on the control socket, so they are read here rather than asked for.
fn stored_networks(paths: &StoragePaths) -> Vec<tsunagi::storage::StoredNetwork> {
    tsunagi::storage::StateStore::open(paths.state_db())
        .and_then(|store| store.list_networks())
        .unwrap_or_default()
}

/// `tsunagi id`: what this device is, and what changes it.
async fn id(args: IdArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());

    match args.action {
        None => show_identity(&paths, &socket).await,
        Some(IdAction::Hostname { name: None }) => show_hostname(&paths, &socket).await,
        Some(IdAction::Hostname { name: Some(name) }) => set_hostname(&paths, &socket, &name).await,
        Some(IdAction::Key { action: None }) => show_key(&paths, &socket).await,
        Some(IdAction::Key {
            action: Some(KeyAction::Rotate),
        }) => rotate_key(&paths, &socket).await,
        Some(IdAction::Secret { action: None }) => show_secrets(&paths),
        Some(IdAction::Secret {
            action: Some(SecretAction::Generate),
        }) => {
            let secret = NetworkSecret::generate();
            println!("{}", secret.encode().as_str());
            eprintln!(
                "\nShare this with every participant, over a channel you trust.\n\
                 Anyone who has it can join the network."
            );
            Ok(())
        }
    }
}

/// Everything about this device in one view.
async fn show_identity(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let observed = observe(paths, socket).await;
    let mut out = Report::new();

    let mut device = device_section(paths, &observed);
    device.push(Row::new(
        Health::Info,
        "signs with",
        "the endpoint key above; there is no separate signing certificate",
    ));
    out.push(device);

    let networks = stored_networks(paths);
    let mut section = Section::new("networks");
    if networks.is_empty() {
        section.push(Row::new(Health::Info, "none", "no network has been joined"));
    }
    for network in &networks {
        section.push(
            Row::new(
                Health::Info,
                network.name.as_str(),
                network.network_id.to_string(),
            )
            .with_note(format!("secret  {}", network.secret.encode().as_str())),
        );
    }
    out.push(section);

    print_report("tsunagi id", &out)
}

/// The name this device answers to.
async fn show_hostname(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match observe(paths, socket).await {
        Observed::Agent(report) => println!("{}", report.hostname),
        Observed::Stored { hostname, .. } => match hostname {
            Some(hostname) => println!("{hostname}"),
            None => println!(
                "{}",
                tsunagi::agent::system_hostname().unwrap_or_else(|| "unknown".into())
            ),
        },
    }
    Ok(())
}

/// Changes the name, through the agent when one is running.
///
/// Through it rather than behind its back: the agent republishes its signed
/// claim, which is what gives up the previous name, and tells its peers. A
/// write straight to the store while it ran would be overwritten by the next
/// thing the agent published.
async fn set_hostname(
    paths: &StoragePaths,
    socket: &std::path::Path,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if socket.exists() {
        return match tsunagi::ipc::unix::set_hostname(socket, name).await {
            Ok(accepted) => {
                println!("{accepted}");
                Ok(())
            }
            Err(err) => {
                Err(format!("the agent is running but would not accept the change: {err}").into())
            }
        };
    }

    let accepted = tsunagi::state::sanitise_hostname(name);
    if accepted.is_empty() {
        return Err("a hostname must contain at least one letter, digit, `-`, `.` or `_`".into());
    }
    let store = tsunagi::storage::StateStore::open(paths.state_db())?;
    store.set_hostname(&accepted)?;
    println!("{accepted}");
    Ok(())
}

/// The key this device signs with.
async fn show_key(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match observe(paths, socket).await {
        Observed::Agent(report) => println!("{}", report.endpoint_id),
        Observed::Stored { endpoint_id, .. } => match endpoint_id {
            Some(id) => println!("{id}"),
            None => return Err("this device has no identity yet; start an agent once".into()),
        },
    }
    Ok(())
}

/// Replaces the signing key.
async fn rotate_key(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // The rotation writes, so it needs the directory to itself. Refused up
    // front rather than after the lock fails, because what a lock failure
    // says does not tell the reader what to do about it.
    if socket.exists() {
        return Err(
            "stop the agent first: replacing the signing key rewrites state it is using".into(),
        );
    }

    let store = tsunagi::storage::StateStore::open(paths.state_db())?;
    let (identity, released) = store.rotate_device_identity()?;
    println!("{}", identity.endpoint_id());
    if !released.is_empty() {
        eprintln!(
            "\nReleased what the previous key held in {} network(s). \
             This device rejoins as a new member and is allocated a new address.",
            released.len()
        );
    }
    Ok(())
}

/// The secret of every network this device has joined.
fn show_secrets(paths: &StoragePaths) -> Result<(), Box<dyn std::error::Error>> {
    let networks = stored_networks(paths);
    if networks.is_empty() {
        eprintln!("no network has been joined");
        return Ok(());
    }
    for network in networks {
        println!("{}  {}", network.name, network.secret.encode().as_str());
    }
    Ok(())
}

/// Reports this device, what the agent is doing, and what this host can do.
///
/// Three levels, and the distinction between the middle two is deliberate:
/// *degraded* is something the agent runs without and that the user can fix
/// from a stated one-liner, *broken* is something it cannot work around.
/// Getting those the wrong way round makes a diagnostic tool useless, so
/// each check below says which it is and why.
async fn status(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    let observed = observe(&paths, &socket).await;

    let mut out = Report::new();
    out.push(device_section(&paths, &observed));

    let mut agent = Section::new("agent");
    match &observed {
        Observed::Agent(report) => {
            agent.push(Row::new(
                Health::Good,
                "running",
                format!("reachable at {}", socket.display()),
            ));
            if !report.bound_sockets.is_empty() {
                agent.push(Row::new(
                    Health::Info,
                    "bound",
                    report.bound_sockets.join(", "),
                ));
            }
            agent.push(if report.cache_healthy {
                Row::new(Health::Good, "cache", "usable")
            } else {
                Row::new(Health::Degraded, "cache", "unavailable")
                    .with_note("disposable: the agent runs, rediscovering what it cached")
            });
        }
        Observed::Stored {
            why,
            socket_present,
            ..
        } => {
            // Nothing running is an ordinary answer to "what is running", not
            // a fault; a socket that will not answer is a fault.
            agent.push(if *socket_present {
                // The version check in the framing names a mismatch only for
                // whichever side is newer. An older agent reading a newer
                // request just drops the connection, so the hint has to be
                // offered rather than asserted.
                Row::new(Health::Degraded, "running", "not answering").with_note(format!(
                    "{why}  ·  it may be an older build: restart it with this binary. \
                         The rest was read from the store"
                ))
            } else {
                Row::new(Health::Info, "running", "no")
                    .with_note(format!("{why}  ·  the rest was read from the store"))
            });
        }
    }
    out.push(agent);

    match &observed {
        Observed::Agent(report) => {
            for network in &report.networks {
                // Whether another configured network answers to the same
                // name, which is what makes two sections look like one.
                let shared = report
                    .networks
                    .iter()
                    .filter(|other| other.name == network.name)
                    .count()
                    > 1;
                out.push(network_section(network, &report.endpoint_id, shared));
            }
        }
        // Without an agent there is no live view, but the store still knows
        // which networks this device belongs to, which is worth saying.
        Observed::Stored { .. } => out.push(configured_networks_section(&paths)),
    }

    if let Observed::Agent(report) = &observed
        && let Some(dns) = &report.dns
    {
        out.push(dns_section(dns));
    }

    out.push(host_section());
    out.push(addresses_section().await);
    print_report("tsunagi status", &out)
}

/// The local resolver: whether it answers, and whether the system asks it.
fn dns_section(dns: &tsunagi::ipc::DnsReport) -> report::Section {
    use report::{Health, Row, Section};

    let mut section = Section::new("dns");
    section.push(Row::new(
        Health::Info,
        "zone",
        format!("{}  ·  {} name(s)", dns.zone, dns.names),
    ));
    if let Some(warning) = &dns.zone_warning {
        section.push(Row::new(Health::Degraded, "zone name", warning.clone()));
    }

    match (&dns.listening, &dns.bind_error) {
        (Some(address), _) => {
            section.push(Row::new(Health::Good, "listening", address.clone()));
        }
        (None, Some(err)) => {
            section.push(Row::new(Health::Broken, "listening", err.clone()));
        }
        (None, None) => {
            section.push(Row::new(Health::Degraded, "listening", "not yet"));
        }
    }

    match &dns.publish_error {
        None if dns.listening.is_some() => {
            section.push(Row::new(
                Health::Good,
                "system resolver",
                "asking this server for the zone",
            ));
        }
        None => {}
        Some(err) => {
            // The server still answers, so this is a degraded overlay and
            // not a broken one; what is missing is the automatic part.
            let row = Row::new(Health::Degraded, "system resolver", err.clone());
            section.push(match (&dns.publish_remedy, &dns.listening) {
                (Some(remedy), _) => row.with_note(remedy.clone()),
                (None, Some(address)) => row.with_note(format!(
                    "resolve names yourself with `dig @{} -p {} <name>.{}`",
                    address.rsplit_once(':').map_or("", |(host, _)| host),
                    address.rsplit_once(':').map_or("", |(_, port)| port),
                    dns.zone
                )),
                (None, None) => row,
            });
        }
    }
    section
}

/// One member of a network, from every source that knows something about it.
///
/// The three sources answer different questions and none of them answers the
/// whole one. The signed state says who belongs, and keeps saying it while
/// they are away. The session list says who is here. The overlay says whose
/// tunnel is up. Reporting them as three lists is what made a peer being
/// offline look like three unrelated faults.
struct MemberRow<'a> {
    endpoint_id: &'a str,
    hostname: Option<&'a str>,
    /// `Some` exactly when there is an authenticated session right now.
    transport: Option<&'a str>,
    rtt_ms: Option<u64>,
    overlay_address_v4: Option<&'a str>,
    tunnel: Option<&'a tsunagi::ipc::OverlayPeerReport>,
    failed_dials: u32,
}

impl MemberRow<'_> {
    fn online(&self) -> bool {
        self.transport.is_some()
    }

    /// What to call it: the name it announced, or a short form of its id.
    ///
    /// A member that is away has no hostname, because nothing durable records
    /// one — only the signed claim survives, and that carries an address.
    fn label(&self) -> String {
        match self.hostname {
            Some(hostname) => hostname.to_string(),
            None => short(self.endpoint_id, 12),
        }
    }
}

/// Joins the three views of a network into one list, online members first.
fn member_rows<'a>(network: &'a tsunagi::ipc::NetworkReport, own_id: &str) -> Vec<MemberRow<'a>> {
    use std::collections::BTreeMap;

    fn entry<'a, 'm>(
        rows: &'m mut BTreeMap<&'a str, MemberRow<'a>>,
        id: &'a str,
    ) -> &'m mut MemberRow<'a> {
        rows.entry(id).or_insert_with(|| MemberRow {
            endpoint_id: id,
            hostname: None,
            transport: None,
            rtt_ms: None,
            overlay_address_v4: None,
            tunnel: None,
            failed_dials: 0,
        })
    }

    let mut rows: BTreeMap<&'a str, MemberRow<'a>> = BTreeMap::new();
    for member in &network.members {
        let row = entry(&mut rows, &member.endpoint_id);
        row.overlay_address_v4 = member.overlay_address_v4.as_deref();
        row.failed_dials = member.failed_dials;
    }
    for peer in &network.peers {
        let row = entry(&mut rows, &peer.endpoint_id);
        row.hostname = peer.hostname.as_deref();
        row.transport = Some(&peer.transport);
        row.rtt_ms = peer.rtt_ms;
    }
    if let Some(overlay) = &network.overlay {
        for peer in &overlay.peers {
            let row = entry(&mut rows, &peer.endpoint_id);
            row.tunnel = Some(peer);
            if row.overlay_address_v4.is_none() {
                row.overlay_address_v4 = peer.address.as_deref();
            }
        }
    }

    // This agent is in the roster too — it signs claims like everyone else —
    // but it is already the subject of the `device` section.
    let mut rows: Vec<MemberRow<'a>> = rows
        .into_values()
        .filter(|row| row.endpoint_id != own_id)
        .collect();
    // Online first, as asked, then by name so the order is stable between
    // runs rather than following whatever the map happened to hold.
    rows.sort_by(|a, b| {
        b.online()
            .cmp(&a.online())
            .then_with(|| a.label().cmp(&b.label()))
    });
    rows
}

/// One network: what it is, who is in it, and what has happened since start.
fn network_section(
    network: &tsunagi::ipc::NetworkReport,
    own_id: &str,
    name_shared: bool,
) -> report::Section {
    use report::{Health, Row, Section};

    // The id is in the heading, not only in a row: a name is a label a user
    // chose and two networks may share one, so a heading without the id
    // reads as one network that is somehow both working and empty.
    let mut section = Section::new(format!(
        "network {} ({})",
        network.name,
        short(&network.network_id, 10)
    ));
    section.push(if network.active {
        Row::new(Health::Good, "state", network.network_id.clone())
    } else {
        Row::new(Health::Degraded, "state", "inactive")
    });
    if name_shared {
        section.push(
            Row::new(
                Health::Degraded,
                "name",
                format!(
                    "another configured network is also called `{}`",
                    network.name
                ),
            )
            .with_note(
                "a network is its name *and* its secret, so these two share nothing. \
                 Usually a mistyped secret; `tsunagi id secret` shows which is which.",
            ),
        );
    }
    if let Some(conflict) = &network.range_conflict {
        section.push(
            Row::new(
                Health::Degraded,
                "range",
                format!("cannot use {conflict}: another network here already does"),
            )
            .with_note(
                "one agent has one interface, so an address belongs to one network. \
                 This one waits to adopt whatever its members settle on; give it \
                 `--ipv4-range` of its own to propose one.",
            ),
        );
    }

    if let Some(overlay) = &network.overlay {
        section.push(Row::new(
            Health::Info,
            "overlay",
            format!(
                "{}  {}  mtu {}",
                overlay.interface,
                match &overlay.address {
                    Some(address) => format!("{address}/{}", overlay.prefix_len),
                    None => "no address agreed yet".to_string(),
                },
                overlay.mtu
            ),
        ));
    }

    let rows = member_rows(network, own_id);
    let online = rows.iter().filter(|row| row.online()).count();
    if rows.is_empty() {
        // Why there is nobody, rather than just that there is nobody: the
        // two reasons want different actions.
        section.push(Row::new(
            Health::Info,
            "members",
            match (&network.range, &network.range_conflict) {
                (None, Some(_)) => "none: this network has no range to allocate from",
                _ => "none known yet; nobody else has joined",
            },
        ));
    } else {
        section.push(Row::new(
            Health::Info,
            "members",
            format!("{online} of {} online", rows.len()),
        ));
    }

    for row in &rows {
        section.push(member_row(row));
    }

    // Counters are history, not health. Grading them keeps a report red long
    // after whatever caused them has gone away — which is exactly how a peer
    // coming back still looked like three problems.
    let (sent, received) = network.control_messages;
    let mut totals = vec![format!("{sent} sent, {received} received")];
    if network.dial_failures > 0 {
        totals.push(format!("{} dial failure(s)", network.dial_failures));
    }
    if network.handshake_failures > 0 {
        totals.push(format!(
            "{} handshake failure(s)",
            network.handshake_failures
        ));
    }
    if let Some(overlay) = &network.overlay
        && overlay.unroutable_packets > 0
    {
        totals.push(format!(
            "{} packet(s) to an address nobody owns{}",
            overlay.unroutable_packets,
            match &overlay.unroutable_sample {
                Some(sample) => format!(" ({sample})"),
                None => String::new(),
            }
        ));
    }
    // Repeated handshake failures with nobody connected is the signature of a
    // mismatched secret, and that *is* a present-tense problem rather than a
    // number from the past.
    let health = if network.handshake_failures > 0 && online == 0 {
        Health::Degraded
    } else {
        Health::Info
    };
    let totals_row = Row::new(health, "since start", totals.join(", "));
    section.push(if health == Health::Degraded {
        totals_row.with_note("handshakes are failing and nobody is connected: check that every member was given the same secret")
    } else {
        totals_row
    });

    section
}

/// One member: connected or not, and what is known either way.
fn member_row(row: &MemberRow<'_>) -> report::Row {
    use report::{Health, Row};

    let Some(transport) = row.transport else {
        // Away. Not a fault of this agent, and in a mesh of laptops it is the
        // ordinary condition, so it is stated rather than flagged.
        let mut detail = "offline".to_string();
        if let Some(v4) = row.overlay_address_v4 {
            detail.push_str(&format!("  ·  {v4} still reserved for it"));
        }
        let out = Row::new(Health::Info, row.label(), detail);
        return if row.failed_dials > 0 {
            // Attributed to the member it concerns, rather than left as a
            // network-wide counter with no explanation attached.
            out.with_note(format!(
                "{} dial attempt(s) failed since it was last reachable",
                row.failed_dials
            ))
        } else {
            out
        };
    };

    let direct = transport.eq_ignore_ascii_case("direct");
    let tunnel_up = row.tunnel.is_some_and(|tunnel| tunnel.is_up());
    let has_overlay = row.tunnel.is_some();

    let mut detail = transport.to_lowercase();
    if let Some(rtt) = row.rtt_ms {
        detail.push_str(&format!("  rtt {rtt}ms"));
    }
    if let Some(v4) = row.overlay_address_v4 {
        detail.push_str(&format!("  ·  {v4}"));
    }

    let health = if !direct || (has_overlay && !tunnel_up) {
        Health::Degraded
    } else {
        Health::Good
    };

    let mut out = Row::new(health, row.label(), detail);
    if let Some(tunnel) = row.tunnel {
        out = out.with_note(match tunnel.handshake_secs_ago {
            Some(secs) => format!(
                "tunnel up, handshake {secs}s ago, tx {} rx {}{}  ·  {}",
                tunnel.tx_packets,
                tunnel.rx_packets,
                if tunnel.dropped > 0 {
                    format!(", {} dropped", tunnel.dropped)
                } else {
                    String::new()
                },
                tunnel.path
            ),
            None => "no WireGuard handshake yet; the tunnel cannot carry traffic".to_string(),
        });
    }
    out
}

/// Shortens an identifier for a column, with an ellipsis when it was cut.
fn short(text: &str, len: usize) -> String {
    if text.chars().count() <= len {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(len).collect::<String>())
    }
}

/// What this host can and cannot do for the data plane.
fn host_section() -> report::Section {
    use report::{Health, Row, Section};

    let mut host = Section::new("host");
    host.push(Row::new(
        Health::Info,
        "implementation",
        "userspace WireGuard (boringtun); no kernel module needed",
    ));
    {
        if cfg!(target_os = "linux") {
            let tun_path = std::path::Path::new("/dev/net/tun");
            host.push(if !tun_path.exists() {
                Row::new(Health::Broken, "/dev/net/tun", "missing")
                    .with_note("load the `tun` module; without it there can be no interface")
            } else {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(tun_path)
                {
                    Ok(_) => Row::new(Health::Good, "/dev/net/tun", "openable"),
                    Err(err) => Row::new(
                        Health::Broken,
                        "/dev/net/tun",
                        format!("not openable: {err}"),
                    )
                    .with_note("the device node must be readable and writable by this user"),
                }
            });
        }

        use tsunagi::overlay::{Privilege, probe_net_admin};
        match probe_net_admin() {
            Privilege::Available => {
                host.push(Row::new(Health::Good, "privileges", "CAP_NET_ADMIN held"));
                host.push(Row::new(
                    Health::Good,
                    "interface",
                    "managed by the agent: created on start, removed on exit",
                ));
            }
            Privilege::Missing(_) => {
                // The note is the command and nothing else: a paragraph of
                // explanation belongs in the runtime error, not in a column
                // the eye is meant to scan.
                host.push(
                    Row::new(Health::Degraded, "privileges", "CAP_NET_ADMIN not held")
                        .with_note(format!("sudo setcap cap_net_admin+p {}", program_path())),
                );
                host.push(Row::new(
                    Health::Degraded,
                    "interface",
                    "cannot be created; run with `--no-tun` meanwhile",
                ));
            }
            Privilege::Unsupported => {
                host.push(Row::new(
                    Health::Degraded,
                    "privileges",
                    format!(
                        "managing interfaces is not implemented on {} yet",
                        std::env::consts::OS
                    ),
                ));
                host.push(Row::new(
                    Health::Degraded,
                    "interface",
                    "cannot be created; run with `--no-tun`",
                ));
            }
        }
    }
    host
}

/// The addresses this host could reach a peer from.
async fn addresses_section() -> report::Section {
    use report::{Health, Row, Section};

    let mut addresses = Section::new("local addresses");
    let found = netwatch_addresses().await;
    if found.is_empty() {
        addresses.push(
            Row::new(Health::Degraded, "interfaces", "none found")
                .with_note("best effort; the agent may still find a way out"),
        );
    }
    for addr in found {
        // Loopback alone reaches nobody, but on a host that also has a real
        // address it is unremarkable, so it is labelled rather than flagged.
        let kind = match (addr.is_loopback(), addr.is_ipv4()) {
            (true, _) => "loopback",
            (false, true) => "ipv4",
            (false, false) => "ipv6",
        };
        addresses.push(Row::new(Health::Info, kind, addr.to_string()));
    }
    addresses
}

/// Writes a report to stdout under a title.
///
/// `anstream` decides whether the escapes survive: they are stripped when
/// stdout is not a terminal, when `NO_COLOR` is set, and on a Windows console
/// that cannot render them.
fn print_report(title: &str, out: &report::Report) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut stdout = anstream::stdout().lock();
    writeln!(stdout, "{title}\n")?;
    write!(stdout, "{}", out.render(true))?;
    Ok(())
}

/// The shape of what `tsunagi status` reports.
///
/// Findings are built first and rendered second, so what is reported is
/// decided separately from how it looks and can be tested without a
/// terminal. Colour is deliberately *redundant*: every row carries a word as
/// well, so the report reads the same when the escapes are stripped — piped
/// to a file, on a dumb terminal, or by someone who cannot distinguish the
/// colours.
mod report {
    use anstyle::{AnsiColor, Color, Style};

    /// How healthy one finding is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Health {
        /// Not a check at all: a fact, such as an identifier or a path.
        ///
        /// Grading these would be noise — an endpoint id is neither good nor
        /// bad — and a column of green `ok` next to plain data teaches the
        /// eye to ignore the column, which is the opposite of the point.
        Info,
        /// Works, nothing to do.
        Good,
        /// The agent runs, but something it could do it cannot, and there is
        /// a remedy. A missing capability with a one-line fix lands here.
        Degraded,
        /// Something the agent needs is unavailable and the function it
        /// serves will not work at all.
        Broken,
    }

    impl Health {
        /// The word printed in the margin. Four characters, so rows line up.
        fn word(self) -> &'static str {
            match self {
                Health::Info => "    ",
                Health::Good => "ok  ",
                Health::Degraded => "warn",
                Health::Broken => "FAIL",
            }
        }

        fn style(self) -> Style {
            let colour = match self {
                Health::Info => return Style::new(),
                Health::Good => AnsiColor::Green,
                Health::Degraded => AnsiColor::Yellow,
                Health::Broken => AnsiColor::Red,
            };
            Style::new().fg_color(Some(Color::Ansi(colour)))
        }
    }

    /// One finding.
    #[derive(Debug, Clone)]
    pub struct Row {
        health: Health,
        label: String,
        detail: String,
        /// What to do about it, when there is something to do.
        note: Option<String>,
    }

    impl Row {
        /// A finding with no remedy attached.
        pub fn new(health: Health, label: impl Into<String>, detail: impl Into<String>) -> Self {
            Self {
                health,
                label: label.into(),
                detail: detail.into(),
                note: None,
            }
        }

        /// Adds the remedy shown under the row.
        pub fn with_note(mut self, note: impl Into<String>) -> Self {
            self.note = Some(note.into());
            self
        }
    }

    /// A group of findings under a heading.
    #[derive(Debug, Clone)]
    pub struct Section {
        title: String,
        rows: Vec<Row>,
    }

    impl Section {
        /// An empty section.
        pub fn new(title: impl Into<String>) -> Self {
            Self {
                title: title.into(),
                rows: Vec::new(),
            }
        }

        /// Adds a finding.
        pub fn push(&mut self, row: Row) {
            self.rows.push(row);
        }
    }

    /// Everything `doctor` found.
    #[derive(Debug, Clone, Default)]
    pub struct Report {
        sections: Vec<Section>,
    }

    impl Report {
        /// An empty report.
        pub fn new() -> Self {
            Self::default()
        }

        /// Adds a section, dropping it if it has no findings.
        pub fn push(&mut self, section: Section) {
            if !section.rows.is_empty() {
                self.sections.push(section);
            }
        }

        fn count(&self, health: Health) -> usize {
            self.sections
                .iter()
                .flat_map(|section| &section.rows)
                .filter(|row| row.health == health)
                .count()
        }

        /// The worst thing in the report.
        pub fn worst(&self) -> Health {
            if self.count(Health::Broken) > 0 {
                Health::Broken
            } else if self.count(Health::Degraded) > 0 {
                Health::Degraded
            } else {
                Health::Good
            }
        }

        /// Whether anything in the report was graded at all.
        ///
        /// A report of plain facts — `tsunagi id` — has nothing to summarise,
        /// and "everything checked out" under a list of identifiers would be
        /// claiming something that was never checked.
        fn has_checks(&self) -> bool {
            self.sections
                .iter()
                .flat_map(|section| &section.rows)
                .any(|row| row.health != Health::Info)
        }

        /// The closing line.
        fn summary(&self) -> String {
            fn checks(count: usize) -> String {
                if count == 1 {
                    "1 check".to_string()
                } else {
                    format!("{count} checks")
                }
            }
            let (degraded, broken) = (self.count(Health::Degraded), self.count(Health::Broken));
            match (degraded, broken) {
                (0, 0) => "everything checked out".to_string(),
                (0, broken) => format!("{} broken", checks(broken)),
                (degraded, 0) => format!("{} degraded", checks(degraded)),
                (degraded, broken) => {
                    format!("{} degraded, {} broken", checks(degraded), checks(broken))
                }
            }
        }

        /// Renders the report.
        ///
        /// `styled` false leaves out every escape sequence, which is what a
        /// test asserts against and what a redirected stdout gets.
        pub fn render(&self, styled: bool) -> String {
            let width = self
                .sections
                .iter()
                .flat_map(|section| &section.rows)
                .map(|row| row.label.chars().count())
                .max()
                .unwrap_or(0);

            let paint = |style: Style, text: &str| {
                if styled {
                    format!("{style}{text}{style:#}")
                } else {
                    text.to_string()
                }
            };
            let bold = Style::new().bold();
            let dim = Style::new().dimmed();

            let mut out = String::new();
            for section in &self.sections {
                out.push_str(&paint(bold, &section.title));
                out.push('\n');
                for row in &section.rows {
                    let label = format!("{:width$}", row.label, width = width);
                    let label = if row.health == Health::Info {
                        paint(dim, &label)
                    } else {
                        label
                    };
                    out.push_str(&format!(
                        "  {}  {}  {}\n",
                        paint(row.health.style(), row.health.word()),
                        label,
                        row.detail
                    ));
                    if let Some(note) = &row.note {
                        // Indented under the row it belongs to, and dimmed so
                        // the findings stay the thing the eye lands on.
                        out.push_str(&format!(
                            "  {:4}  {:width$}  {}\n",
                            "",
                            "",
                            paint(dim, note),
                            width = width
                        ));
                    }
                }
                out.push('\n');
            }

            if self.has_checks() {
                let worst = self.worst();
                out.push_str(&paint(worst.style(), &self.summary()));
                out.push('\n');
            } else {
                // Trim the blank line the last section left behind.
                while out.ends_with("\n\n") {
                    out.pop();
                }
            }
            out
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use super::*;

        fn sample() -> Report {
            let mut report = Report::new();
            let mut storage = Section::new("storage");
            storage.push(Row::new(Health::Good, "state", "/var/lib/tsunagi"));
            storage.push(
                Row::new(Health::Degraded, "cache directory", "not writable")
                    .with_note("disposable; the agent runs without it"),
            );
            report.push(storage);
            let mut plane = Section::new("data plane");
            plane.push(Row::new(Health::Broken, "/dev/net/tun", "missing"));
            report.push(plane);
            report
        }

        /// Drops every CSI sequence, so a styled render can be compared with
        /// a plain one.
        fn strip(text: &str) -> String {
            let mut out = String::new();
            let mut chars = text.chars();
            while let Some(ch) = chars.next() {
                if ch == '\u{1b}' {
                    for ch in chars.by_ref() {
                        if ch == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(ch);
                }
            }
            out
        }

        #[test]
        fn an_unstyled_report_carries_no_escape_sequences() {
            // Colour must never be the only signal: this is what lands in a
            // file, a pipe, or a terminal that cannot do colour.
            let text = sample().render(false);
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(text.contains("ok  "));
            assert!(text.contains("warn"));
            assert!(text.contains("FAIL"));
        }

        #[test]
        fn a_styled_report_says_the_same_thing_with_escapes_added() {
            let styled = sample().render(true);
            assert!(styled.contains('\u{1b}'));
            assert_eq!(strip(&styled), sample().render(false));
        }

        #[test]
        fn the_detail_column_starts_at_the_same_offset_on_every_row() {
            // Labels differ in length across sections, so the padding has to
            // be computed over the whole report rather than per section.
            let mut report = Report::new();
            let mut short = Section::new("short labels");
            short.push(Row::new(Health::Good, "a", "detail-one"));
            report.push(short);
            let mut long = Section::new("long labels");
            long.push(Row::new(
                Health::Broken,
                "a-much-longer-label",
                "detail-two",
            ));
            report.push(long);

            let text = report.render(false);
            let offsets: Vec<usize> = ["detail-one", "detail-two"]
                .iter()
                .map(|detail| {
                    let line = text
                        .lines()
                        .find(|line| line.contains(detail))
                        .unwrap_or_else(|| panic!("no row for {detail} in:\n{text}"));
                    line.find(detail).unwrap()
                })
                .collect();
            assert_eq!(offsets[0], offsets[1], "misaligned:\n{text}");
        }

        #[test]
        fn the_summary_names_the_worst_thing_found() {
            assert_eq!(sample().worst(), Health::Broken);
            assert!(
                sample()
                    .render(false)
                    .contains("1 check degraded, 1 check broken")
            );

            let mut clean = Report::new();
            let mut section = Section::new("storage");
            section.push(Row::new(Health::Good, "state", "fine"));
            clean.push(section);
            assert_eq!(clean.worst(), Health::Good);
            assert!(clean.render(false).contains("everything checked out"));
        }

        #[test]
        fn a_report_of_plain_facts_claims_nothing_at_the_end() {
            // `tsunagi id` reports identifiers, not checks. Summarising them
            // as fine would assert something that was never tested.
            let mut report = Report::new();
            let mut section = Section::new("device");
            section.push(Row::new(Health::Info, "endpoint id", "abc123"));
            report.push(section);

            let text = report.render(false);
            assert!(!text.contains("everything checked out"), "{text:?}");
            assert!(!text.contains("degraded") && !text.contains("broken"));
            assert!(text.ends_with("abc123\n"), "{text:?}");
        }

        #[test]
        fn an_empty_section_is_left_out_rather_than_printed_bare() {
            let mut report = Report::new();
            report.push(Section::new("nothing here"));
            assert!(!report.render(false).contains("nothing here"));
        }
    }
}

/// The user this process is running as, for an instruction it can paste.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "<your-user>".to_string())
}

/// This program's path, for an instruction the user can paste.
fn program_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_string))
        .unwrap_or_else(|| "tsunagi".to_string())
}

async fn netwatch_addresses() -> Vec<std::net::IpAddr> {
    // Best effort; used for diagnostics only.
    let state = netwatch::interfaces::State::new().await;
    let mut addresses = state.local_addresses.regular;
    addresses.sort();
    addresses.dedup();
    addresses
}

async fn up(args: UpArgs) -> Result<(), Box<dyn std::error::Error>> {
    let name = NetworkName::new(args.network.clone())?;
    let secret = load_secret(args.secret.as_deref(), args.secret_file.as_deref())?;
    let paths = args.paths.resolve()?;

    // Parsed up front so a typo is reported immediately, and so the option is
    // never silently ignored when the data plane is off.
    let ipv4_range = resolve_ipv4_range(args.ipv4_range.as_ref())?;

    let mut bootstrap: Vec<EndpointAddr> = Vec::new();
    for peer in &args.peers {
        bootstrap.push(parse_peer(peer)?);
    }
    let discovery: Arc<dyn NetworkDiscovery> =
        Arc::new(CompositeDiscovery::new([
            Arc::new(StaticBootstrap::new(bootstrap)) as Arc<dyn NetworkDiscovery>,
        ]));

    let mut config = AgentConfig::new(paths.clone())
        .with_overlay_ipv4_range(ipv4_range)
        .with_transport(args.reach.into())
        .with_discovery(discovery)
        .with_discovery_interval(Duration::from_secs(5));
    if let Some(hostname) = &args.hostname {
        config = config.with_hostname(hostname.clone());
    }
    if !args.binds.is_empty() {
        config = config.with_bind_addrs(args.binds.clone());
    }

    // What the user asked for is checked first, before anything that could
    // fail for a reason of its own: a misspelled protocol or setting is
    // their mistake to see, not something to bury under a privilege error.
    let wanted: Vec<&ProtocolSpec> = {
        let mut wanted = Vec::new();
        for name in args
            .protocols
            .iter()
            .filter(|name| !name.eq_ignore_ascii_case("none"))
        {
            let Some(spec) = PROTOCOLS.iter().find(|spec| spec.name == name.as_str()) else {
                let known: Vec<&str> = PROTOCOLS.iter().map(|spec| spec.name).collect();
                return Err(format!(
                    "this build has no protocol called `{name}`; it has {}. \
                     Run `tsunagi protocols` to see what each one takes.",
                    known.join(", ")
                )
                .into());
            };
            wanted.push(spec);
        }
        wanted
    };

    let settings = parse_settings(&args.protocol_options)?;
    // A setting nobody takes is a mistake, not a preference: one that was
    // silently dropped looks exactly like one that did not work.
    for setting in &settings {
        if !wanted
            .iter()
            .any(|spec| !settings_for(spec, std::slice::from_ref(setting)).is_empty())
        {
            return Err(format!(
                "no selected protocol takes `{}`; run `tsunagi protocols` to see what they do",
                setting.key
            )
            .into());
        }
    }

    // The interface belongs to the agent, so it is configured once whatever
    // was selected to carry traffic over it.
    let mut wireguard = None;
    if !wanted.is_empty() {
        let tun_factory: Arc<dyn TunFactory> = if args.no_tun {
            Arc::new(MemoryTunFactory::new())
        } else {
            system_tun_factory()?
        };
        let mtu = args.mtu.unwrap_or(tsunagi_wg_quic::DEFAULT_MTU);
        config = config.with_interface(tun_factory, args.interface.clone(), mtu);
    }

    for spec in &wanted {
        let options = settings_for(spec, &settings);
        match spec.name {
            tsunagi_wg_quic::WIREGUARD_PROTOCOL => {
                let mut wg = WireguardConfig::new(paths.state_dir.join("wg-quic"));
                if let Some(mtu) = args.mtu {
                    wg = wg.with_mtu(mtu);
                }
                let wg = WireguardPlugin::configure(wg, &options)?;
                let plugin = WireguardPlugin::open(wg).await?;
                config = config.with_plugin(plugin.clone() as Arc<dyn IpPlugin>);
                wireguard = Some(plugin);
            }
            other => return Err(format!("`{other}` is listed but not built in").into()),
        }
    }

    let agent = Agent::spawn(config).await?;
    // From here on every exit goes through `agent.shutdown()`, so the endpoint
    // is never dropped without being closed.
    let mut events = agent.subscribe();
    let network = match agent.join_network(&name, &secret).await {
        Ok(network) => network,
        Err(err) => {
            agent.shutdown().await;
            return Err(err.into());
        }
    };

    println!("tsunagi is up");
    println!("  endpoint id  {}", agent.endpoint_id());
    println!("  hostname     {}", agent.hostname());
    println!("  network      {name} ({network})");
    println!("  state        {}", paths.state_dir.display());
    if args.peers.is_empty() {
        println!(
            "\nNo --peer was given, so this agent waits to be contacted.\n\
             On the other machine run:\n\n  tsunagi up --network {name} --secret <secret> \\\n    --peer {}\n",
            agent.endpoint_id()
        );
    }
    // A local resolver for this network's members. The zone name is the
    // user's to choose; a name that shadows a public one is reported and
    // then used, because that is a decision and not a mistake.
    let dns = if args.dns {
        let raw = args.dns_zone.clone().unwrap_or_else(|| name.to_string());
        match tsunagi::dns::ZoneName::new(&raw) {
            Ok(zone) => {
                if let Some(warning) = zone.collision() {
                    tracing::warn!("{warning}");
                }
                println!("  dns zone     {}", zone.as_str());
                Some(spawn_dns(agent.clone(), network, zone, args.dns_port))
            }
            Err(err) => {
                agent.shutdown().await;
                return Err(format!("--dns-zone {raw}: {err}").into());
            }
        }
    } else {
        None
    };

    // Serve `tsunagi status` for as long as this agent runs. Failing to bind
    // is not fatal: the agent itself works fine without it.
    let control = {
        let agent = agent.clone();
        let plugin = wireguard.clone();
        let dns = dns.as_ref().map(|service| Arc::clone(&service.state));
        let source: Arc<dyn tsunagi::ipc::unix::ReportSource> =
            Arc::new(AgentControl { agent, plugin, dns });
        let path = control_socket(&paths, args.control_socket.as_ref());
        match tsunagi::ipc::unix::ControlSocket::bind(path, source).await {
            Ok(socket) => {
                println!("  control      {}", socket.path().display());
                Some(socket)
            }
            Err(err) => {
                eprintln!("warning: `tsunagi status` will not work: {err}");
                None
            }
        }
    };

    println!("Press Ctrl-C to stop.\n");

    let status_every =
        (args.status_interval > 0).then(|| Duration::from_secs(args.status_interval));
    let mut ticker = status_every.map(tokio::time::interval);

    loop {
        tokio::select! {
            reason = stop_signal() => {
                println!("\nstopping ({reason})...");
                break;
            }
            event = events.recv() => match event {
                Ok(event) => print_event(&event),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    println!("  (missed {skipped} events)");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            _ = async {
                match ticker.as_mut() {
                    Some(ticker) => { ticker.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            }, if ticker.is_some() => {
                print_status(&agent, network, wireguard.as_deref()).await;
            }
        }
    }

    if let Some(control) = control {
        control.shutdown().await;
    }
    // Before the agent, so the resolver stops being pointed at a server
    // that is about to stop answering.
    if let Some(dns) = dns {
        dns.shutdown().await;
    }
    agent.shutdown().await;
    println!("stopped.");
    Ok(())
}

/// Collects a status report from the agent and, when present, the WireGuard
/// plugin. The two are combined here because only this binary knows about
/// both.
async fn build_report(
    agent: &Agent,
    wireguard: Option<&WireguardPlugin>,
    dns: Option<DnsState>,
) -> tsunagi::ipc::StatusReport {
    use tsunagi::ipc::{
        DnsReport, MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport,
        StatusReport,
    };

    let overlay = agent.overlay();
    let dns = dns.map(|dns| DnsReport {
        zone: dns.zone,
        listening: dns.listening.map(|address| address.to_string()),
        bind_error: dns.bind_error,
        publish_error: dns.publish_error,
        publish_remedy: dns.publish_remedy,
        zone_warning: dns.zone_warning,
        names: dns.names,
    });

    let Ok(status) = agent.status().await else {
        return StatusReport::default();
    };

    let networks = status
        .networks
        .iter()
        .map(|network| {
            let overlay = wireguard
                .and_then(|plugin| plugin.overview(network.network_id))
                .map(|view| OverlayReport {
                    interface: overlay
                        .as_ref()
                        .map_or_else(String::new, |overlay| overlay.interface.clone()),
                    mtu: overlay.as_ref().map_or(0, |overlay| overlay.mtu),
                    address: view.overlay_address_v4.map(|addr| addr.to_string()),
                    prefix_len: view.ipv4_range.map_or(0, |range| range.prefix_len),
                    peers: view
                        .peers
                        .iter()
                        .map(|peer| OverlayPeerReport {
                            endpoint_id: peer.endpoint_id.to_string(),
                            public_key: peer.public_key.to_string(),
                            address: peer.overlay_address_v4.map(|addr| addr.to_string()),
                            handshake_secs_ago: peer
                                .tunnel
                                .as_ref()
                                .and_then(|tunnel| tunnel.health.since_handshake)
                                .map(|since| since.as_secs()),
                            tx_packets: peer
                                .tunnel
                                .as_ref()
                                .map_or(0, |tunnel| tunnel.stats.tx_packets),
                            rx_packets: peer
                                .tunnel
                                .as_ref()
                                .map_or(0, |tunnel| tunnel.stats.rx_packets),
                            dropped: peer.tunnel.as_ref().map_or(0, |tunnel| {
                                tunnel.stats.dropped_wrong_source + tunnel.stats.dropped_oversize
                            }),
                            protocol_errors: peer
                                .tunnel
                                .as_ref()
                                .map_or(0, |tunnel| tunnel.stats.protocol_errors),
                            path: peer
                                .tunnel
                                .as_ref()
                                .map(|tunnel| tunnel.path.clone())
                                .unwrap_or_else(|| "no data link".into()),
                        })
                        .collect(),
                    // The interface belongs to the agent, so the counters
                    // about it come from there and are the same for every
                    // network sharing it.
                    unroutable_packets: overlay
                        .as_ref()
                        .map_or(0, |overlay| overlay.counters.unroutable),
                    multicast_packets: overlay
                        .as_ref()
                        .map_or(0, |overlay| overlay.counters.multicast),
                    unroutable_sample: overlay.as_ref().and_then(|overlay| {
                        overlay
                            .counters
                            .unroutable_sample
                            .map(|address| address.to_string())
                    }),
                });

            NetworkReport {
                name: network.name.to_string(),
                network_id: network.network_id.to_string(),
                active: matches!(network.state, tsunagi::agent::NetworkState::Active),
                peers: network
                    .peers
                    .iter()
                    .map(|peer| PeerReport {
                        endpoint_id: peer.endpoint_id.to_string(),
                        hostname: peer.hostname.clone(),
                        transport: peer.transport.to_string(),
                        rtt_ms: peer.rtt.map(|rtt| rtt.as_millis() as u64),
                    })
                    .collect(),
                members: network
                    .members
                    .iter()
                    .map(|member| MemberReport {
                        endpoint_id: member.endpoint_id.to_string(),
                        overlay_address_v4: member.overlay_address_v4.map(|addr| addr.to_string()),
                        // What this agent is currently experiencing trying to
                        // reach it, so a dial-failure count can be attributed
                        // to the member it belongs to instead of floating
                        // free as a network-wide number.
                        failed_dials: network
                            .candidates
                            .iter()
                            .find(|candidate| candidate.endpoint_id == member.endpoint_id)
                            .map_or(0, |candidate| candidate.consecutive_failures),
                    })
                    .collect(),
                range: network.range.map(|range| range.to_string()),
                range_conflict: network.range_conflict.map(|range| range.to_string()),
                dial_failures: network.metrics.dial_failures,
                handshake_failures: network.metrics.handshake_failures,
                control_messages: (
                    network.metrics.control_messages_sent,
                    network.metrics.control_messages_received,
                ),
                overlay,
            }
        })
        .collect();

    StatusReport {
        endpoint_id: status.endpoint_id.to_string(),
        hostname: status.hostname.clone(),
        bound_sockets: status
            .bound_sockets
            .iter()
            .map(ToString::to_string)
            .collect(),
        cache_healthy: status.cache_healthy,
        networks,
        dns,
    }
}

/// Resolves when the process is asked to stop.
///
/// Both Ctrl-C and `SIGTERM` are handled, so a service manager stopping the
/// agent gets the same clean shutdown an interactive user does.
async fn stop_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("cannot listen for SIGTERM: {err}");
                let _ = tokio::signal::ctrl_c().await;
                return "interrupted";
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "interrupted",
            _ = terminate.recv() => "terminated",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "interrupted"
    }
}

/// Builds the interface factory.
///
/// One path: the agent creates and configures the interface itself. It is
/// also the one that cleans up after itself, because the interface is tied to
/// an open file descriptor and goes away with the agent, however the agent
/// goes away.
#[cfg(target_os = "linux")]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    use tsunagi::overlay::{ManagedTunFactory, NetlinkProvisioner};
    let provisioner = NetlinkProvisioner::new()?;
    Ok(Arc::new(ManagedTunFactory::new(Arc::new(provisioner))))
}

/// There is no provisioner for this platform yet.
///
/// Refused here rather than at the first packet, and with the one thing that
/// does work on every platform named.
#[cfg(not(target_os = "linux"))]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    Err(format!(
        "managing the overlay interface is not implemented on {} yet. \
         Run with `--no-tun` to keep the tunnels off the operating system.",
        std::env::consts::OS
    )
    .into())
}

fn print_event(event: &Event) {
    match event {
        Event::PeerConnected {
            peer,
            transport,
            rtt,
            ..
        } => println!(
            "  + peer {} connected over {transport:?} rtt={rtt:?}",
            peer.fmt_short()
        ),
        Event::PeerDisconnected { peer, reason, .. } => {
            println!("  - peer {} gone: {reason}", peer.fmt_short())
        }
        Event::DataLinkUp {
            peer,
            protocol,
            path,
            max_datagram,
            ..
        } => println!(
            "  + data link to {} for {protocol}: {path}, datagram {max_datagram}",
            peer.fmt_short()
        ),
        Event::DataLinkDown {
            peer,
            protocol,
            reason,
            ..
        } => println!(
            "  - data link to {} for {protocol}: {reason}",
            peer.fmt_short()
        ),
        Event::HandshakeRejected { peer, reason, .. } => println!(
            "  ! rejected {}: {reason}",
            peer.map(|peer| peer.fmt_short().to_string())
                .unwrap_or_else(|| "a caller".into())
        ),
        Event::PluginError {
            protocol, reason, ..
        } => println!("  ! {protocol}: {reason}"),
        Event::CacheReset { reason } => println!("  ! cache was reset: {reason}"),
        _ => {}
    }
}

async fn print_status(agent: &Agent, network: NetworkId, wireguard: Option<&WireguardPlugin>) {
    let Ok(status) = agent.network_status(network).await else {
        return;
    };
    println!("\n--- status ---");
    println!(
        "control: {} peer(s), {} dial failure(s), {} handshake failure(s)",
        status.peers.len(),
        status.metrics.dial_failures,
        status.metrics.handshake_failures
    );
    for peer in &status.peers {
        println!(
            "  {} {} {:?} rtt={:?}",
            peer.endpoint_id.fmt_short(),
            peer.hostname.as_deref().unwrap_or("?"),
            peer.transport,
            peer.rtt
        );
    }

    if let Some(plugin) = wireguard
        && let Some(view) = plugin.overview(network)
    {
        println!(
            "{}: {} on {}/{} mtu {}, {}/{} tunnel(s) established",
            plugin.protocol_id(),
            agent
                .overlay()
                .map_or_else(|| "no interface".to_string(), |overlay| overlay.interface),
            view.overlay_address_v4
                .map_or_else(|| "no address yet".to_string(), |addr| addr.to_string()),
            view.ipv4_range.map_or(0, |range| range.prefix_len),
            view.mtu,
            view.established_peers(),
            view.peers.len()
        );
        for peer in &view.peers {
            match &peer.tunnel {
                Some(tunnel) => println!(
                    "  {} {} {} tx={} rx={} dropped={} path={}",
                    peer.public_key.fmt_short(),
                    peer.overlay_address_v4
                        .map_or_else(|| "no address".to_string(), |addr| addr.to_string()),
                    match tunnel.health.since_handshake {
                        Some(since) => format!("handshake {}s ago", since.as_secs()),
                        None => "NOT HANDSHAKEN".to_string(),
                    },
                    tunnel.stats.tx_packets,
                    tunnel.stats.rx_packets,
                    tunnel.stats.dropped_wrong_source + tunnel.stats.dropped_oversize,
                    tunnel.path
                ),
                None => println!(
                    "  {} {} waiting for a data link",
                    peer.public_key.fmt_short(),
                    peer.overlay_address_v4
                        .map_or_else(|| "no address".to_string(), |addr| addr.to_string())
                ),
            }
        }
    }
    if let Some(overlay) = agent.overlay()
        && overlay.counters.unroutable > 0
    {
        println!(
            "  {} packet(s) for unknown addresses{}",
            overlay.counters.unroutable,
            match overlay.counters.unroutable_sample {
                Some(sample) => format!(" (for example {sample})"),
                None => String::new(),
            }
        );
    }
    println!();
}

#[cfg(test)]
mod status_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::report::Health;
    use super::*;
    use tsunagi::ipc::{MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport};

    const OWN: &str = "aaaa0000";
    const ONLINE: &str = "bbbb1111";
    const AWAY: &str = "cccc2222";

    fn overlay(peers: Vec<OverlayPeerReport>) -> OverlayReport {
        OverlayReport {
            interface: "tsundemo".into(),
            mtu: 1280,
            address: Some("10.13.37.69".into()),
            prefix_len: 24,
            peers,
            ..Default::default()
        }
    }

    fn tunnel(endpoint_id: &str, handshake: Option<u64>) -> OverlayPeerReport {
        OverlayPeerReport {
            endpoint_id: endpoint_id.into(),
            public_key: "keykeykey".into(),
            address: Some("10.13.37.237".into()),
            handshake_secs_ago: handshake,
            tx_packets: 32,
            rx_packets: 887,
            path: "direct via 192.0.2.1:50303".into(),
            ..Default::default()
        }
    }

    /// The situation that prompted this: one peer left and came back.
    fn network_after_a_peer_returned() -> NetworkReport {
        NetworkReport {
            name: "LAB".into(),
            network_id: "xa7gyz".into(),
            active: true,
            peers: vec![PeerReport {
                endpoint_id: ONLINE.into(),
                hostname: Some("music".into()),
                transport: "direct".into(),
                rtt_ms: Some(24),
            }],
            members: vec![
                MemberReport {
                    endpoint_id: OWN.into(),
                    overlay_address_v4: Some("10.13.37.69".into()),
                    failed_dials: 0,
                },
                MemberReport {
                    endpoint_id: ONLINE.into(),
                    overlay_address_v4: Some("10.13.37.237".into()),
                    failed_dials: 0,
                },
            ],
            range: Some("10.13.37.0/24".into()),
            range_conflict: None,
            // Everything below happened while the peer was away.
            dial_failures: 9,
            handshake_failures: 0,
            control_messages: (2, 2),
            overlay: Some(OverlayReport {
                unroutable_packets: 1,
                unroutable_sample: Some("10.13.37.237".into()),
                ..overlay(vec![tunnel(ONLINE, Some(29))])
            }),
        }
    }

    #[test]
    fn two_networks_with_one_name_are_told_apart_and_flagged() {
        // The confusing case: two sections headed identically, one working
        // and one empty, read as a single network that is somehow both.
        let network = network_after_a_peer_returned();
        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, true));
        let text = out.render(false);

        assert!(
            text.contains(&format!("network LAB ({})", short(&network.network_id, 10))),
            "the heading must identify the network, not just name it:\n{text}"
        );
        assert!(text.contains("also called `LAB`"), "{text}");
        assert!(text.contains("mistyped secret"), "{text}");
    }

    #[test]
    fn a_network_with_no_range_says_that_is_why_it_is_empty() {
        // Rather than "nobody else has joined", which points at the wrong
        // thing entirely: nobody can join a network with no addresses.
        let mut network = network_after_a_peer_returned();
        network.peers.clear();
        network.members.clear();
        network.overlay = None;
        network.range = None;
        network.range_conflict = Some("10.13.37.0/24".into());

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert!(text.contains("no range to allocate from"), "{text}");
        assert!(text.contains("another network here already does"), "{text}");
        assert!(text.contains("--ipv4-range"), "the fix is named: {text}");
    }

    #[test]
    fn counters_from_the_past_do_not_grade_the_present() {
        // A peer that left and returned leaves dial failures and a packet
        // sent to an address nobody owned behind it. Once it is back, those
        // are history: reporting them as current faults made a working
        // network look broken.
        let network = network_after_a_peer_returned();
        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));

        assert_eq!(out.worst(), Health::Good, "{}", out.render(false));
        let text = out.render(false);
        assert!(text.contains("since start"), "{text}");
        assert!(
            text.contains("9 dial failure(s)"),
            "the history is still shown: {text}"
        );
    }

    #[test]
    fn this_agent_is_not_listed_among_its_own_peers() {
        let network = network_after_a_peer_returned();
        let rows = member_rows(&network, OWN);
        assert_eq!(rows.len(), 1, "only the other member");
        assert_eq!(rows[0].endpoint_id, ONLINE);
    }

    #[test]
    fn offline_members_are_listed_after_online_ones() {
        let mut network = network_after_a_peer_returned();
        network.members.push(MemberReport {
            endpoint_id: AWAY.into(),
            overlay_address_v4: Some("10.13.37.99".into()),
            failed_dials: 9,
        });

        let rows = member_rows(&network, OWN);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].online(), "the connected member comes first");
        assert!(!rows[1].online());
        assert_eq!(rows[1].endpoint_id, AWAY);
    }

    #[test]
    fn a_member_that_is_away_is_stated_rather_than_flagged() {
        // In a mesh of laptops a member being away is the ordinary
        // condition, not a fault of this agent. It is said plainly, with
        // what the signed state still knows about it, and the failed dials
        // are attributed to it instead of floating free as a counter.
        let mut network = network_after_a_peer_returned();
        network.members.push(MemberReport {
            endpoint_id: AWAY.into(),
            overlay_address_v4: Some("10.13.37.99".into()),
            failed_dials: 9,
        });

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);

        assert_eq!(out.worst(), Health::Good, "{text}");
        assert!(text.contains("offline"), "{text}");
        assert!(text.contains("10.13.37.99 still reserved for it"), "{text}");
        assert!(text.contains("9 dial attempt(s) failed"), "{text}");
        assert!(text.contains("1 of 2 online"), "{text}");
    }

    #[test]
    fn a_relayed_peer_is_graded_as_degraded_quality() {
        let mut network = network_after_a_peer_returned();
        network.peers[0].transport = "relay".into();

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        assert_eq!(out.worst(), Health::Degraded, "{}", out.render(false));
        assert!(out.render(false).contains("relay"));
    }

    #[test]
    fn a_tunnel_that_never_handshook_is_flagged_while_the_peer_is_connected() {
        let mut network = network_after_a_peer_returned();
        network.overlay = Some(overlay(vec![tunnel(ONLINE, None)]));

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert_eq!(out.worst(), Health::Degraded, "{text}");
        assert!(text.contains("no WireGuard handshake yet"), "{text}");
    }

    #[test]
    fn handshake_failures_with_nobody_connected_point_at_the_secret() {
        // The classic symptom of one member being given a different secret.
        // With a peer connected the same counter is just history.
        let mut network = network_after_a_peer_returned();
        network.peers.clear();
        network.overlay = Some(overlay(Vec::new()));
        network.handshake_failures = 4;

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert_eq!(out.worst(), Health::Degraded, "{text}");
        assert!(text.contains("same secret"), "{text}");
    }
}

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
    /// Shows this device's identity, and changes it.
    ///
    /// Every item follows the same shape: name it to see it, name it with a
    /// value to change it.
    Id(IdArgs),
    /// Runs the agent until interrupted: the device's one process.
    ///
    /// It serves every network this device has joined, answers `status`,
    /// and is what `join`, `leave`, `stop` and `dns` talk to. Which
    /// networks it is in is decided separately, and can change while it
    /// runs.
    // Boxed: it is much larger than the other variants, and every command
    // but this one would otherwise pay for its size. A `//` comment, not a
    // `///` one, or clap would print it as help.
    Up(Box<UpArgs>),
    /// Reports this device, what the agent is doing, and what this host can do.
    Status(StatusArgs),
    /// Shows the protocols this build can carry packets with.
    Protocols,
    /// Makes a network, or joins one — the command that does the work.
    ///
    /// The same as `tsunagi network join`, at the top level because it is
    /// what gets typed: `up` runs the agent, this decides what it is in.
    Join(JoinArgs),
    /// Shows the networks this device belongs to, and leaves them.
    Network(NetworkArgs),
    /// Shows the local resolver, and turns it on or off.
    Dns(DnsArgs),
    /// Removes everything this device has stored and starts over.
    Wipe(WipeArgs),
}

#[derive(Debug, Args)]
struct DnsArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long, global = true)]
    control_socket: Option<PathBuf>,

    #[command(subcommand)]
    action: Option<DnsAction>,
}

#[derive(Debug, Subcommand)]
enum DnsAction {
    /// Starts serving, now and after every restart.
    On {
        /// Port to listen on, on loopback of both families.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
    },
    /// Stops serving, now and after every restart.
    Off,
}

#[derive(Debug, Args)]
struct NetworkArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long, global = true)]
    control_socket: Option<PathBuf>,

    #[command(subcommand)]
    action: Option<NetworkAction>,
}

/// Making or joining one network.
///
/// The name alone is enough: this device's network of that name if it has
/// one, and otherwise a new network with a secret invented here and printed
/// so it can be passed on.
#[derive(Debug, Args)]
struct JoinArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long)]
    control_socket: Option<PathBuf>,

    /// Network name. Must be identical on every participant.
    #[arg(long, short = 'n')]
    network: String,

    /// The shared secret, as printed when a network is made.
    #[arg(long, short = 's', env = "TSUNAGI_SECRET")]
    secret: Option<String>,

    /// Read the shared secret from a file instead of the command line.
    #[arg(long, conflicts_with = "secret")]
    secret_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum NetworkAction {
    /// Makes a network, or joins one, in the agent that is already running.
    ///
    /// The state directory belongs to one live agent, so this is how a
    /// network is added to it, and it takes effect at once. With no agent
    /// running it is configured and starts with the next `tsunagi up`.
    /// `tsunagi join` is the same command, spelled shorter.
    Join(JoinArgs),
    /// Stops serving a network, keeping everything so it can be resumed.
    ///
    /// Not leaving: the configuration, the secret, the address and the
    /// signed state all stay. Sessions close and the address comes off the
    /// interface, and nothing is announced — to the others this device is
    /// simply away, as if it had been switched off. It stays stopped
    /// across restarts until `tsunagi network start`.
    Stop {
        /// Which network, by id. A unique prefix is enough.
        network: String,
    },
    /// Serves a stopped network again, from where it left off.
    Start {
        /// Which network, by id. A unique prefix is enough.
        network: String,
    },
    /// Gives up this device's address and name in a network, and forgets it.
    ///
    /// A signed release goes out first, so the address and name are freed
    /// for the others rather than staying reserved to a member that has
    /// gone. That needs the agent running; without it nothing can be sent.
    ///
    /// Everything local goes: the configuration, the secret, this
    /// network's signed records, its cached hints and the protocol key it
    /// used. `stop` is the one that keeps them.
    Leave {
        /// Which network, by id. A unique prefix is enough; the name is not,
        /// because two networks may share one.
        network: String,

        /// Remove it without telling anybody.
        ///
        /// For a network nobody else is in, or one joined with a mistyped
        /// secret. The others keep whatever this device claimed.
        #[arg(long)]
        offline: bool,
    },
    /// Shows the secret of a network, which is half of its identity.
    ///
    /// Printed only when asked for, never as part of an overview: these
    /// reports get pasted into chats and issue trackers.
    Secret {
        /// Which network, by id; a unique prefix is enough. All of them if
        /// omitted.
        network: Option<String>,

        #[command(subcommand)]
        action: Option<SecretAction>,
    },
}

#[derive(Debug, Subcommand)]
enum SecretAction {
    /// Prints a fresh random secret, for a network that does not exist yet.
    Generate,
}

#[derive(Debug, Args)]
struct WipeArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to check for a running agent.
    #[arg(long)]
    control_socket: Option<PathBuf>,

    /// Actually remove it. Without this the command only says what it would.
    #[arg(long)]
    yes: bool,
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

    /// Serve a local DNS zone for every network this device is in.
    ///
    /// Each network becomes a zone named after it, and its members resolve
    /// as `<hostname>.<network>` from signed state, so a member that is
    /// switched off still resolves. Answers are the overlay's IPv4
    /// addresses; questions are taken on loopback of both families, over
    /// UDP and TCP.
    ///
    /// Remembered: once on it stays on, and `tsunagi dns off` turns it off.
    #[arg(long, help_heading = "System")]
    dns: bool,

    /// Port for the local DNS server, on loopback of both families.
    ///
    /// Remembered with the setting, so it needs giving only when changing.
    #[arg(long, value_name = "PORT", help_heading = "System")]
    dns_port: Option<u16>,

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

/// Port the local resolver listens on unless told otherwise.
///
/// On Windows the default is 53, because the Windows DNS client only ever asks
/// on 53 and cannot be pointed at another port — a resolver on anything else
/// cannot be wired into the system at all. This is the same choice Tailscale
/// makes: a fixed, system-usable port plus an NRPT rule for the network's
/// suffix. An explicit `--dns-port` still wins (so two agents on one host, and
/// the tests, can each take a port of their own); this only decides what a
/// plain `--dns` picks. Elsewhere the default is a high port that needs no
/// privilege, since systemd-resolved can be pointed at any port.
const DEFAULT_DNS_PORT: u16 = if cfg!(target_os = "windows") { 53 } else { 5354 };

/// Settings key: whether the local resolver is wanted.
const DNS_ENABLED: &str = "dns.enabled";
/// Settings key: which port it listens on.
const DNS_PORT: &str = "dns.port";

/// Whether the local resolver is on, and on which port.
///
/// Stored with the device rather than passed on every start: a resolver
/// that quietly goes away when a command line is retyped is worse than no
/// resolver at all, because the names simply stop working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsSetting {
    enabled: bool,
    port: u16,
}

impl Default for DnsSetting {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_DNS_PORT,
        }
    }
}

/// Reads the stored resolver setting. Read-only, so it needs no lock.
fn dns_setting(paths: &StoragePaths) -> DnsSetting {
    let Ok(store) = tsunagi::storage::StateStore::open(paths.state_db()) else {
        return DnsSetting::default();
    };
    DnsSetting {
        enabled: matches!(
            store.get_setting(DNS_ENABLED).ok().flatten().as_deref(),
            Some("1")
        ),
        port: store
            .get_setting(DNS_PORT)
            .ok()
            .flatten()
            .and_then(|port| port.parse().ok())
            .unwrap_or(DEFAULT_DNS_PORT),
    }
}

/// Writes the resolver setting, for the next start and for this one.
fn store_dns_setting(
    paths: &StoragePaths,
    setting: DnsSetting,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = tsunagi::storage::StateStore::open(paths.state_db())?;
    store.set_setting(DNS_ENABLED, if setting.enabled { "1" } else { "0" })?;
    store.set_setting(DNS_PORT, &setting.port.to_string())?;
    Ok(())
}

/// What this device already knows about the network a command names.
///
/// Two things, and both are only knowable *before* joining: whether this
/// network was already configured here, and whether another one answers to
/// the same name. A name is a label and an id is the identity, so those two
/// are different networks that share nothing — almost always a mistyped
/// secret, and the one mistake that makes a report unreadable. Said at the
/// moment it happens, it is obvious; discovered later in a status report,
/// it is a mystery.
fn network_context(
    configured: &[tsunagi::storage::StoredNetwork],
    name: &NetworkName,
    network_id: tsunagi::NetworkId,
) -> (NetworkStanding, Option<String>) {
    let known = configured
        .iter()
        .find(|other| other.network_id == network_id)
        .map(|other| {
            if other.auto_start {
                NetworkStanding::Known
            } else {
                NetworkStanding::Stopped
            }
        })
        .unwrap_or(NetworkStanding::New);
    let shared = configured
        .iter()
        .find(|other| other.name == *name && other.network_id != network_id)
        .map(|other| other.network_id.to_string());
    (known, shared)
}

/// How a network the command line names stood before the command ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkStanding {
    /// Not configured here at all: this command makes it.
    New,
    /// Configured and meant to run.
    Known,
    /// Configured and deliberately stopped — which this command undoes,
    /// because a command line that names a network says to run it. Said
    /// out loud, or a `stop` quietly comes back at the next restart.
    Stopped,
}

/// Where the secret a command is about to use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretOrigin {
    /// Given on the command line, in a file or in the environment.
    Given,
    /// Read from the one network of that name this device already has.
    Stored,
    /// Invented here, because there was nothing to go on.
    Generated,
}

/// Works out which secret a network name means.
///
/// Three cases, and they are what make the name alone a usable command:
///
/// * given — use it, whatever is stored;
/// * not given and this device is already in exactly one network of that
///   name — that one, so `join --network lab` resumes rather than making a
///   stranger with the same name;
/// * not given and there is none — invent one, because an ad-hoc network is
///   a thing people want and "generate a secret first" is a step with no
///   purpose. The caller prints it: a secret nobody can read is no use.
///
/// Two networks of one name and no secret is the one case with no answer,
/// and it says so rather than choosing.
fn resolve_secret(
    paths: &StoragePaths,
    name: &NetworkName,
    secret: Option<&str>,
    secret_file: Option<&std::path::Path>,
) -> Result<(NetworkSecret, SecretOrigin), Box<dyn std::error::Error>> {
    if secret.is_some() || secret_file.is_some() {
        return Ok((load_secret(secret, secret_file)?, SecretOrigin::Given));
    }

    let known: Vec<tsunagi::storage::StoredNetwork> = stored_networks(paths)
        .into_iter()
        .filter(|network| network.name == *name)
        .collect();
    match known.as_slice() {
        [] => Ok((NetworkSecret::generate(), SecretOrigin::Generated)),
        [one] => Ok((one.secret.clone(), SecretOrigin::Stored)),
        several => Err(format!(
            "this device is in {} networks called `{name}`, so the name alone does not say \
             which. Give --secret, or `tsunagi network` lists them with their ids.",
            several.len()
        )
        .into()),
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
        Command::Join(args) => join_command(args).await,
        Command::Network(args) => network_command(args).await,
        Command::Dns(args) => dns_command(args).await,
        Command::Wipe(args) => wipe(args).await,
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
    let socket_present = tsunagi::ipc::is_serving(socket).await;
    let why = if socket_present {
        match tsunagi::ipc::request_status(socket).await {
            Ok(report) => return Observed::Agent(Box::new(report)),
            Err(err) => format!("{err}"),
        }
    } else {
        "no agent is serving this state directory".to_string()
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
/// secret must never appear. `tsunagi network secret` is the place that shows one,
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
    /// One zone per network, named after it.
    zones: Vec<String>,
    /// Anything worth saying about those names, one line each.
    zone_warnings: Vec<String>,
    listening: Vec<SocketAddr>,
    bind_error: Option<String>,
    publish_error: Option<String>,
    publish_remedy: Option<String>,
    names: u32,
}

/// The local DNS service: a server, and an attempt to tell the OS about it.
///
/// The two are deliberately independent. The server comes up whether or not
/// the resolver can be configured, because a resolver the user can point at
/// by hand is worth more than nothing, and the reason it was not configured
/// is reported rather than swallowed.
///
/// One service for the agent, not one per network: an agent has one
/// identity and as many networks as it likes, each of them a zone named
/// after it, and they all arrive at the same socket.
struct DnsService {
    state: Arc<std::sync::Mutex<DnsState>>,
    publisher: Arc<dyn tsunagi::dns::DnsPublisher>,
    port: u16,
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

/// What the control socket reports about the resolver.
fn dns_report(dns: DnsState) -> tsunagi::ipc::DnsReport {
    tsunagi::ipc::DnsReport {
        zones: dns.zones,
        listening: dns
            .listening
            .iter()
            .map(|address| address.to_string())
            .collect(),
        bind_error: dns.bind_error,
        publish_error: dns.publish_error,
        publish_remedy: dns.publish_remedy,
        zone_warnings: dns.zone_warnings,
        names: dns.names,
    }
}

/// Picks the publisher for this platform.
fn dns_publisher() -> Arc<dyn tsunagi::dns::DnsPublisher> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(tsunagi::dns::publish::ResolvedPublisher::new())
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(tsunagi::dns::publish::NrptPublisher::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Arc::new(tsunagi::dns::publish::UnsupportedPublisher::new())
    }
}

/// Starts the DNS service and keeps it in step with the agent's state.
///
/// Every network the agent is in becomes a zone named after it, so joining
/// or leaving one changes what resolves without restarting anything.
fn spawn_dns(agent: Agent, port: u16) -> DnsService {
    use tsunagi::dns::{DnsServer, SharedZone, Zone, ZoneName, Zones, listen_plan};

    let state = Arc::new(std::sync::Mutex::new(DnsState::default()));
    let publisher = dns_publisher();

    let task = {
        let state = Arc::clone(&state);
        let publisher = Arc::clone(&publisher);
        tokio::spawn(async move {
            let shared = SharedZone::default();
            // Held for their `Drop`, which stops each server: the values
            // are never read, but letting them go is what closes the
            // sockets. One per address family, so a question is answered
            // over whichever the resolver uses.
            let mut _servers: Vec<DnsServer> = Vec::new();
            let mut bound: Vec<SocketAddr> = Vec::new();
            let mut published: Option<tsunagi::dns::Published> = None;
            // A condition that persists is worth saying once, not every
            // pass; and a refusal will not lift without somebody acting, so
            // hammering at it two seconds apart is pure noise.
            let mut reported: Option<String> = None;
            let mut retry_after: Option<tokio::time::Instant> = None;
            let mut recipe_shown = false;
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));

            // The port does not change while the service runs; turning DNS
            // off and on again is what changes it, and that is a new
            // service. So this is bound once and kept.
            let wanted = listen_plan(port);
            let mut last: Option<std::io::Error> = None;
            for family in wanted.families() {
                for candidate in family {
                    match DnsServer::bind(*candidate, shared.clone()).await {
                        Ok(fresh) => {
                            tracing::info!(address = %fresh.local_addr(), "dns listening");
                            bound.push(fresh.local_addr());
                            _servers.push(fresh);
                            break;
                        }
                        Err(err) => last = Some(err),
                    }
                }
            }
            let bind_error = bound.is_empty().then(|| {
                last.map_or_else(
                    || "no address to listen on".to_string(),
                    |err| err.to_string(),
                )
            });
            {
                let listening = bound.clone();
                update(&state, |state| {
                    state.listening = listening;
                    state.bind_error = bind_error;
                });
            }

            loop {
                ticker.tick().await;
                let Ok(status) = agent.status().await else {
                    continue;
                };

                // One zone per network, named after it. A name that cannot
                // be a zone is said once and skipped: the network works,
                // it just has no names.
                let mut zones = Vec::new();
                let mut labels = Vec::new();
                let mut warnings = Vec::new();
                for network in &status.networks {
                    let zone = match ZoneName::new(network.name.as_str()) {
                        Ok(zone) => zone,
                        Err(err) => {
                            warnings.push(format!(
                                "`{}` cannot be a zone, so its members have no names: {err}",
                                network.name
                            ));
                            continue;
                        }
                    };
                    if let Some(warning) = zone.collision() {
                        warnings.push(warning);
                    }
                    labels.push(zone.as_str().to_string());
                    // Names come from signed state, so a member that is
                    // away is in here too.
                    let members = network.members.iter().filter_map(|member| {
                        Some((member.hostname.clone()?, member.overlay_address_v4?))
                    });
                    zones.push(Zone::new(zone, members));
                }
                let zones = Zones::new(zones);
                let names = zones.names() as u32;
                shared.set(zones);
                update(&state, |state| {
                    state.zones = labels.clone();
                    state.zone_warnings = warnings;
                    state.names = names;
                });

                if bound.is_empty() {
                    continue;
                }
                // The interface belongs to the agent, so the resolver
                // setting attaches to that one and not to a protocol's.
                // Only one that is really on the host: an in-memory
                // interface has a name and nothing else, and telling the
                // operating system about that name would configure
                // whatever else happens to be called it.
                let interface = agent
                    .overlay()
                    .filter(|overlay| overlay.on_host)
                    .map(|overlay| overlay.interface)
                    .filter(|name| !name.is_empty());
                let Some(interface) = interface else {
                    update(&state, |state| {
                        state.publish_error = Some(
                            "there is no overlay interface on this host to attach the resolver \
                             setting to"
                                .to_string(),
                        );
                        state.publish_remedy = None;
                    });
                    continue;
                };
                if labels.is_empty() {
                    // Nothing to route here yet. Whatever was published is
                    // now wrong, and saying nothing is the honest setting.
                    if published.take().is_some() {
                        let _ = publisher.revert().await;
                    }
                    continue;
                }

                let want_published = tsunagi::dns::Published {
                    interface,
                    servers: bound.clone(),
                    domains: labels.clone(),
                };
                let due = retry_after.is_none_or(|at| tokio::time::Instant::now() >= at);
                if published.as_ref() != Some(&want_published) && due {
                    match publisher.apply(&want_published).await {
                        Ok(()) => {
                            tracing::info!(
                                zones = %labels.join(", "),
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
            }
        })
    };

    DnsService {
        state,
        publisher,
        port,
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
    /// The resolver, which this owns so it can be switched while running.
    dns: Arc<tokio::sync::Mutex<Option<DnsService>>>,
    /// Where the setting is remembered, so it survives a restart.
    paths: StoragePaths,
}

impl tsunagi::ipc::ReportSource for AgentControl {
    fn report(&self) -> tsunagi::BoxFuture<'_, tsunagi::ipc::StatusReport> {
        Box::pin(async move {
            let dns = self.dns_state().await;
            build_report(&self.agent, self.plugin.as_deref(), dns).await
        })
    }

    fn set_dns(
        &self,
        enable: bool,
        port: Option<u16>,
    ) -> tsunagi::BoxFuture<'_, Result<Option<tsunagi::ipc::DnsReport>, String>> {
        Box::pin(async move {
            let mut service = self.dns.lock().await;
            let port = port
                .or_else(|| service.as_ref().map(|service| service.port))
                .unwrap_or_else(|| dns_setting(&self.paths).port);

            // Remembered first: what the agent is doing and what it will do
            // after a restart must not drift apart, and a failure to store
            // it is exactly the kind of drift.
            store_dns_setting(
                &self.paths,
                DnsSetting {
                    enabled: enable,
                    port,
                },
            )
            .map_err(|err| err.to_string())?;

            match (enable, service.take()) {
                // Already serving on that port: nothing to restart.
                (true, Some(running)) if running.port == port => {
                    *service = Some(running);
                }
                // A different port means a different socket.
                (true, previous) => {
                    if let Some(previous) = previous {
                        previous.shutdown().await;
                    }
                    *service = Some(spawn_dns(self.agent.clone(), port));
                }
                (false, Some(running)) => running.shutdown().await,
                (false, None) => {}
            }
            let handle = service.as_ref().map(|service| Arc::clone(&service.state));
            // The lock goes before the wait: nothing else should queue
            // behind a sleep, and the state is shared by an `Arc` anyway.
            drop(service);

            let state = match handle {
                // Freshly started: let it bind and collect a zone or two
                // before answering, so the report is the state and not a
                // snapshot of nothing.
                Some(state) => {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    Some(match state.lock() {
                        Ok(guard) => guard.clone(),
                        Err(poisoned) => poisoned.into_inner().clone(),
                    })
                }
                None => None,
            };
            Ok(state.map(dns_report))
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

    fn join(
        &self,
        name: String,
        secret: String,
    ) -> tsunagi::BoxFuture<'_, Result<tsunagi::ipc::JoinedReport, String>> {
        Box::pin(async move {
            let name = NetworkName::new(&name).map_err(|err| err.to_string())?;
            let secret = NetworkSecret::decode(&secret).map_err(|err| err.to_string())?;
            let keys = tsunagi::identity::NetworkKeys::derive(&name, &secret);

            // Read before joining: afterwards "already configured" is true
            // of everything, and the difference is what the user is told.
            let before = self
                .agent
                .list_networks()
                .await
                .map_err(|err| err.to_string())?;
            let already = before
                .iter()
                .any(|other| other.network_id == keys.network_id());
            let shared = before
                .iter()
                .find(|other| other.name == name && other.network_id != keys.network_id())
                .map(|other| other.network_id.to_string());

            let network_id = self
                .agent
                .join_network(&name, &secret)
                .await
                .map_err(|err| err.to_string())?;
            Ok(tsunagi::ipc::JoinedReport {
                name: name.as_str().to_string(),
                network_id: network_id.to_string(),
                already_configured: already,
                name_shared_with: shared,
            })
        })
    }

    fn set_active(
        &self,
        network_id: String,
        active: bool,
    ) -> tsunagi::BoxFuture<'_, Result<tsunagi::ipc::ActiveReport, String>> {
        Box::pin(async move {
            let wanted: tsunagi::NetworkId = network_id
                .parse()
                .map_err(|err| format!("`{network_id}` is not a network id: {err}"))?;
            let name = self
                .agent
                .list_networks()
                .await
                .map_err(|err| err.to_string())?
                .into_iter()
                .find(|network| network.network_id == wanted)
                .map(|network| network.name.as_str().to_string())
                .ok_or_else(|| format!("this agent is not in {wanted}"))?;

            let was = self.agent.is_active(wanted).await;
            if was != active {
                // Both of these also remember the answer, so a restart
                // does what the last instruction said.
                if active {
                    self.agent
                        .activate_network(wanted)
                        .await
                        .map_err(|err| err.to_string())?;
                } else {
                    self.agent
                        .deactivate_network(wanted)
                        .await
                        .map_err(|err| err.to_string())?;
                }
            }
            Ok(tsunagi::ipc::ActiveReport {
                name,
                active,
                changed: was != active,
            })
        })
    }

    fn leave(
        &self,
        network_id: String,
    ) -> tsunagi::BoxFuture<'_, Result<tsunagi::ipc::LeftReport, String>> {
        Box::pin(async move {
            let wanted: tsunagi::NetworkId = network_id
                .parse()
                .map_err(|err| format!("`{network_id}` is not a network id: {err}"))?;
            // The name is for the message the user reads, and it is only
            // available while the network is still configured.
            let name = self
                .agent
                .list_networks()
                .await
                .map_err(|err| err.to_string())?
                .into_iter()
                .find(|network| network.network_id == wanted)
                .map(|network| network.name.as_str().to_string())
                .ok_or_else(|| format!("this agent is not in {wanted}"))?;

            let outcome = self
                .agent
                .leave_network(wanted)
                .await
                .map_err(|err| err.to_string())?;
            Ok(tsunagi::ipc::LeftReport {
                name,
                announced: outcome.announced,
                peers_told: outcome.peers_told as u32,
            })
        })
    }
}

impl AgentControl {
    /// The resolver's state, when there is one.
    async fn dns_state(&self) -> Option<DnsState> {
        let service = self.dns.lock().await;
        service.as_ref().map(|service| match service.state.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
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

/// Finds the one configured network whose id starts with `wanted`.
///
/// A prefix, because the ids are 52 characters and `status` prints them
/// shortened; the name is deliberately not accepted, since two networks can
/// share one and choosing for the user is how the wrong network gets left.
fn resolve_network<'a>(
    networks: &'a [tsunagi::storage::StoredNetwork],
    wanted: &str,
) -> Result<&'a tsunagi::storage::StoredNetwork, String> {
    let wanted = wanted.trim().trim_end_matches('…');
    if wanted.is_empty() {
        return Err("name a network by its id; `tsunagi network` lists them".to_string());
    }
    let matched: Vec<&tsunagi::storage::StoredNetwork> = networks
        .iter()
        .filter(|network| network.network_id.to_string().starts_with(wanted))
        .collect();
    match matched.as_slice() {
        [one] => Ok(one),
        [] => {
            if networks
                .iter()
                .any(|network| network.name.as_str() == wanted)
            {
                return Err(format!(
                    "`{wanted}` is a network name, not an id. Two networks can share a name, \
                     so this takes the id; `tsunagi network` lists them."
                ));
            }
            Err(format!(
                "no configured network has an id starting `{wanted}`; \
                 `tsunagi network` lists them"
            ))
        }
        several => Err(format!(
            "`{wanted}` matches {} networks; use more of the id",
            several.len()
        )),
    }
}

/// `tsunagi network`: what this device belongs to, and leaving it.
async fn network_command(args: NetworkArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    match args.action {
        None => show_networks(&paths, &socket).await,
        Some(NetworkAction::Join(args)) => join_command(args).await,
        Some(NetworkAction::Stop { network }) => set_active(&paths, &socket, &network, false).await,
        Some(NetworkAction::Start { network }) => set_active(&paths, &socket, &network, true).await,
        Some(NetworkAction::Leave { network, offline }) => {
            leave_network(&paths, &socket, &network, offline).await
        }
        Some(NetworkAction::Secret {
            network,
            action: None,
        }) => show_secrets(&paths, network.as_deref()),
        Some(NetworkAction::Secret {
            action: Some(SecretAction::Generate),
            ..
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

/// `tsunagi join`: make a network or join one.
async fn join_command(args: JoinArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    let name = NetworkName::new(args.network)?;
    // A name this device already has means that network; a name nobody
    // has means a new one, and no secret is needed to make a network with
    // somebody in a hurry.
    let (secret, origin) = resolve_secret(
        &paths,
        &name,
        args.secret.as_deref(),
        args.secret_file.as_deref(),
    )?;
    // How it stood before, read now because afterwards everything is
    // configured and the difference is what the user needs to see.
    let network_id = tsunagi::identity::NetworkKeys::derive(&name, &secret).network_id();
    let (standing, _) = network_context(&stored_networks(&paths), &name, network_id);
    join_network(&paths, &socket, &name, secret, origin, standing).await
}

/// Joins a network: into the running agent if there is one.
async fn join_network(
    paths: &StoragePaths,
    socket: &std::path::Path,
    name: &NetworkName,
    secret: NetworkSecret,
    origin: SecretOrigin,
    standing: NetworkStanding,
) -> Result<(), Box<dyn std::error::Error>> {
    // The running agent, because a second `up` cannot have the directory
    // and because this way the network starts at once instead of at the
    // next restart.
    if tsunagi::ipc::is_serving(socket).await {
        let report =
            tsunagi::ipc::join_network(socket, name.as_str(), secret.encode().as_str())
                .await?;
        // The id in full either way: it is what every other command takes,
        // and the shortened form in a report is for reading, not copying.
        match standing {
            NetworkStanding::New => {
                println!("joined `{}` ({})", report.name, report.network_id)
            }
            NetworkStanding::Known => println!(
                "`{}` ({}) was already here; it is running",
                report.name, report.network_id
            ),
            // Joining is an instruction to run it, so it undoes a stop —
            // said out loud, because a pause that ends without a word is
            // a pause nobody can rely on.
            NetworkStanding::Stopped => println!(
                "`{}` ({}) was stopped; it is running again",
                report.name, report.network_id
            ),
        }
        if let Some(other) = &report.name_shared_with {
            eprintln!(
                "\nwarning: `{}` is also configured with a different secret, as {}.\n\
                 A network is its name *and* its secret, so these two share nothing.\n\
                 If that was a mistyped secret, `tsunagi network leave` removes one.",
                report.name,
                short(other, 10)
            );
        }
        if origin == SecretOrigin::Generated {
            invite(socket, name, &secret).await;
        }
        return Ok(());
    }

    // No agent: configure it, and say when it will take effect rather than
    // leaving the impression that it is running.
    let keys = tsunagi::identity::NetworkKeys::derive(name, &secret);
    let storage = tsunagi::storage::Storage::open(paths)?;
    let shared = storage
        .list_networks()
        .await
        .unwrap_or_default()
        .iter()
        .find(|other| other.name == *name && other.network_id != keys.network_id())
        .map(|other| other.network_id.to_string());
    storage
        .upsert_network(keys.network_id(), name.clone(), secret.clone(), true)
        .await?;
    storage.release_ownership_lock();

    match standing {
        NetworkStanding::New => println!("joined `{name}` ({})", keys.network_id()),
        NetworkStanding::Known => {
            println!("`{name}` ({}) was already here", keys.network_id())
        }
        NetworkStanding::Stopped => {
            println!(
                "`{name}` ({}) was stopped; it will start",
                keys.network_id()
            )
        }
    }
    if let Some(other) = shared {
        eprintln!(
            "\nwarning: `{name}` is also configured with a different secret, as {}.\n\
             A network is its name *and* its secret, so these two share nothing.",
            short(&other, 10)
        );
    }
    if origin == SecretOrigin::Generated {
        println!("  secret  {}", secret.encode().as_str());
    }
    eprintln!("\nNo agent is running here, so it starts with the next `tsunagi up`.");
    Ok(())
}

/// Prints the one line that gets somebody else into this network.
///
/// Only when the secret was invented here: there is nowhere else to read it
/// from, and the whole point of a network made in a hurry is that the
/// command can be pasted to the other person as it stands. The endpoint id
/// comes from the running agent, because without a peer to contact the
/// other side has nothing to go on.
async fn invite(socket: &std::path::Path, name: &NetworkName, secret: &NetworkSecret) {
    let endpoint = tsunagi::ipc::request_status(socket)
        .await
        .ok()
        .map(|report| report.endpoint_id)
        .filter(|id| !id.is_empty());
    println!("  secret  {}", secret.encode().as_str());
    println!(
        "\nRun this on the other machine:\n\n  \
         tsunagi join --network {name} --secret {}",
        secret.encode().as_str()
    );
    match endpoint {
        Some(endpoint) => println!(
            "\nIts agent has to be running. If it is not:\n\n  \
             tsunagi up --peer {endpoint}"
        ),
        None => println!("\nIts agent has to be running: `tsunagi up`."),
    }
}

/// Every configured network, live where an agent can say so.
async fn show_networks(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let stored = stored_networks(paths);
    if stored.is_empty() {
        eprintln!("no network has been joined");
        return Ok(());
    }

    let observed = observe(paths, socket).await;
    let live = match &observed {
        Observed::Agent(report) => report.networks.clone(),
        Observed::Stored { .. } => Vec::new(),
    };

    let mut out = Report::new();
    let mut section = Section::new("networks");
    for network in &stored {
        let id = network.network_id.to_string();
        let running = live.iter().find(|other| other.network_id == id);
        // Three states, and the difference matters: running, stopped on
        // purpose and kept, or configured and waiting for an agent.
        let (state, note) = match running {
            Some(live) if live.active => (
                match live.overlay.as_ref().and_then(|o| o.address.clone()) {
                    Some(address) => format!("running  ·  {address}"),
                    None => "running  ·  no address agreed yet".to_string(),
                },
                format!(
                    "`tsunagi network stop {}` pauses it, `leave` gives it up",
                    short(&id, 10)
                ),
            ),
            Some(_) => (
                "stopped".to_string(),
                format!(
                    "kept as it was; `tsunagi network start {}` resumes it",
                    short(&id, 10)
                ),
            ),
            None if network.auto_start => (
                "configured  ·  starts with the agent".to_string(),
                format!(
                    "`tsunagi network stop {}` keeps it from starting",
                    short(&id, 10)
                ),
            ),
            None => (
                "stopped".to_string(),
                format!(
                    "kept as it was; `tsunagi network start {}` resumes it",
                    short(&id, 10)
                ),
            ),
        };
        section.push(
            Row::new(
                Health::Info,
                network.name.as_str().to_string(),
                format!("{id}  ·  {state}"),
            )
            .with_note(note),
        );
    }
    out.push(section);
    print_report("tsunagi networks", &out)
}

/// Stops serving a network, or starts serving it again.
///
/// Deliberately not a signed anything: stopping is this device being away,
/// which is an ordinary condition the others already handle, and the whole
/// point is that everything is still here when it comes back.
async fn set_active(
    paths: &StoragePaths,
    socket: &std::path::Path,
    wanted: &str,
    active: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let networks = stored_networks(paths);
    let network = resolve_network(&networks, wanted)?;
    let id = network.network_id.to_string();
    let name = network.name.clone();

    if tsunagi::ipc::is_serving(socket).await {
        let report = tsunagi::ipc::set_active(socket, &id, active).await?;
        match (report.active, report.changed) {
            (false, true) => println!(
                "stopped `{}` ({}); everything it has is kept",
                report.name,
                short(&id, 10)
            ),
            (false, false) => {
                println!("`{}` ({}) was already stopped", report.name, short(&id, 10))
            }
            (true, true) => println!("started `{}` ({})", report.name, short(&id, 10)),
            (true, false) => println!("`{}` ({}) was already running", report.name, short(&id, 10)),
        }
        if !report.active {
            eprintln!(
                "\nNothing was announced: to the others this device is away, and the address \
                 and name it holds stay reserved for it. `tsunagi network start {}` resumes \
                 it; `tsunagi network leave` is the one that gives them up.",
                short(&id, 10)
            );
        }
        return Ok(());
    }

    // No agent: the stored flag is what the next start reads.
    let storage = tsunagi::storage::Storage::open(paths)?;
    storage.set_auto_start(network.network_id, active).await?;
    storage.release_ownership_lock();
    println!(
        "`{name}` ({}) will {} with the next `tsunagi up`",
        short(&id, 10),
        if active { "start" } else { "stay stopped" }
    );
    Ok(())
}

/// Leaves one network, announcing it if there is anything to announce with.
async fn leave_network(
    paths: &StoragePaths,
    socket: &std::path::Path,
    wanted: &str,
    offline: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let networks = stored_networks(paths);
    let network = resolve_network(&networks, wanted)?;
    let id = network.network_id.to_string();
    let name = network.name.clone();

    // The running agent does it, because only it can publish the release
    // while its sessions are still up.
    if tsunagi::ipc::is_serving(socket).await {
        let report = tsunagi::ipc::leave_network(socket, &id).await?;
        println!("left `{}` ({})", report.name, short(&id, 10));
        match (report.announced, report.peers_told) {
            (true, 0) => eprintln!(
                "\nNobody was connected, so nothing was told: the others keep the address \
                 and name this device claimed until it says otherwise, and it no longer can."
            ),
            (true, peers) => eprintln!(
                "\nThe release went to {peers} connected peer(s); they pass it on, so the \
                 address and name are freed for the rest as they sync."
            ),
            (false, _) => eprintln!(
                "\nThe network was not running, so nothing was announced: the others keep \
                 the address and name this device claimed."
            ),
        }
        return Ok(());
    }

    if !offline {
        return Err(format!(
            "no agent is running for this state directory, so nothing can announce that \
             `{name}` is being left. Start it and run this again to free the address and \
             name for the others, or pass --offline to drop the network locally and leave \
             them holding it."
        )
        .into());
    }

    // Local removal. The storage lock makes sure no agent is using it.
    let storage = tsunagi::storage::Storage::open(paths)?;
    storage.remove_network(network.network_id).await?;
    // What a protocol kept for it goes too; there is no plugin loaded here
    // to be asked, so the one this build has is asked directly.
    forget_protocol_state(paths, network.network_id);
    storage.release_ownership_lock();
    println!("left `{name}` ({}) locally", short(&id, 10));
    eprintln!(
        "\nNothing was announced: the others keep the address and name this device \
         claimed in it."
    );
    Ok(())
}

/// Removes what the compiled-in protocols keep for a network.
///
/// The offline path has no agent and so no plugins to ask. Each failure is
/// reported and none is fatal: the network is already gone from the state.
fn forget_protocol_state(paths: &StoragePaths, network: tsunagi::NetworkId) {
    let store = tsunagi_wg_quic::WireguardConfig::new(paths.state_dir.join("wg-quic"));
    match tsunagi_wg_quic::WgKeyStore::open(store.key_store_path()) {
        Ok(store) => {
            if let Err(err) = store.forget(network) {
                eprintln!("warning: the wg-quic key for it could not be removed: {err}");
            }
        }
        // Never opened means never used, which is nothing to clean up.
        Err(err) if !store.key_store_path().exists() => {
            let _ = err;
        }
        Err(err) => eprintln!("warning: the wg-quic key store could not be opened: {err}"),
    }
}

/// `tsunagi wipe`: back to a device that has never joined anything.
async fn wipe(args: WipeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    if tsunagi::ipc::is_serving(&socket).await {
        return Err(
            "stop the agent first: a wipe removes the state it is using, and leaving a \
             network properly needs it running anyway"
                .into(),
        );
    }

    let plan = tsunagi::storage::wipe_plan(&paths)?;
    if plan.is_empty() {
        println!("nothing stored: this device has never joined anything");
        return Ok(());
    }

    let networks = stored_networks(&paths);
    if !args.yes {
        println!("`tsunagi wipe --yes` would remove:\n");
        for entry in plan.entries() {
            println!("  {}", entry.display());
        }
        if !networks.is_empty() {
            println!("\nand with it, membership of:\n");
            for network in &networks {
                println!("  {}  {}", network.name, network.network_id);
            }
            println!(
                "\nNobody is told. Leave each network first — start the agent and run\n\
                 `tsunagi network leave <id>` — to free the address and name it holds\n\
                 for the others. Afterwards this device is a stranger: a new identity,\n\
                 no networks, and no way to sign anything for the old ones."
            );
        }
        println!("\nNothing was removed.");
        return Ok(());
    }

    let removed = tsunagi::storage::wipe(&paths)?;
    // A socket file with nothing behind it is a leftover of the same kind. On
    // Windows there is no socket file, so this only ever tidies a Unix one.
    if !tsunagi::ipc::is_serving(&socket).await {
        let _ = std::fs::remove_file(&socket);
    }
    println!("removed {} item(s):", removed.entries().count());
    for entry in removed.entries() {
        println!("  {}", entry.display());
    }
    if !networks.is_empty() {
        eprintln!(
            "\nThis device left {} network(s) without telling anybody; they keep what it \
             claimed. The next start generates a new identity and knows nothing.",
            networks.len()
        );
    }
    Ok(())
}

/// `tsunagi dns`: the local resolver, and turning it on or off.
async fn dns_command(args: DnsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());

    let enable = match args.action {
        None => return show_dns(&paths, &socket).await,
        Some(DnsAction::On { .. }) => true,
        Some(DnsAction::Off) => false,
    };
    let port = match args.action {
        Some(DnsAction::On { port }) => port,
        _ => None,
    };

    // The running agent, so it takes effect now; it stores the setting too,
    // so the two can never say different things.
    if tsunagi::ipc::is_serving(&socket).await {
        let report = tsunagi::ipc::set_dns(&socket, enable, port).await?;
        match report {
            Some(report) => {
                println!(
                    "serving {} on {}",
                    match report.zones.as_slice() {
                        [] => "no zone yet".to_string(),
                        zones => zones.join(", "),
                    },
                    if report.listening.is_empty() {
                        report
                            .bind_error
                            .clone()
                            .unwrap_or_else(|| "nothing".to_string())
                    } else {
                        report.listening.join(", ")
                    }
                );
                if let Some(err) = &report.publish_error {
                    eprintln!("\nthe system resolver was not told: {err}");
                }
            }
            None => println!("not serving"),
        }
        return Ok(());
    }

    let stored = dns_setting(&paths);
    store_dns_setting(
        &paths,
        DnsSetting {
            enabled: enable,
            port: port.unwrap_or(stored.port),
        },
    )?;
    println!("{} for future starts", if enable { "on" } else { "off" });
    eprintln!("\nNo agent is running here, so it takes effect with the next `tsunagi up`.");
    Ok(())
}

/// What the resolver is doing, or why it is not.
async fn show_dns(
    paths: &StoragePaths,
    socket: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use report::Report;

    let observed = observe(paths, socket).await;
    let mut out = Report::new();
    match &observed {
        Observed::Agent(report) => out.push(match &report.dns {
            Some(dns) => dns_section(dns),
            None => dns_absent_section(),
        }),
        // Not running: the stored setting is what it will do next time,
        // which is the only truthful thing to say.
        Observed::Stored { .. } => {
            use report::{Health, Row, Section};
            let setting = dns_setting(paths);
            let mut section = Section::new("dns");
            section.push(
                Row::new(
                    Health::Info,
                    if setting.enabled { "on" } else { "off" },
                    format!("port {}, for the next start", setting.port),
                )
                .with_note("no agent is running, so nothing is answering right now"),
            );
            out.push(section);
        }
    }
    print_report("tsunagi dns", &out)
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

    // What this device *is*, not what it belongs to. The networks are
    // `tsunagi network`, and their secrets are asked for by name there:
    // printing them in an overview put them in every pasted report.
    let networks = stored_networks(paths);
    let mut section = Section::new("networks");
    section.push(match networks.len() {
        0 => Row::new(Health::Info, "none", "no network has been joined")
            .with_note("`tsunagi join --network <name>` makes or joins one"),
        count => Row::new(
            Health::Info,
            "joined",
            format!(
                "{count} network(s): {}",
                networks
                    .iter()
                    .map(|network| network.name.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_note("`tsunagi network` lists them with their ids and addresses"),
    });
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
    if tsunagi::ipc::is_serving(socket).await {
        return match tsunagi::ipc::set_hostname(socket, name).await {
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
    if tsunagi::ipc::is_serving(socket).await {
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
fn show_secrets(
    paths: &StoragePaths,
    wanted: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let networks = stored_networks(paths);
    if networks.is_empty() {
        eprintln!("no network has been joined");
        return Ok(());
    }
    match wanted {
        Some(wanted) => {
            let network = resolve_network(&networks, wanted)?;
            println!("{}", network.secret.encode().as_str());
        }
        None => {
            for network in networks {
                println!(
                    "{}  {}  {}",
                    network.name,
                    network.network_id,
                    network.secret.encode().as_str()
                );
            }
        }
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

    if let Observed::Agent(report) = &observed {
        out.push(match &report.dns {
            Some(dns) => dns_section(dns),
            None => dns_absent_section(),
        });
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
        "zones",
        match dns.zones.as_slice() {
            [] => "none yet: this agent is in no network that can be one".to_string(),
            zones => format!("{}  ·  {} name(s)", zones.join(", "), dns.names),
        },
    ));
    for warning in &dns.zone_warnings {
        section.push(Row::new(Health::Degraded, "zone name", warning.clone()));
    }

    match (dns.listening.as_slice(), &dns.bind_error) {
        ([], Some(err)) => {
            section.push(Row::new(Health::Broken, "listening", err.clone()));
        }
        ([], None) => {
            section.push(Row::new(Health::Degraded, "listening", "not yet"));
        }
        // One address per family it could open. Both is the ordinary case;
        // one is worth seeing rather than hiding, because then a question
        // over the other family goes unanswered.
        (addresses, _) => {
            section.push(Row::new(Health::Good, "listening", addresses.join(", ")));
        }
    }

    match &dns.publish_error {
        None if !dns.listening.is_empty() => {
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
            section.push(match (&dns.publish_remedy, dns.listening.first()) {
                (Some(remedy), _) => row.with_note(remedy.clone()),
                (None, Some(address)) => row.with_note(format!(
                    "resolve names yourself with `dig @{} -p {} <name>.{}`",
                    address.rsplit_once(':').map_or("", |(host, _)| host),
                    address.rsplit_once(':').map_or("", |(_, port)| port),
                    dns.zones.first().map_or("<zone>", String::as_str)
                )),
                (None, None) => row,
            });
        }
    }
    section
}

/// Says that there is no local resolver, when there is none.
///
/// Its absence is why a name does not resolve, and nothing else in the
/// report says so: a missing section reads as nothing to report rather than
/// as a feature that was never asked for.
fn dns_absent_section() -> report::Section {
    use report::{Health, Row, Section};

    let mut section = Section::new("dns");
    section.push(
        Row::new(
            Health::Info,
            "not serving",
            "no local resolver for any network",
        )
        .with_note(
            "members resolve by address only. `tsunagi up --dns` serves \
             `<hostname>.<network>` from signed state, so a member that is switched \
             off still resolves.",
        ),
    );
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
                 Usually a mistyped secret; `tsunagi network secret` shows which is which.",
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
        let interface = if overlay.on_host {
            overlay.interface.clone()
        } else {
            // The name is real to the agent and to nothing else. Said here,
            // because an address on an interface the operating system does
            // not have explains every ping that goes nowhere.
            format!("{} (in memory, --no-tun)", overlay.interface)
        };
        section.push(Row::new(
            if overlay.on_host {
                Health::Info
            } else {
                Health::Degraded
            },
            "overlay",
            format!(
                "{interface}  {}  mtu {}",
                match &overlay.address {
                    Some(address) => format!("{address}/{}", overlay.prefix_len),
                    None => "no address agreed yet".to_string(),
                },
                overlay.mtu
            ),
        ));
    }

    // Only when something has: a relay that has carried nothing is not
    // worth a line, and one that has is worth knowing about — it is
    // somebody else's traffic on this device's uplink.
    let relayed = network.relay_forwarded + network.relay_sent_via + network.relay_received_via;
    if relayed > 0 {
        section.push(Row::new(
            Health::Info,
            "relay",
            format!(
                "{} carried for others  ·  {} sent through a peer, {} arrived through one",
                network.relay_forwarded, network.relay_sent_via, network.relay_received_via
            ),
        ));
    }

    let rows = member_rows(network, own_id);
    let online = rows.iter().filter(|row| row.online()).count();
    if rows.is_empty() {
        // Why there is nobody, rather than just that there is nobody: the
        // three reasons want different actions, and the third one used to
        // read as the first.
        match (&network.range, &network.range_conflict, network.candidates) {
            (None, Some(_), _) => section.push(Row::new(
                Health::Info,
                "members",
                "none: this network has no range to allocate from",
            )),
            // Nobody to contact and nowhere to look. An agent finds a peer
            // by being told about one, or from what it remembers of an
            // earlier session — with neither it waits for ever, and the
            // report should say so rather than imply patience.
            (_, _, 0) => section.push(
                Row::new(
                    Health::Degraded,
                    "members",
                    "none, and nobody to contact: no candidates in this network",
                )
                .with_note(format!(
                    "somebody has to make the introduction. Start this agent with \
                     `--peer <their-endpoint-id>`, or have them start theirs with \
                     `--peer {}`. Once they have met, each remembers the other.",
                    short(own_id, 12)
                )),
            ),
            _ => section.push(Row::new(
                Health::Info,
                "members",
                format!(
                    "none yet  ·  {} candidate(s) being tried",
                    network.candidates
                ),
            )),
        }
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
                let held = if cfg!(target_os = "windows") {
                    "assumes an elevated process; creation reports if not"
                } else {
                    "CAP_NET_ADMIN held"
                };
                host.push(Row::new(Health::Good, "privileges", held));
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
    let paths = args.paths.resolve()?;

    // Parsed up front so a typo is reported immediately, and so the option is
    // never silently ignored when the data plane is off.
    let ipv4_range = resolve_ipv4_range(args.ipv4_range.as_ref())?;

    // The resolver is a property of the device, not of this command line.
    // `--dns` turns it on and it stays on; `tsunagi dns off` is what turns
    // it off. Anything else means names work today and are gone tomorrow
    // because a flag was not retyped.
    let stored_dns = dns_setting(&paths);
    let serve_dns = args.dns || stored_dns.enabled;
    let dns_port = args.dns_port.unwrap_or(stored_dns.port);
    if serve_dns != stored_dns.enabled || dns_port != stored_dns.port {
        // Written before the agent takes the directory, which it is about
        // to do; nothing else holds it at this point.
        store_dns_setting(
            &paths,
            DnsSetting {
                enabled: serve_dns,
                port: dns_port,
            },
        )?;
    }

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

    let agent = match Agent::spawn(config).await {
        Ok(agent) => agent,
        // One agent per identity, and the state directory is that identity.
        // It can be in as many networks as you like — but only through the
        // agent that is already running, so the lock on its own is an
        // answer to a question nobody asked.
        Err(tsunagi::Error::StateLocked { path }) => {
            let socket = control_socket(&paths, args.control_socket.as_ref());
            if tsunagi::ipc::is_serving(&socket).await {
                return Err(format!(
                    "an agent is already running for {}, and one state directory is one \
                     agent — it is the device, not a network.\n\n\
                     To add a network to it:\n\n  \
                     tsunagi join --network <name>\n\n\
                     To run a second, separate agent instead, give it everything of its \
                     own:\n\n  \
                     tsunagi up --state-dir <dir> --cache-dir <dir> --interface tsun1 \
                     --ipv4-range <cidr>\n\n\
                     That is a different identity with its own interface, not this one \
                     with another network. `tsunagi network` lists what this one has.",
                    path.display()
                )
                .into());
            }
            return Err(tsunagi::Error::StateLocked { path }.into());
        }
        Err(err) => return Err(err.into()),
    };
    // From here on every exit goes through `agent.shutdown()`, so the endpoint
    // is never dropped without being closed.
    let mut events = agent.subscribe();

    println!("tsunagi is up");
    println!("  endpoint id  {}", agent.endpoint_id());
    println!("  hostname     {}", agent.hostname());
    // What this device belongs to is a separate question from whether its
    // agent is running, and `tsunagi join` answers it at any time.
    let configured = agent.list_networks().await.unwrap_or_default();
    let running = configured.iter().filter(|network| network.active).count();
    println!(
        "  networks     {}",
        match configured.len() {
            0 => "none yet  ·  `tsunagi join --network <name>` makes or joins one".to_string(),
            total => format!("{running} of {total} running  ·  `tsunagi network` lists them"),
        }
    );
    println!("  state        {}", paths.state_dir.display());
    // A local resolver for every network this agent is in, each a zone
    // named after it. A name that shadows a public one is reported and then
    // used, because that is a decision and not a mistake.
    let dns = Arc::new(tokio::sync::Mutex::new(if serve_dns {
        println!("  dns          127.0.0.1:{dns_port} and [::1]:{dns_port}");
        Some(spawn_dns(agent.clone(), dns_port))
    } else {
        None
    }));

    // Serve `tsunagi status` for as long as this agent runs. Failing to bind
    // is not fatal: the agent itself works fine without it.
    let control = {
        let agent = agent.clone();
        let plugin = wireguard.clone();
        let dns = Arc::clone(&dns);
        let source: Arc<dyn tsunagi::ipc::ReportSource> = Arc::new(AgentControl {
            agent,
            plugin,
            dns,
            paths: paths.clone(),
        });
        let path = control_socket(&paths, args.control_socket.as_ref());
        match tsunagi::ipc::ControlSocket::bind(path, source).await {
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

    println!("\nPress Ctrl-C to stop.\n");

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
                print_status(&agent, None, wireguard.as_deref()).await;
            }
        }
    }

    if let Some(control) = control {
        control.shutdown().await;
    }
    // Before the agent, so the resolver stops being pointed at a server
    // that is about to stop answering.
    if let Some(dns) = dns.lock().await.take() {
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
        MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport, StatusReport,
    };

    let overlay = agent.overlay();
    let dns = dns.map(dns_report);

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
                    on_host: overlay.as_ref().is_some_and(|overlay| overlay.on_host),
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
                candidates: network.candidates.len() as u32,
                relay_forwarded: network.relay.forwarded,
                relay_sent_via: network.relay.sent_via,
                relay_received_via: network.relay.received_via,
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

/// The Wintun adapter, created and configured by the agent and removed when it
/// exits, the same as the Linux one.
#[cfg(target_os = "windows")]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    use tsunagi::overlay::{ManagedTunFactory, WintunProvisioner};
    let provisioner = WintunProvisioner::new()?;
    Ok(Arc::new(ManagedTunFactory::new(Arc::new(provisioner))))
}

/// There is no provisioner for this platform yet.
///
/// Refused here rather than at the first packet, and with the one thing that
/// does work on every platform named.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
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

async fn print_status(
    agent: &Agent,
    network: Option<NetworkId>,
    wireguard: Option<&WireguardPlugin>,
) {
    // The network this command line named, or — when it named none — the
    // first one the agent has, since there is no other candidate for "the"
    // network and `tsunagi status` covers the whole picture anyway.
    let network = match network {
        Some(network) => network,
        None => match agent.list_networks().await {
            Ok(networks) => match networks.iter().find(|network| network.active) {
                Some(network) => network.network_id,
                None => return,
            },
            Err(_) => return,
        },
    };
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
            // A real interface, which is the ordinary case; the in-memory
            // one has a test of its own.
            on_host: true,
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
            candidates: 1,
            relay_forwarded: 0,
            relay_sent_via: 0,
            relay_received_via: 0,
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
    fn an_agent_with_nobody_to_contact_says_so_instead_of_waiting_quietly() {
        // The wiped-and-restarted case: both devices join the same network
        // and sit there. An agent finds a peer by being told about one or
        // by remembering an earlier session, and with neither it will wait
        // for ever — which "nobody else has joined" reads as patience.
        let mut network = network_after_a_peer_returned();
        network.peers.clear();
        network.members.clear();
        network.overlay = None;
        network.candidates = 0;

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert!(text.contains("nobody to contact"), "{text}");
        assert!(text.contains("--peer"), "the fix is named: {text}");
        assert!(text.contains(OWN), "with this device's own id: {text}");
        assert_eq!(out.worst(), Health::Degraded, "{text}");
    }

    #[test]
    fn candidates_with_nobody_connected_yet_is_patience_rather_than_a_fault() {
        // Something to try is the ordinary state of a network coming up.
        let mut network = network_after_a_peer_returned();
        network.peers.clear();
        network.members.clear();
        network.overlay = None;
        network.candidates = 2;

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert!(text.contains("2 candidate(s) being tried"), "{text}");
        assert_ne!(out.worst(), Health::Degraded, "{text}");
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
    fn an_in_memory_interface_is_not_presented_as_a_host_interface() {
        // `--no-tun` runs the tunnels and moves packets between agents, but
        // the operating system has no interface, no address and no route. An
        // address printed beside a name the host does not have is what makes
        // a ping that goes nowhere look like a network fault.
        let mut network = network_after_a_peer_returned();
        if let Some(overlay) = &mut network.overlay {
            overlay.on_host = false;
        }

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN, false));
        let text = out.render(false);
        assert!(text.contains("in memory"), "{text}");
        assert!(text.contains("--no-tun"), "the reason is named: {text}");
        assert_eq!(out.worst(), Health::Degraded, "{text}");
    }

    #[test]
    fn with_no_local_resolver_the_report_says_so_rather_than_nothing() {
        // The absence is the answer to "why does the name not resolve?".
        // Left out, the report looked the same as one where DNS was running.
        let mut out = report::Report::new();
        out.push(dns_absent_section());
        let text = out.render(false);
        assert!(text.contains("not serving"), "{text}");
        assert!(text.contains("--dns"), "the flag that starts it: {text}");
        // Nothing is wrong with an agent that was never asked to serve DNS.
        assert_eq!(out.worst(), Health::Good, "{text}");
    }

    #[test]
    fn both_families_are_listed_while_only_one_bound_is_still_good() {
        use tsunagi::ipc::DnsReport;

        let both = DnsReport {
            zones: vec!["lab".into()],
            listening: vec!["10.13.37.69:5354".into(), "[::1]:5354".into()],
            names: 2,
            ..Default::default()
        };
        let mut out = report::Report::new();
        out.push(dns_section(&both));
        let text = out.render(false);
        assert!(text.contains("10.13.37.69:5354, [::1]:5354"), "{text}");

        // One family is worth seeing rather than hiding: a question over the
        // other one goes unanswered.
        let one = DnsReport {
            listening: vec!["127.0.0.1:5354".into()],
            ..both.clone()
        };
        let mut out = report::Report::new();
        out.push(dns_section(&one));
        assert!(out.render(false).contains("127.0.0.1:5354"));

        // Neither, with a reason, is broken.
        let none = DnsReport {
            listening: Vec::new(),
            bind_error: Some("address already in use".into()),
            ..both
        };
        let mut out = report::Report::new();
        out.push(dns_section(&none));
        assert_eq!(out.worst(), Health::Broken, "{}", out.render(false));
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

#[cfg(test)]
mod network_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};
    use tsunagi::storage::StoredNetwork;

    fn configured(name: &str, secret: &str) -> StoredNetwork {
        let name = NetworkName::new(name).unwrap();
        let secret =
            NetworkSecret::from_bytes(&[secret.as_bytes(), &[0u8; 32]].concat()[..32]).unwrap();
        let keys = NetworkKeys::derive(&name, &secret);
        StoredNetwork {
            network_id: keys.network_id(),
            name,
            secret,
            auto_start: true,
        }
    }

    #[test]
    fn a_prefix_of_the_id_is_enough_and_an_ambiguous_one_is_refused() {
        // `status` prints ids shortened, so what a person has to hand is a
        // prefix. Accepting it is the difference between leaving a network
        // and copying 52 characters correctly.
        let networks = vec![configured("lab", "one"), configured("lab", "two")];
        let full = networks[0].network_id.to_string();

        let picked = resolve_network(&networks, &full[..10]).unwrap();
        assert_eq!(picked.network_id, networks[0].network_id);
        // The ellipsis a person copies out of the report is not part of it.
        let picked = resolve_network(&networks, &format!("{}…", &full[..10])).unwrap();
        assert_eq!(picked.network_id, networks[0].network_id);

        let err = resolve_network(&networks, "").unwrap_err();
        assert!(err.contains("by its id"), "{err}");
    }

    #[test]
    fn a_name_is_refused_because_two_networks_can_share_one() {
        // Exactly the situation this command exists for: two networks called
        // `lab`, one of them joined with a mistyped secret. Choosing for the
        // user here is how the wrong one gets left.
        let networks = vec![configured("lab", "one"), configured("lab", "two")];
        let err = resolve_network(&networks, "lab").unwrap_err();
        assert!(err.contains("not an id"), "{err}");
        assert!(
            err.contains("tsunagi network"),
            "it says where to look: {err}"
        );
    }

    #[test]
    fn an_id_that_matches_nothing_says_so() {
        let networks = vec![configured("lab", "one")];
        let err = resolve_network(&networks, "zzzzzz").unwrap_err();
        assert!(err.contains("no configured network"), "{err}");
    }

    #[test]
    fn a_prefix_shared_by_two_networks_is_refused_rather_than_guessed() {
        let networks = vec![configured("lab", "one"), configured("other", "two")];
        let shared = &networks[0].network_id.to_string()[..1];
        let both = networks
            .iter()
            .filter(|network| network.network_id.to_string().starts_with(shared))
            .count();
        if both < 2 {
            // The two derived ids happen not to share a first character;
            // the empty prefix is the same question with a certain answer.
            let err = resolve_network(&networks, "").unwrap_err();
            assert!(err.contains("by its id"), "{err}");
            return;
        }
        let err = resolve_network(&networks, shared).unwrap_err();
        assert!(err.contains("use more of the id"), "{err}");
    }
}

#[cfg(test)]
mod secret_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tsunagi::identity::NetworkKeys;

    fn paths(dir: &tempfile::TempDir) -> StoragePaths {
        StoragePaths::new(dir.path().join("state"), dir.path().join("cache"))
    }

    fn already_joined(paths: &StoragePaths, name: &str) -> NetworkSecret {
        let name = NetworkName::new(name).unwrap();
        let secret = NetworkSecret::generate();
        let keys = NetworkKeys::derive(&name, &secret);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let store = tsunagi::storage::StateStore::open(paths.state_db()).unwrap();
        store
            .upsert_network(keys.network_id(), &name, &secret, true)
            .unwrap();
        secret
    }

    #[test]
    fn a_name_nobody_has_yet_gets_a_secret_of_its_own() {
        // An ad-hoc network is a thing people want, and "generate a secret
        // first" is a step with no purpose. The caller prints what this
        // invents, because a secret nobody can read is no use.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir);
        let name = NetworkName::new("spontaneous").unwrap();

        let (secret, origin) = resolve_secret(&paths, &name, None, None).unwrap();
        assert_eq!(origin, SecretOrigin::Generated);
        // A real one: decodable, and different every time.
        let text = secret.encode().as_str().to_string();
        assert!(NetworkSecret::decode(&text).is_ok());
        let (other, _) = resolve_secret(&paths, &name, None, None).unwrap();
        assert_ne!(other.encode().as_str(), text);
    }

    #[test]
    fn a_name_this_device_already_has_resumes_it() {
        // Otherwise `tsunagi join --network lab` would invent a stranger with
        // the same name every time, which is the confusion this whole
        // report format exists to prevent.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir);
        let joined = already_joined(&paths, "lab");

        let (secret, origin) =
            resolve_secret(&paths, &NetworkName::new("lab").unwrap(), None, None).unwrap();
        assert_eq!(origin, SecretOrigin::Stored);
        assert_eq!(secret.encode().as_str(), joined.encode().as_str());
    }

    #[test]
    fn a_secret_that_was_given_wins_over_the_stored_one() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir);
        already_joined(&paths, "lab");
        let given = NetworkSecret::generate();

        let (secret, origin) = resolve_secret(
            &paths,
            &NetworkName::new("lab").unwrap(),
            Some(given.encode().as_str()),
            None,
        )
        .unwrap();
        assert_eq!(origin, SecretOrigin::Given);
        assert_eq!(secret.encode().as_str(), given.encode().as_str());
    }

    #[test]
    fn two_networks_of_one_name_refuse_to_guess() {
        // The mistyped-secret case. Picking one would be picking wrong half
        // the time, and doing it silently.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir);
        already_joined(&paths, "lab");
        already_joined(&paths, "lab");

        let err = resolve_secret(&paths, &NetworkName::new("lab").unwrap(), None, None)
            .expect_err("it cannot choose");
        assert!(err.to_string().contains("does not say which"), "{err}");
    }
}

#[cfg(test)]
mod network_context_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tsunagi::identity::NetworkKeys;
    use tsunagi::storage::StoredNetwork;

    fn configured(name: &str, seed: u8) -> StoredNetwork {
        let name = NetworkName::new(name).unwrap();
        let secret = NetworkSecret::from_bytes([seed; 32]).unwrap();
        let keys = NetworkKeys::derive(&name, &secret);
        StoredNetwork {
            network_id: keys.network_id(),
            name,
            secret,
            auto_start: true,
        }
    }

    #[test]
    fn a_network_already_here_is_told_from_a_new_one() {
        // `up` prints which of the two happened. Without it, a command line
        // that quietly recreates a network somebody just left looks exactly
        // like the one they meant to start.
        let known = configured("lab", 1);
        let name = known.name.clone();
        let (standing, shared) =
            network_context(std::slice::from_ref(&known), &name, known.network_id);
        assert_eq!(standing, NetworkStanding::Known);
        assert_eq!(shared, None);

        let fresh = configured("lab", 2);
        let (standing, shared) =
            network_context(std::slice::from_ref(&known), &name, fresh.network_id);
        assert_eq!(
            standing,
            NetworkStanding::New,
            "a different secret is a different network"
        );
        assert_eq!(
            shared,
            Some(known.network_id.to_string()),
            "and the one it shares a name with is named"
        );
    }

    #[test]
    fn a_name_nobody_here_uses_shares_with_nothing() {
        let (standing, shared) = network_context(
            &[configured("lab", 1)],
            &NetworkName::new("other").unwrap(),
            configured("other", 3).network_id,
        );
        assert_eq!(standing, NetworkStanding::New);
        assert_eq!(shared, None);
    }

    #[test]
    fn a_stopped_network_is_told_from_one_that_is_merely_known() {
        // Joining a stopped network starts it — which is right, it is an
        // instruction to run it — and saying so is what keeps a pause
        // from ending without a word.
        let mut stopped = configured("lab", 1);
        stopped.auto_start = false;
        let name = stopped.name.clone();

        let (standing, _) =
            network_context(std::slice::from_ref(&stopped), &name, stopped.network_id);
        assert_eq!(standing, NetworkStanding::Stopped);
    }
}

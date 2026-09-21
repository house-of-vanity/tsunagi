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
use tsunagi::dataplane::wireguard::{
    MemoryTunFactory, TunFactory, WireguardConfig, WireguardPlugin,
};
use tsunagi::discovery::{CompositeDiscovery, NetworkDiscovery, StaticBootstrap};
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::iroh_types::EndpointAddr;
use tsunagi::state::Ipv4Range;
use tsunagi::{Agent, NetworkId};

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
    /// Generates a fresh network secret and prints it.
    Secret,
    /// Shows this device's identity without joining anything.
    Id(StatusArgs),
    /// Joins a network and runs until interrupted.
    // Boxed: it is much larger than the other variants, and every command
    // but this one would otherwise pay for its size. A `//` comment, not a
    // `///` one, or clap would print it as help.
    Up(Box<UpArgs>),
    /// Reports this device, what the agent is doing, and what this host can do.
    Status(StatusArgs),
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
    /// Directory for the mandatory state. Defaults to the platform location.
    #[arg(long, env = "TSUNAGI_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Directory for the disposable cache. Defaults to the platform location.
    #[arg(long, env = "TSUNAGI_CACHE_DIR")]
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
enum Transport {
    /// Loopback and the local network only. Publishes nothing.
    Local,
    /// Public address lookup, direct paths only, no relays.
    Direct,
    /// Public address lookup plus public relay fallback. The default.
    #[value(alias = "n0")]
    Relay,
}

impl From<Transport> for TransportPolicy {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Local => TransportPolicy::LocalOnly,
            Transport::Direct => TransportPolicy::DirectOnly,
            Transport::Relay => TransportPolicy::N0Defaults,
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
    #[arg(long)]
    hostname: Option<String>,

    /// How much external connectivity to use.
    #[arg(long, value_enum, default_value_t = Transport::Relay)]
    transport: Transport,

    /// A peer to contact, as `<endpoint-id>` or `<endpoint-id>@<ip:port>,...`.
    ///
    /// One agent needs to know another to begin with. Repeat for several.
    #[arg(long = "peer", value_name = "PEER")]
    peers: Vec<String>,

    /// Local address to bind. Repeat for several; defaults to iroh's choice.
    #[arg(long = "bind", value_name = "ADDR")]
    binds: Vec<SocketAddr>,

    /// Run the WireGuard data plane.
    #[arg(long)]
    wireguard: bool,

    /// Do not create a real network interface.
    ///
    /// The WireGuard tunnels still run and handshake, so the mesh can be
    /// verified with no privileges; traffic just does not reach the
    /// operating system.
    #[arg(long)]
    no_tun: bool,

    /// Interface name prefix for the WireGuard data plane.
    #[arg(long, default_value = "tsun")]
    wg_prefix: String,

    /// Interface MTU for the WireGuard data plane.
    ///
    /// Must be at least 1280, the minimum IPv6 requires.
    #[arg(long)]
    wg_mtu: Option<u32>,

    /// IPv4 overlay range, as `address/prefix`, or `none` to disable IPv4.
    ///
    /// Defaults to 10.13.37.0/24. Only the first member to join decides:
    /// a network that has already settled on a range wins, and a joining
    /// agent adopts what it finds. Addresses are allocated from it and
    /// recorded in signed state, so each member keeps its own across
    /// restarts and long absences.
    #[arg(long, value_name = "CIDR")]
    ipv4_range: Option<String>,

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
        Command::Secret => {
            let secret = NetworkSecret::generate();
            println!("{}", secret.encode().as_str());
            eprintln!(
                "\nShare this with every participant, over a channel you trust.\n\
                 Anyone who has it can join the network."
            );
            Ok(())
        }
        Command::Id(args) => show_id(args).await,
        Command::Up(args) => up(*args).await,
        Command::Status(args) => status(args).await,
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
        networks: Vec<(String, String, bool)>,
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
    let (endpoint_id, hostname, networks) =
        match tsunagi::storage::StateStore::open(paths.state_db()) {
            Ok(store) => (
                store
                    .device_identity()
                    .ok()
                    .flatten()
                    .map(|identity| identity.endpoint_id().to_string()),
                store.hostname().ok().flatten(),
                store
                    .list_networks()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|network| {
                        (
                            network.name.to_string(),
                            network.network_id.to_string(),
                            network.auto_start,
                        )
                    })
                    .collect(),
            ),
            Err(_) => (None, None, Vec::new()),
        };
    Observed::Stored {
        endpoint_id,
        hostname,
        networks,
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

/// The `networks` section, as the state store knows them.
fn stored_networks_section(networks: &[(String, String, bool)]) -> report::Section {
    use report::{Health, Row, Section};

    let mut section = Section::new("networks");
    if networks.is_empty() {
        section.push(Row::new(Health::Info, "none", "no network has been joined"));
    }
    for (name, id, auto_start) in networks {
        section.push(Row::new(
            Health::Info,
            name,
            format!("{id}{}", if *auto_start { "  (auto-start)" } else { "" }),
        ));
    }
    section
}

async fn show_id(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    let observed = observe(&paths, &socket).await;

    let mut out = Report::new();
    out.push(device_section(&paths, &observed));
    match &observed {
        Observed::Agent(report) => {
            let mut section = Section::new("networks");
            if report.networks.is_empty() {
                section.push(Row::new(Health::Info, "none", "no network has been joined"));
            }
            for network in &report.networks {
                section.push(Row::new(
                    Health::Info,
                    &network.name,
                    format!(
                        "{}  ({})",
                        network.network_id,
                        if network.active { "active" } else { "inactive" }
                    ),
                ));
            }
            out.push(section);
        }
        Observed::Stored { networks, .. } => out.push(stored_networks_section(networks)),
    }
    print_report("tsunagi id", &out)
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

    if let Observed::Agent(report) = &observed {
        for network in &report.networks {
            out.push(network_section(network, &report.endpoint_id));
        }
    }

    out.push(host_section());
    out.push(addresses_section().await);
    print_report("tsunagi status", &out)
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
                row.overlay_address_v4 = peer.address_v4.as_deref();
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
fn network_section(network: &tsunagi::ipc::NetworkReport, own_id: &str) -> report::Section {
    use report::{Health, Row, Section};

    let mut section = Section::new(format!("network {}", network.name));
    section.push(if network.active {
        Row::new(
            Health::Good,
            "state",
            format!("active  {}", network.network_id),
        )
    } else {
        Row::new(
            Health::Degraded,
            "state",
            format!("inactive  {}", network.network_id),
        )
    });

    if let Some(overlay) = &network.overlay {
        section.push(Row::new(
            Health::Info,
            "overlay",
            format!(
                "{}  {}/{}{}  mtu {}",
                overlay.interface,
                overlay.address,
                overlay.prefix_len,
                match &overlay.address_v4 {
                    Some(v4) => format!(" and {v4}"),
                    None => String::new(),
                },
                overlay.mtu
            ),
        ));
    }

    let rows = member_rows(network, own_id);
    let online = rows.iter().filter(|row| row.online()).count();
    if rows.is_empty() {
        section.push(Row::new(
            Health::Info,
            "members",
            "none known yet; nobody else has joined",
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
    #[cfg(feature = "tun-device")]
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

        use tsunagi::dataplane::wireguard::{Privilege, probe_net_admin};
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
    #[cfg(not(feature = "tun-device"))]
    host.push(
        Row::new(
            Health::Degraded,
            "interface",
            "not built in; the tunnels run but cannot reach the OS",
        )
        .with_note("rebuild with the `tun-device` feature, or run with `--no-tun`"),
    );
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
        .with_transport(args.transport.into())
        .with_discovery(discovery)
        .with_discovery_interval(Duration::from_secs(5));
    if let Some(hostname) = &args.hostname {
        config = config.with_hostname(hostname.clone());
    }
    if !args.binds.is_empty() {
        config = config.with_bind_addrs(args.binds.clone());
    }

    // The data plane is optional and never required for the control plane.
    let wireguard = if args.wireguard {
        let tun_factory: Arc<dyn TunFactory> = if args.no_tun {
            Arc::new(MemoryTunFactory::new())
        } else {
            system_tun_factory()?
        };
        let mut wg = WireguardConfig::new(paths.state_dir.join("wireguard"))
            .with_interface_prefix(args.wg_prefix.clone());
        if let Some(mtu) = args.wg_mtu {
            wg = wg.with_mtu(mtu);
        }
        let plugin = WireguardPlugin::open(wg, tun_factory).await?;
        config = config.with_plugin(plugin.clone() as Arc<dyn IpPlugin>);
        Some(plugin)
    } else {
        None
    };

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
    // Serve `tsunagi status` for as long as this agent runs. Failing to bind
    // is not fatal: the agent itself works fine without it.
    let control = {
        let agent = agent.clone();
        let plugin = wireguard.clone();
        let source: Arc<dyn tsunagi::ipc::unix::ReportSource> = Arc::new(
            move || -> tsunagi::BoxFuture<'static, tsunagi::ipc::StatusReport> {
                let agent = agent.clone();
                let plugin = plugin.clone();
                Box::pin(async move { build_report(&agent, plugin.as_deref()).await })
            },
        );
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
) -> tsunagi::ipc::StatusReport {
    use tsunagi::ipc::{
        MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport, StatusReport,
    };

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
                    interface: view.interface.clone(),
                    mtu: view.mtu,
                    address: view.overlay_address.to_string(),
                    address_v4: view.overlay_address_v4.map(|addr| addr.to_string()),
                    prefix: view.overlay_prefix.to_string(),
                    prefix_len: view.overlay_prefix_len,
                    peers: view
                        .peers
                        .iter()
                        .map(|peer| OverlayPeerReport {
                            endpoint_id: peer.endpoint_id.to_string(),
                            public_key: peer.public_key.to_string(),
                            address: peer.overlay_address.to_string(),
                            address_v4: peer.overlay_address_v4.map(|addr| addr.to_string()),
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
                    unroutable_packets: view.unroutable_packets,
                    multicast_packets: view.multicast_packets,
                    unroutable_sample: view.unroutable_sample.map(|address| address.to_string()),
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
#[cfg(all(feature = "tun-device", target_os = "linux"))]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    use tsunagi::dataplane::wireguard::{ManagedTunFactory, NetlinkProvisioner};
    let provisioner = NetlinkProvisioner::new()?;
    Ok(Arc::new(ManagedTunFactory::new(Arc::new(provisioner))))
}

/// There is no provisioner for this platform yet.
///
/// Refused here rather than at the first packet, and with the one thing that
/// does work on every platform named.
#[cfg(all(feature = "tun-device", not(target_os = "linux")))]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    Err(format!(
        "managing the overlay interface is not implemented on {} yet. \
         Run with `--no-tun` to keep the tunnels off the operating system.",
        std::env::consts::OS
    )
    .into())
}

#[cfg(not(feature = "tun-device"))]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    Err("this build has no interface support; rebuild with the `tun-device` feature or pass --no-tun".into())
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
            "wireguard: {} on {}/{} mtu {}, {}/{} tunnel(s) established",
            view.interface,
            view.overlay_address,
            view.overlay_prefix_len,
            view.mtu,
            view.established_peers(),
            view.peers.len()
        );
        for peer in &view.peers {
            match &peer.tunnel {
                Some(tunnel) => println!(
                    "  {} {} {} tx={} rx={} dropped={} path={}",
                    peer.public_key.fmt_short(),
                    peer.overlay_address,
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
                    peer.overlay_address
                ),
            }
        }
        if view.unroutable_packets > 0 {
            println!(
                "  {} packet(s) for unknown addresses",
                view.unroutable_packets
            );
        }
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
            address: "fd55::1".into(),
            address_v4: Some("10.13.37.69".into()),
            prefix: "fd55::".into(),
            prefix_len: 64,
            peers,
            ..Default::default()
        }
    }

    fn tunnel(endpoint_id: &str, handshake: Option<u64>) -> OverlayPeerReport {
        OverlayPeerReport {
            endpoint_id: endpoint_id.into(),
            public_key: "keykeykey".into(),
            address: "fd55::2".into(),
            address_v4: Some("10.13.37.237".into()),
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
    fn counters_from_the_past_do_not_grade_the_present() {
        // A peer that left and returned leaves dial failures and a packet
        // sent to an address nobody owned behind it. Once it is back, those
        // are history: reporting them as current faults made a working
        // network look broken.
        let network = network_after_a_peer_returned();
        let mut out = report::Report::new();
        out.push(network_section(&network, OWN));

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
        out.push(network_section(&network, OWN));
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
        out.push(network_section(&network, OWN));
        assert_eq!(out.worst(), Health::Degraded, "{}", out.render(false));
        assert!(out.render(false).contains("relay"));
    }

    #[test]
    fn a_tunnel_that_never_handshook_is_flagged_while_the_peer_is_connected() {
        let mut network = network_after_a_peer_returned();
        network.overlay = Some(overlay(vec![tunnel(ONLINE, None)]));

        let mut out = report::Report::new();
        out.push(network_section(&network, OWN));
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
        out.push(network_section(&network, OWN));
        let text = out.render(false);
        assert_eq!(out.worst(), Health::Degraded, "{text}");
        assert!(text.contains("same secret"), "{text}");
    }
}

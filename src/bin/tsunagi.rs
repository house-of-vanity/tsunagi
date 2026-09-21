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
    /// Reports what this machine can and cannot do.
    Doctor(PathArgs),
    /// Shows this device's identity without joining anything.
    Id(PathArgs),
    /// Joins a network and runs until interrupted.
    Up(UpArgs),
    /// Asks a running agent what it is doing.
    Status(StatusArgs),
    /// Prints the one-time privileged setup for the overlay interface.
    ///
    /// Run its output once as root, then run `tsunagi up` as an ordinary
    /// user: the agent attaches to the prepared interface and needs no
    /// privileges of its own.
    TunSetup(TunSetupArgs),
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Control socket to talk to. Derived from the state directory by default.
    #[arg(long)]
    control_socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TunSetupArgs {
    #[command(flatten)]
    paths: PathArgs,

    /// Network name, exactly as passed to `tsunagi up`.
    #[arg(long, short = 'n')]
    network: String,

    /// The shared secret.
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

    /// The user that should own the interface. Defaults to the current one.
    #[arg(long)]
    user: Option<String>,

    /// Interface name prefix, matching `tsunagi up --wg-prefix`.
    #[arg(long, default_value = "tsun")]
    wg_prefix: String,

    /// Interface MTU, matching `tsunagi up --wg-mtu`. At least 1280.
    #[arg(long)]
    wg_mtu: Option<u32>,

    /// Match `tsunagi up --ipv4-range`.
    #[arg(long, value_name = "CIDR")]
    ipv4_range: Option<String>,
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
        Command::Doctor(paths) => doctor(paths).await,
        Command::Id(paths) => show_id(paths).await,
        Command::Up(args) => up(args).await,
        Command::TunSetup(args) => tun_setup(args).await,
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

async fn status(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref());
    if !socket.exists() {
        return Err(format!(
            "no agent is running for {} (no control socket at {})",
            paths.state_dir.display(),
            socket.display()
        )
        .into());
    }
    let report = tsunagi::ipc::unix::request_status(&socket)
        .await
        .map_err(|err| format!("cannot reach the agent at {}: {err}", socket.display()))?;
    print!("{}", report.render());
    Ok(())
}

/// Works out the interface name and overlay address, then prints the
/// privileged commands that prepare it.
///
/// The address depends on this agent's WireGuard key for the network, so the
/// key store is opened (and the key created on first use) to compute it.
async fn tun_setup(args: TunSetupArgs) -> Result<(), Box<dyn std::error::Error>> {
    use tsunagi::dataplane::wireguard::{
        DEFAULT_MTU, OVERLAY_PREFIX_LEN, WgKeyStore, interface_name, overlay_address,
    };
    use tsunagi::identity::NetworkKeys;

    let name = NetworkName::new(args.network.clone())?;
    let secret = load_secret(args.secret.as_deref(), args.secret_file.as_deref())?;
    let paths = args.paths.resolve()?;
    let network = NetworkKeys::derive(&name, &secret).network_id();

    let store_path = paths.state_dir.join("wireguard").join("wireguard.sqlite");
    let store = tokio::task::spawn_blocking({
        let store_path = store_path.clone();
        move || WgKeyStore::open(store_path)
    })
    .await??;
    let key = tokio::task::spawn_blocking(move || store.load_or_create(network)).await??;

    let interface = interface_name(&args.wg_prefix, network)?;
    let address = overlay_address(network, &key.public());
    let ipv4_range = resolve_ipv4_range(args.ipv4_range.as_ref())?;
    let mtu = args.wg_mtu.unwrap_or(DEFAULT_MTU);
    let user = args.user.unwrap_or_else(|| {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "$USER".to_string())
    });

    println!("# Network  {name} ({network})");
    println!("# Interface {interface}, address {address}/{OVERLAY_PREFIX_LEN}, mtu {mtu}");
    if ipv4_range.is_some() {
        println!(
            "# IPv4 is allocated once the agent runs and agrees with its peers, so it\n\
             # cannot be printed here. Start `tsunagi up`; it prints the exact\n\
             # `ip address add` command for the address it was given."
        );
    }
    println!("# Run once as root; then run `tsunagi up` as {user}.");
    println!(
        "#\n\
         # keep_addr_on_down matters: a persistent TUN interface has no carrier\n\
         # until a process attaches, and Linux flushes IPv6 addresses from an\n\
         # interface that loses carrier unless it is set. `nodad` matters for the\n\
         # same reason: duplicate address detection can never finish without a\n\
         # carrier, leaving the address tentative and unusable.\n"
    );
    println!("sudo ip tuntap add dev {interface} mode tun user {user}");
    println!("sudo ip link set dev {interface} mtu {mtu} up");
    println!("sudo sysctl -qw net.ipv6.conf.{interface}.keep_addr_on_down=1");
    println!("sudo ip -6 address add {address}/{OVERLAY_PREFIX_LEN} dev {interface} nodad");

    println!("\n# To check it afterwards:");
    println!("ip -6 addr show dev {interface}");
    println!("\n# To remove it again:");
    println!("sudo ip link del dev {interface}");
    Ok(())
}

async fn show_id(paths: PathArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = paths.resolve()?;
    println!("state directory  {}", paths.state_dir.display());
    println!("cache directory  {}", paths.cache_dir.display());

    let agent =
        Agent::spawn(AgentConfig::new(paths).with_transport(TransportPolicy::LocalOnly)).await?;
    println!("endpoint id      {}", agent.endpoint_id());
    println!("hostname         {}", agent.hostname());
    for network in agent.list_networks().await? {
        println!(
            "network          {} ({}) auto-start={}",
            network.name, network.network_id, network.auto_start
        );
    }
    agent.shutdown().await;
    Ok(())
}

async fn doctor(paths: PathArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = paths.resolve()?;
    println!("tsunagi doctor\n");

    println!("state directory  {}", paths.state_dir.display());
    println!("cache directory  {}", paths.cache_dir.display());
    match std::fs::create_dir_all(&paths.state_dir) {
        Ok(()) => println!("  writable       yes"),
        Err(err) => println!("  writable       NO ({err})"),
    }

    println!("\ncontrol plane");
    println!("  needs         outbound UDP; no privileges");
    println!("  status        always available");

    println!("\ndata plane (WireGuard)");
    println!("  implementation userspace (boringtun); no kernel module needed");
    #[cfg(feature = "tun-device")]
    {
        let tun_path = std::path::Path::new("/dev/net/tun");
        if cfg!(target_os = "linux") {
            if tun_path.exists() {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(tun_path)
                {
                    Ok(_) => println!("  /dev/net/tun   openable"),
                    Err(err) => println!("  /dev/net/tun   present but not openable ({err})"),
                }
            } else {
                println!("  /dev/net/tun   missing (load the `tun` module)");
            }
        }
        println!("  interfaces     supported on this build");
    }
    #[cfg(not(feature = "tun-device"))]
    println!("  interfaces     not built in (enable the `tun-device` feature)");

    #[cfg(unix)]
    {
        // Creating a network interface needs CAP_NET_ADMIN, which in practice
        // means root unless capabilities were granted explicitly.
        let euid = std::fs::metadata("/proc/self").ok().map(|_| ());
        let _ = euid;
        println!(
            "  privileges     creating an interface needs CAP_NET_ADMIN; \
             use --no-tun to run without it"
        );
    }

    println!("\nlocal addresses");
    let state = netwatch_addresses().await;
    if state.is_empty() {
        println!("  none found");
    }
    for addr in state {
        println!("  {addr}");
    }
    Ok(())
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
    use tsunagi::ipc::{NetworkReport, OverlayPeerReport, OverlayReport, PeerReport, StatusReport};

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
                        transport: format!("{:?}", peer.transport),
                        rtt_ms: peer.rtt.map(|rtt| rtt.as_millis() as u64),
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

#[cfg(feature = "tun-device")]
fn system_tun_factory() -> Result<Arc<dyn TunFactory>, Box<dyn std::error::Error>> {
    use tsunagi::dataplane::wireguard::SystemTunFactory;
    Ok(Arc::new(SystemTunFactory::new()))
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

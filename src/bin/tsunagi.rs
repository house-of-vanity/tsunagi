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
/// `direct` and `n0` publish this endpoint's addresses, keyed by its endpoint
/// id, to Number 0's public lookup service, and resolve peers through it.
/// That is what makes `--peer <endpoint-id>` work without an address.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Transport {
    /// Loopback and the local network only. Publishes nothing.
    Local,
    /// Public address lookup, but no relays.
    Direct,
    /// iroh's defaults: public address lookup plus the public n0 relays.
    N0,
}

impl From<Transport> for TransportPolicy {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Local => TransportPolicy::LocalOnly,
            Transport::Direct => TransportPolicy::DirectOnly,
            Transport::N0 => TransportPolicy::N0Defaults,
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
    #[arg(long, value_enum, default_value_t = Transport::N0)]
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
    #[arg(long)]
    wg_mtu: Option<u32>,

    /// How often to print a status summary, in seconds. Zero disables it.
    #[arg(long, default_value_t = 15)]
    status_interval: u64,
}

impl UpArgs {
    fn load_secret(&self) -> Result<NetworkSecret, Box<dyn std::error::Error>> {
        let text = match (&self.secret, &self.secret_file) {
            (Some(secret), _) => secret.clone(),
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
    }
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
    let secret = args.load_secret()?;
    let paths = args.paths.resolve()?;

    let mut bootstrap: Vec<EndpointAddr> = Vec::new();
    for peer in &args.peers {
        bootstrap.push(parse_peer(peer)?);
    }
    let discovery: Arc<dyn NetworkDiscovery> =
        Arc::new(CompositeDiscovery::new([
            Arc::new(StaticBootstrap::new(bootstrap)) as Arc<dyn NetworkDiscovery>,
        ]));

    let mut config = AgentConfig::new(paths.clone())
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

    agent.shutdown().await;
    println!("stopped.");
    Ok(())
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

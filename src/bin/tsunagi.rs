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
    // Boxed: it is much larger than the other variants, and every command
    // but this one would otherwise pay for its size. A `//` comment, not a
    // `///` one, or clap would print it as help.
    Up(Box<UpArgs>),
    /// Asks a running agent what it is doing.
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
        Command::Doctor(paths) => doctor(paths).await,
        Command::Id(paths) => show_id(paths).await,
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

/// Reports what this machine can and cannot do, and how badly it matters.
///
/// Three levels, and the distinction between the middle two is deliberate:
/// *degraded* is something the agent runs without and that the user can fix
/// from a stated one-liner, *broken* is something it cannot work around.
/// Getting those the wrong way round makes a diagnostic tool useless, so
/// each check below says which it is and why.
async fn doctor(paths: PathArgs) -> Result<(), Box<dyn std::error::Error>> {
    use report::{Health, Report, Row, Section};

    let paths = paths.resolve()?;
    let mut doctor = Report::new();

    // Storage. The asymmetry here is the point: state is mandatory and cache
    // is disposable, so the same failure means different things.
    let mut storage = Section::new("storage");
    storage.push(match std::fs::create_dir_all(&paths.state_dir) {
        Ok(()) => Row::new(
            Health::Good,
            "state directory",
            format!("{} (writable)", paths.state_dir.display()),
        ),
        Err(err) => Row::new(
            Health::Broken,
            "state directory",
            format!("{}: {err}", paths.state_dir.display()),
        )
        .with_note("mandatory: the agent will not start without it"),
    });
    storage.push(match std::fs::create_dir_all(&paths.cache_dir) {
        Ok(()) => Row::new(
            Health::Good,
            "cache directory",
            format!("{} (writable)", paths.cache_dir.display()),
        ),
        Err(err) => Row::new(
            Health::Degraded,
            "cache directory",
            format!("{}: {err}", paths.cache_dir.display()),
        )
        .with_note("disposable: the agent runs, rediscovering what it cached"),
    });
    doctor.push(storage);

    // Control plane. Binding a socket is a real check rather than a claim.
    let mut control = Section::new("control plane");
    control.push(
        match std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
            .or_else(|_| std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)))
        {
            Ok(_) => Row::new(Health::Good, "udp socket", "can bind; no privileges needed"),
            Err(err) => Row::new(Health::Broken, "udp socket", format!("cannot bind: {err}"))
                .with_note("nothing will reach any peer"),
        },
    );
    doctor.push(control);

    let mut data = Section::new("data plane (WireGuard)");
    data.push(Row::new(
        Health::Good,
        "implementation",
        "userspace (boringtun); no kernel module needed",
    ));
    #[cfg(feature = "tun-device")]
    {
        if cfg!(target_os = "linux") {
            let tun_path = std::path::Path::new("/dev/net/tun");
            data.push(if !tun_path.exists() {
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
                data.push(Row::new(Health::Good, "privileges", "CAP_NET_ADMIN held"));
                data.push(Row::new(
                    Health::Good,
                    "interface",
                    "managed by the agent: created on start, removed on exit",
                ));
            }
            Privilege::Missing(_) => {
                // The note is the command and nothing else: a paragraph of
                // explanation belongs in the runtime error, not in a column
                // the eye is meant to scan.
                data.push(
                    Row::new(Health::Degraded, "privileges", "CAP_NET_ADMIN not held")
                        .with_note(format!("sudo setcap cap_net_admin+p {}", program_path())),
                );
                data.push(Row::new(
                    Health::Degraded,
                    "interface",
                    "cannot be created; run with `--no-tun` meanwhile",
                ));
            }
            Privilege::Unsupported => {
                data.push(Row::new(
                    Health::Degraded,
                    "privileges",
                    format!(
                        "managing interfaces is not implemented on {} yet",
                        std::env::consts::OS
                    ),
                ));
                data.push(Row::new(
                    Health::Degraded,
                    "interface",
                    "cannot be created; run with `--no-tun`",
                ));
            }
        }
    }
    #[cfg(not(feature = "tun-device"))]
    data.push(
        Row::new(
            Health::Degraded,
            "interface",
            "not built in; the tunnels run but cannot reach the OS",
        )
        .with_note("rebuild with the `tun-device` feature, or run with `--no-tun`"),
    );
    doctor.push(data);

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
        addresses.push(Row::new(Health::Good, kind, addr.to_string()));
    }
    doctor.push(addresses);

    // `anstream` decides whether the escapes survive: they are stripped when
    // stdout is not a terminal, when NO_COLOR is set, and on a Windows console
    // that cannot render them.
    use std::io::Write;
    let mut out = anstream::stdout().lock();
    writeln!(out, "tsunagi doctor\n")?;
    write!(out, "{}", doctor.render(true))?;
    Ok(())
}

/// The shape of what `tsunagi doctor` reports.
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
                Health::Good => "ok  ",
                Health::Degraded => "warn",
                Health::Broken => "FAIL",
            }
        }

        fn style(self) -> Style {
            let colour = match self {
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
                    out.push_str(&format!(
                        "  {}  {:width$}  {}\n",
                        paint(row.health.style(), row.health.word()),
                        row.label,
                        row.detail,
                        width = width
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

            let worst = self.worst();
            out.push_str(&paint(worst.style(), &self.summary()));
            out.push('\n');
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

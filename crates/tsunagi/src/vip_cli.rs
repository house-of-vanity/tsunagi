//! Named virtual service administration; every mutation submits one complete draft.
use super::{PathArgs, control_socket, resolve_network_index};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use tsunagi::ipc::{self, NetworkReport};
use tsunagi::vip::{Backend, Listener, Protocol, VipConfig, VipStatus};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  tsng vip create lab k8s\n  tsng vip port add lab k8s tcp/443 --backend cp1:6443 --backend cp2:7443\n  tsng vip backend add lab k8s tcp/443 cp3:6443\n  tsng vip status lab k8s --watch\n  tsng vip edit lab k8s\n\nNames, full ids and unique id prefixes are accepted. Changes are shared with the network.\nTCP port checks default to on; UDP uses data-path probes and explicit ICMP errors."
)]
pub(crate) struct VipArgs {
    #[command(flatten)]
    paths: PathArgs,
    /// Agent control socket; defaults to the running service.
    #[arg(long, global = true, env = "TSUNAGI_CONTROL_SOCKET")]
    control_socket: Option<PathBuf>,
    /// Machine-readable configuration and local observations.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    action: Action,
}
#[derive(Debug, Args)]
struct Target {
    /// Network exact name, id or unique id prefix.
    network: String,
    /// VIP exact name, id or unique id prefix.
    vip: String,
}
#[derive(Debug, Args)]
struct PortTarget {
    #[command(flatten)]
    target: Target,
    /// Listener as tcp/443 or udp/53.
    listener: String,
}
#[derive(Debug, Subcommand)]
enum Action {
    /// List services in one network, or every configured network.
    List { network: Option<String> },
    /// Create a named VIP with an automatically reserved internal address.
    Create { network: String, name: String },
    /// Show the complete saved configuration and local status.
    Show(Target),
    /// Show local health, routing choices and cumulative traffic counters.
    Status {
        #[command(flatten)]
        target: Target,
        /// Refresh once a second until interrupted.
        #[arg(long)]
        watch: bool,
    },
    /// Edit the entire configuration in VISUAL/EDITOR and save it atomically.
    Edit(Target),
    /// Remove a VIP; existing flows drain until completion or idle expiry.
    Remove(Target),
    /// Add, configure or remove listeners independently of the VIP.
    Port {
        #[command(subcommand)]
        action: PortAction,
    },
    /// Change a listener's destination nodes and application ports.
    Backend {
        #[command(subcommand)]
        action: BackendAction,
    },
}
#[derive(Debug, Subcommand)]
enum PortAction {
    /// Add a listener, optionally with its complete initial backend set.
    Add {
        #[command(flatten)]
        target: PortTarget,
        /// Node name/id followed by :port. Repeat for multiple destinations.
        #[arg(long)]
        backend: Vec<String>,
    },
    /// Change check settings and flow idle expiry.
    Set {
        #[command(flatten)]
        target: PortTarget,
        /// Active TCP connect checks: on or off.
        #[arg(long,value_parser=["on","off"])]
        port_check: Option<String>,
        /// Milliseconds between active checks (250..3600000).
        #[arg(long)]
        check_interval_ms: Option<u32>,
        /// TCP check deadline in milliseconds (100..60000).
        #[arg(long)]
        check_timeout_ms: Option<u32>,
        /// Consecutive failures before exclusion.
        #[arg(long)]
        failures: Option<u8>,
        /// Consecutive successes before recovery.
        #[arg(long)]
        successes: Option<u8>,
        /// Flow idle expiry in seconds (1..604800).
        #[arg(long)]
        idle_timeout: Option<u32>,
    },
    /// Remove a listener from new-flow selection; existing flows drain.
    Remove(PortTarget),
}
#[derive(Debug, Subcommand)]
enum BackendAction {
    /// Add a destination node and port to a listener.
    Add {
        #[command(flatten)]
        target: PortTarget,
        backend: String,
    },
    /// Remove a destination from new-flow selection.
    Remove {
        #[command(flatten)]
        target: PortTarget,
        backend: String,
    },
}
impl Action {
    fn network(&self) -> Option<&str> {
        match self {
            Self::List { network } => network.as_deref(),
            Self::Create { network, .. } => Some(network),
            Self::Show(t) | Self::Edit(t) | Self::Remove(t) | Self::Status { target: t, .. } => {
                Some(&t.network)
            }
            Self::Port { action } => Some(
                &match action {
                    PortAction::Add { target, .. }
                    | PortAction::Set { target, .. }
                    | PortAction::Remove(target) => target,
                }
                .target
                .network,
            ),
            Self::Backend { action } => Some(
                &match action {
                    BackendAction::Add { target, .. } | BackendAction::Remove { target, .. } => {
                        target
                    }
                }
                .target
                .network,
            ),
        }
    }
}
fn parse_listener(s: &str) -> Result<(Protocol, u16)> {
    let (p, n) = s
        .split_once('/')
        .ok_or("listener must be tcp/PORT or udp/PORT")?;
    let port = n.parse::<u16>()?;
    if port == 0 {
        return Err("port must not be zero".into());
    }
    Ok((p.parse()?, port))
}
fn backend(n: &NetworkReport, s: &str) -> Result<Backend> {
    let (node, port) = s.rsplit_once(':').ok_or("backend must be NODE:PORT")?;
    let peer = match ipc::resolve_node(n, node) {
        Ok(member) => member.endpoint_id.clone(),
        Err(error) => {
            let matches = n
                .members
                .iter()
                .any(|m| m.hostname.as_deref() == Some(node) || m.endpoint_id.starts_with(node));
            if matches {
                return Err(error.into());
            }
            node.parse::<iroh::EndpointId>()
                .map_err(|_| error)?
                .to_string()
        }
    };
    let port = port.parse()?;
    if port == 0 {
        return Err("backend port must not be zero".into());
    }
    Ok(Backend { peer, port })
}
fn selected(n: &NetworkReport, t: &Target) -> Result<VipStatus> {
    Ok(ipc::resolve_vip(n, &t.vip)?.clone())
}
fn listener<'a>(c: &'a mut VipConfig, target: &PortTarget) -> Result<&'a mut Listener> {
    let (p, n) = parse_listener(&target.listener)?;
    c.listeners
        .iter_mut()
        .find(|l| l.protocol == p && l.port == n)
        .ok_or_else(|| format!("no listener {} on {}", target.listener, c.name).into())
}
fn name_of<'a>(n: &'a NetworkReport, peer: &'a str) -> &'a str {
    n.members
        .iter()
        .find(|m| m.endpoint_id == peer)
        .and_then(|m| m.hostname.as_deref())
        .unwrap_or(peer)
}
fn show(n: &NetworkReport, v: &VipStatus, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(v)?);
        return Ok(());
    }
    println!(
        "{}.{}  {}",
        v.config.name,
        n.name,
        v.error.as_deref().unwrap_or("configured")
    );
    for l in &v.listeners {
        let choice = l
            .selected
            .as_ref()
            .map(|b| format!("{}:{}", name_of(n, &b.peer), b.port))
            .unwrap_or_else(|| "none".into());
        println!(
            "  {}/{}  next: {}  flows: {}  tx/rx: {}/{} bytes  drops: {}  UDP failovers: {}",
            l.protocol,
            l.port,
            choice,
            l.backends.iter().map(|b| b.active_flows).sum::<u32>(),
            l.counters.tx_bytes,
            l.counters.rx_bytes,
            l.counters.dropped,
            l.counters.failovers
        );
        for b in &l.backends {
            let rtt = b
                .rtt_us
                .map(|n| format!("{:.2} ms", n as f64 / 1000.))
                .unwrap_or_else(|| "unknown".into());
            println!(
                "    {}:{}  {}  RTT {}  active {}",
                name_of(n, &b.backend.peer),
                b.backend.port,
                b.state,
                rtt,
                b.active_flows
            );
        }
    }
    Ok(())
}
pub(crate) async fn run(args: VipArgs) -> Result<()> {
    let custom = args.paths.state_dir.is_some();
    let paths = args.paths.resolve()?;
    let socket = control_socket(&paths, args.control_socket.as_ref(), custom);
    let report = ipc::request_status(&socket).await?;
    if let Action::List { network: None } = &args.action {
        for n in &report.networks {
            for v in &n.vips {
                show(n, v, args.json)?;
            }
        }
        return Ok(());
    }
    let selector = args.action.network().ok_or("network is required")?;
    let names: Vec<_> = report
        .networks
        .iter()
        .map(|n| (n.network_id.clone(), n.name.clone()))
        .collect();
    let network = &report.networks[resolve_network_index(&names, selector)?];
    if let Action::Status {
        target,
        watch: true,
    } = &args.action
    {
        let mut previous: Option<(std::time::Instant, u64, u64)> = None;
        loop {
            let report = ipc::request_status(&socket).await?;
            let n = report
                .networks
                .iter()
                .find(|n| n.network_id == network.network_id)
                .ok_or("network was removed")?;
            let vip = selected(n, target)?;
            let (tx, rx) = vip.listeners.iter().fold((0u64, 0u64), |a, l| {
                (
                    a.0.saturating_add(l.counters.tx_bytes),
                    a.1.saturating_add(l.counters.rx_bytes),
                )
            });
            let now = std::time::Instant::now();
            if let Some((at, old_tx, old_rx)) = previous
                && !args.json
            {
                let secs = now.duration_since(at).as_secs_f64();
                if secs > 0. {
                    println!(
                        "TX {:.1} KiB/s · RX {:.1} KiB/s",
                        tx.saturating_sub(old_tx) as f64 / secs / 1024.,
                        rx.saturating_sub(old_rx) as f64 / secs / 1024.
                    );
                }
            }
            previous = Some((now, tx, rx));
            show(n, &vip, args.json)?;
            tokio::select! {_=tokio::signal::ctrl_c()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
        }
        return Ok(());
    }
    let mut edited_file = None;
    let (mut config, expected, delete) = match &args.action {
        Action::List { .. } => {
            for v in &network.vips {
                show(network, v, args.json)?;
            }
            return Ok(());
        }
        Action::Show(t) | Action::Status { target: t, .. } => {
            let v = selected(network, t)?;
            show(network, &v, args.json)?;
            if matches!(args.action, Action::Show(_)) && !args.json {
                println!("{}", serde_json::to_string_pretty(&v.config)?);
            }
            return Ok(());
        }
        Action::Create { name, .. } => (VipConfig::new(name), None, false),
        Action::Remove(t) => {
            let v = selected(network, t)?;
            (v.config, Some(v.revision), true)
        }
        Action::Edit(t) => {
            let v = selected(network, t)?;
            let mut file = tempfile::Builder::new()
                .prefix("tsunagi-vip-")
                .suffix(".json")
                .tempfile()?;
            use std::io::Write;
            file.write_all(serde_json::to_string_pretty(&v.config)?.as_bytes())?;
            file.flush()?;
            let editor = std::env::var("VISUAL")
                .or_else(|_| std::env::var("EDITOR"))
                .unwrap_or_else(|_| "vi".into());
            let mut words = editor.split_whitespace();
            let program = words.next().ok_or("empty EDITOR")?;
            let status = std::process::Command::new(program)
                .args(words)
                .arg(file.path())
                .status()?;
            if !status.success() {
                return Err("editor failed; VIP unchanged".into());
            }
            let bytes = std::fs::read(file.path())?;
            let cfg: VipConfig = match serde_json::from_slice(&bytes) {
                Ok(c) => c,
                Err(e) => {
                    let (_, path) = file.keep()?;
                    return Err(
                        format!("invalid draft: {e}; retained at {}", path.display()).into(),
                    );
                }
            };
            if cfg.id != v.config.id {
                return Err("VIP id cannot be edited".into());
            }
            edited_file = Some(file);
            (cfg, Some(v.revision), false)
        }
        Action::Port { action } => {
            let target = match action {
                PortAction::Add { target, .. }
                | PortAction::Set { target, .. }
                | PortAction::Remove(target) => target,
            };
            let v = selected(network, &target.target)?;
            let mut cfg = v.config;
            match action {
                PortAction::Add {
                    target,
                    backend: destinations,
                } => {
                    let (p, port) = parse_listener(&target.listener)?;
                    let mut l = Listener::new(p, port);
                    l.backends = destinations
                        .iter()
                        .map(|b| backend(network, b))
                        .collect::<Result<_>>()?;
                    cfg.listeners.push(l);
                }
                PortAction::Remove(target) => {
                    let (p, port) = parse_listener(&target.listener)?;
                    listener(&mut cfg, target)?;
                    cfg.listeners.retain(|l| l.protocol != p || l.port != port);
                }
                PortAction::Set {
                    target,
                    port_check,
                    check_interval_ms,
                    check_timeout_ms,
                    failures,
                    successes,
                    idle_timeout,
                } => {
                    let l = listener(&mut cfg, target)?;
                    if let Some(v) = port_check {
                        l.port_check = v == "on";
                    }
                    if let Some(v) = check_interval_ms {
                        l.check_interval_ms = *v;
                    }
                    if let Some(v) = check_timeout_ms {
                        l.check_timeout_ms = *v;
                    }
                    if let Some(v) = failures {
                        l.failure_threshold = *v;
                    }
                    if let Some(v) = successes {
                        l.recovery_threshold = *v;
                    }
                    if let Some(v) = idle_timeout {
                        l.idle_timeout_secs = *v;
                    }
                }
            }
            (cfg, Some(v.revision), false)
        }
        Action::Backend { action } => {
            let (target, destination, remove) = match action {
                BackendAction::Add { target, backend } => (target, backend, false),
                BackendAction::Remove { target, backend } => (target, backend, true),
            };
            let v = selected(network, &target.target)?;
            let mut cfg = v.config;
            let b = backend(network, destination)?;
            let l = listener(&mut cfg, target)?;
            if remove {
                if !l.backends.contains(&b) {
                    return Err("backend is not configured".into());
                }
                l.backends.retain(|x| x != &b);
            } else {
                l.backends.push(b);
            }
            (cfg, Some(v.revision), false)
        }
    };
    // Canonical order makes displayed drafts and shared state deterministic.
    config.listeners.sort_by_key(|l| (l.protocol, l.port));
    for l in &mut config.listeners {
        l.backends.sort();
    }
    let id = config.id.clone();
    let vips = match ipc::save_vip(&socket, &network.network_id, config, expected, delete).await {
        Ok(vips) => vips,
        Err(error) => {
            if let Some(file) = edited_file {
                let (_, path) = file.keep()?;
                return Err(format!("{error}; draft retained at {}", path.display()).into());
            }
            return Err(error.into());
        }
    };
    if delete {
        if args.json {
            println!("{{\"removed\":\"{id}\"}}");
        } else {
            println!("VIP removed; existing flows drain.");
        }
    } else if let Some(v) = vips.iter().find(|v| v.config.id == id) {
        show(network, v, args.json)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn vip_commands_parse_complete_listener_and_settings() {
        let cli = super::super::Cli::try_parse_from([
            "tsng",
            "vip",
            "port",
            "add",
            "lab",
            "k8s",
            "tcp/443",
            "--backend",
            "cp1:6443",
            "--backend",
            "cp2:7443",
        ]);
        assert!(cli.is_ok(), "{cli:?}");
        assert!(
            super::super::Cli::try_parse_from([
                "tsng",
                "vip",
                "port",
                "set",
                "lab",
                "k8s",
                "tcp/443",
                "--port-check",
                "off",
                "--failures",
                "3"
            ])
            .is_ok()
        );
        assert!(parse_listener("tcp/0").is_err());
        assert!(parse_listener("sctp/53").is_err());
    }
}

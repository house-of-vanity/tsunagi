//! A backend that drives the standard `wg` and `ip` tools.
//!
//! This is the one part of the plugin that changes the operating system. It is
//! split in two deliberately:
//!
//! * a **pure planner** that turns a desired configuration into an exact list
//!   of commands, and pure **parsers** for the tools' output — both fully
//!   unit tested on every platform;
//! * a thin executor that runs the plan, which needs Linux and
//!   `CAP_NET_ADMIN`.
//!
//! Nothing that arrives from the network is ever passed through as text. Peer
//! keys, endpoints, allowed prefixes and keepalives are typed values that this
//! module re-serialises itself, so an announcement cannot inject an argument
//! or a configuration directive. The only names involved are derived locally.
//!
//! The interface is created by this plugin and removed by this plugin. An
//! interface that already exists and is not a WireGuard device is refused, not
//! adopted, so the agent never takes over something it did not create.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use zeroize::Zeroizing;

use crate::dataplane::PluginError;

use super::config::{Cidr, InterfaceConfig, InterfaceState, PeerState};
use super::keys::{WgPublicKey, WgSecretKey};

/// Which external programs to use.
#[derive(Debug, Clone)]
pub struct Tools {
    /// The `wg` executable.
    pub wg: String,
    /// The `ip` executable.
    pub ip: String,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            wg: "wg".into(),
            ip: "ip".into(),
        }
    }
}

/// One command to run, with optional data for its standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgCommand {
    /// Program to execute.
    pub program: String,
    /// Arguments, already separated. Never a shell string.
    pub args: Vec<String>,
    /// Data piped to the program's standard input.
    ///
    /// Used for the WireGuard configuration so the private key never reaches
    /// the filesystem. Zeroized on drop.
    pub stdin: Option<Zeroizing<String>>,
}

impl WgCommand {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            stdin: None,
        }
    }

    /// A redacted rendering, safe for logs.
    pub fn describe(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// Builds the commands that bring `desired` into being.
///
/// `current` is what the interface looks like now, or `None` if it does not
/// exist yet. The plan is minimal: an interface that already matches produces
/// only the idempotent link-up command.
pub fn plan_apply(
    desired: &InterfaceConfig,
    current: Option<&InterfaceState>,
    tools: &Tools,
) -> Vec<WgCommand> {
    let mut plan = Vec::new();
    let name = desired.name.as_str();

    if current.is_none() {
        plan.push(WgCommand::new(
            &tools.ip,
            &["link", "add", "dev", name, "type", "wireguard"],
        ));
    }

    // `setconf` replaces everything, `syncconf` applies a difference without
    // tearing down live peers. Use each where it belongs.
    let subcommand = if current.is_none() {
        "setconf"
    } else {
        "syncconf"
    };
    let mut configure = WgCommand::new(&tools.wg, &[subcommand, name, "/dev/stdin"]);
    configure.stdin = Some(desired.render());
    plan.push(configure);

    let desired_addrs: BTreeSet<Cidr> = desired.addresses.iter().copied().collect();
    let current_addrs: BTreeSet<Cidr> = current
        .map(|state| state.addresses.iter().copied().collect())
        .unwrap_or_default();

    for addr in desired_addrs.difference(&current_addrs) {
        plan.push(WgCommand::new(
            &tools.ip,
            &["address", "add", &addr.to_string(), "dev", name],
        ));
    }
    // Addresses on an interface this plugin owns that are not wanted any more
    // were either put there by an older configuration or by hand. Either way
    // reconciliation removes them.
    for addr in current_addrs.difference(&desired_addrs) {
        plan.push(WgCommand::new(
            &tools.ip,
            &["address", "del", &addr.to_string(), "dev", name],
        ));
    }

    if let Some(mtu) = desired.mtu {
        plan.push(WgCommand::new(
            &tools.ip,
            &["link", "set", "mtu", &mtu.to_string(), "dev", name],
        ));
    }

    plan.push(WgCommand::new(
        &tools.ip,
        &["link", "set", "up", "dev", name],
    ));
    plan
}

/// Builds the commands that remove an interface this plugin created.
pub fn plan_remove(interface: &str, tools: &Tools) -> Vec<WgCommand> {
    vec![WgCommand::new(
        &tools.ip,
        &["link", "del", "dev", interface],
    )]
}

/// Parses the output of `wg showconf <interface>`.
///
/// The private key present in that output is used only to derive the
/// interface's public key and is dropped immediately.
pub fn parse_showconf(interface: &str, text: &str) -> Result<InterfaceState, PluginError> {
    #[derive(Default)]
    struct PartialPeer {
        public_key: Option<WgPublicKey>,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<Cidr>,
        persistent_keepalive: Option<u16>,
    }

    let mut public_key: Option<WgPublicKey> = None;
    let mut listen_port = 0u16;
    let mut peers: Vec<PeerState> = Vec::new();
    let mut current: Option<PartialPeer> = None;

    let finish = |peer: PartialPeer, peers: &mut Vec<PeerState>| -> Result<(), PluginError> {
        let key = peer
            .public_key
            .ok_or_else(|| PluginError::Other("wg showconf peer without a public key".into()))?;
        peers.push(
            PeerState {
                public_key: key,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips,
                persistent_keepalive: peer.persistent_keepalive,
            }
            .normalised(),
        );
        Ok(())
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.eq_ignore_ascii_case("[interface]") {
            if let Some(peer) = current.take() {
                finish(peer, &mut peers)?;
            }
            continue;
        }
        if line.eq_ignore_ascii_case("[peer]") {
            if let Some(peer) = current.take() {
                finish(peer, &mut peers)?;
            }
            current = Some(PartialPeer::default());
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let name = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match current.as_mut() {
            None => match name.as_str() {
                "privatekey" => {
                    // Derive the public key, then let the secret drop.
                    let raw = data_encoding::BASE64
                        .decode(value.as_bytes())
                        .map_err(|_| {
                            PluginError::Other("wg showconf private key is not base64".into())
                        })?;
                    let bytes = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
                        PluginError::Other("wg showconf private key is not 32 bytes".into())
                    })?;
                    public_key = Some(WgSecretKey::from_bytes(&bytes).public());
                }
                "listenport" => {
                    listen_port = value
                        .parse()
                        .map_err(|_| PluginError::Other(format!("bad listen port {value:?}")))?;
                }
                _ => {}
            },
            Some(peer) => match name.as_str() {
                "publickey" => peer.public_key = Some(WgPublicKey::decode(value)?),
                "endpoint" => peer.endpoint = value.parse().ok(),
                "allowedips" => {
                    for entry in value.split(',') {
                        let entry = entry.trim();
                        if entry.is_empty() {
                            continue;
                        }
                        peer.allowed_ips.push(parse_cidr(entry)?);
                    }
                }
                "persistentkeepalive" => {
                    peer.persistent_keepalive =
                        match value {
                            "off" => None,
                            other => Some(other.parse().map_err(|_| {
                                PluginError::Other(format!("bad keepalive {other:?}"))
                            })?),
                        };
                }
                _ => {}
            },
        }
    }
    if let Some(peer) = current.take() {
        finish(peer, &mut peers)?;
    }

    let public_key = public_key
        .ok_or_else(|| PluginError::Other("wg showconf did not report a private key".into()))?;

    Ok(InterfaceState {
        name: interface.to_string(),
        public_key,
        listen_port,
        addresses: Vec::new(),
        peers,
    }
    .normalised())
}

/// Parses the addresses out of `ip -o address show dev <interface>`.
pub fn parse_ip_addresses(text: &str) -> Result<Vec<Cidr>, PluginError> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            if token != "inet" && token != "inet6" {
                continue;
            }
            let Some(value) = tokens.next() else {
                continue;
            };
            // A link-local address is added by the kernel, not by us.
            let cidr = parse_cidr(value)?;
            if cidr.addr.is_loopback() {
                continue;
            }
            if let std::net::IpAddr::V6(ip) = cidr.addr
                && (ip.segments()[0] & 0xffc0) == 0xfe80
            {
                continue;
            }
            out.push(cidr);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn parse_cidr(text: &str) -> Result<Cidr, PluginError> {
    let (addr, prefix) = text
        .split_once('/')
        .ok_or_else(|| PluginError::Other(format!("{text:?} is not an address with a prefix")))?;
    let addr = addr
        .parse()
        .map_err(|_| PluginError::Other(format!("{addr:?} is not an IP address")))?;
    let prefix_len = prefix
        .parse()
        .map_err(|_| PluginError::Other(format!("{prefix:?} is not a prefix length")))?;
    Cidr::new(addr, prefix_len)
}

pub use executor::WgToolBackend;

#[cfg(target_os = "linux")]
mod executor {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::*;
    use crate::dataplane::wireguard::backend::WireguardBackend;

    /// Drives the real `wg` and `ip` tools.
    ///
    /// Requires Linux and `CAP_NET_ADMIN`, so it is never used by the default
    /// test suite.
    #[derive(Debug, Clone)]
    pub struct WgToolBackend {
        tools: Tools,
    }

    impl WgToolBackend {
        /// Creates a backend using `wg` and `ip` from `PATH`.
        pub fn new() -> Result<Self, PluginError> {
            Self::with_tools(Tools::default())
        }

        /// Creates a backend using explicitly located tools.
        pub fn with_tools(tools: Tools) -> Result<Self, PluginError> {
            Ok(Self { tools })
        }

        fn run(&self, command: &WgCommand) -> Result<String, PluginError> {
            let mut child = Command::new(&command.program)
                .args(&command.args)
                .stdin(if command.stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|err| {
                    PluginError::Unavailable(format!("cannot run `{}`: {err}", command.program))
                })?;

            if let Some(stdin) = &command.stdin {
                let mut handle = child.stdin.take().ok_or_else(|| {
                    PluginError::Other("could not open the child's standard input".into())
                })?;
                handle.write_all(stdin.as_bytes()).map_err(|err| {
                    PluginError::Other(format!("cannot write the WireGuard configuration: {err}"))
                })?;
                drop(handle);
            }

            let output = child.wait_with_output().map_err(|err| {
                PluginError::Other(format!("`{}` did not complete: {err}", command.describe()))
            })?;
            if !output.status.success() {
                // The configuration went to stdin, so stderr cannot contain it.
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Err(PluginError::Unavailable(format!(
                    "`{}` failed: {stderr}",
                    command.describe()
                )));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }

        fn link_exists(&self, interface: &str) -> bool {
            Command::new(&self.tools.ip)
                .args(["link", "show", "dev", interface])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        }
    }

    impl WireguardBackend for WgToolBackend {
        fn name(&self) -> &str {
            "wg-tools"
        }

        fn inspect(&self, interface: &str) -> Result<Option<InterfaceState>, PluginError> {
            if !self.link_exists(interface) {
                return Ok(None);
            }
            let showconf = WgCommand::new(&self.tools.wg, &["showconf", interface]);
            let text = match self.run(&showconf) {
                Ok(text) => text,
                Err(_) => {
                    // The link exists but is not a WireGuard device. It is not
                    // ours, so it is refused rather than adopted or modified.
                    return Err(PluginError::Rejected(format!(
                        "interface `{interface}` already exists and is not a WireGuard device; \
                         refusing to touch it"
                    )));
                }
            };
            let mut state = parse_showconf(interface, &text)?;
            let addresses = self.run(&WgCommand::new(
                &self.tools.ip,
                &["-o", "address", "show", "dev", interface],
            ))?;
            state.addresses = parse_ip_addresses(&addresses)?;
            Ok(Some(state.normalised()))
        }

        fn apply(&self, desired: &InterfaceConfig) -> Result<(), PluginError> {
            let current = self.inspect(&desired.name)?;
            for command in plan_apply(desired, current.as_ref(), &self.tools) {
                self.run(&command)?;
            }
            Ok(())
        }

        fn remove(&self, interface: &str) -> Result<(), PluginError> {
            if !self.link_exists(interface) {
                return Ok(());
            }
            for command in plan_remove(interface, &self.tools) {
                self.run(&command)?;
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod executor {
    use super::*;

    /// Placeholder on platforms where this backend is not implemented.
    ///
    /// The planner and the parsers in this module work everywhere; only
    /// applying a configuration is Linux-specific.
    #[derive(Debug, Clone)]
    pub struct WgToolBackend {
        _private: (),
    }

    impl WgToolBackend {
        /// Always fails: this backend drives `ip link ... type wireguard`,
        /// which exists on Linux only.
        pub fn new() -> Result<Self, PluginError> {
            Self::with_tools(Tools::default())
        }

        /// Always fails, see [`WgToolBackend::new`].
        pub fn with_tools(_tools: Tools) -> Result<Self, PluginError> {
            Err(PluginError::Unavailable(
                "the wg-tools backend is implemented for Linux only".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::dataplane::wireguard::config::{InterfaceParams, build_interface};
    use crate::dataplane::wireguard::keys::WgSecretKey;
    use crate::dataplane::wireguard::overlay::overlay_address;
    use crate::identity::{NetworkId, NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![4u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn sample() -> (NetworkId, InterfaceConfig, WgPublicKey) {
        let id = network("plan");
        let peer = WgSecretKey::generate().public();
        let config = build_interface(
            InterfaceParams {
                network: id,
                name: "tsun0".into(),
                private_key: WgSecretKey::generate(),
                listen_port: 51820,
                mtu: Some(1380),
                keepalive: Some(25),
            },
            [peer],
            |_| Some("10.0.0.5:51820".parse().unwrap()),
        );
        (id, config, peer)
    }

    #[test]
    fn creating_an_interface_plans_every_step_in_order() {
        let (_, config, _) = sample();
        let plan = plan_apply(&config, None, &Tools::default());
        let described: Vec<String> = plan.iter().map(WgCommand::describe).collect();

        assert_eq!(described[0], "ip link add dev tsun0 type wireguard");
        assert_eq!(described[1], "wg setconf tsun0 /dev/stdin");
        assert!(plan[1].stdin.is_some(), "the config goes over stdin");
        assert!(described.iter().any(|c| c.starts_with("ip address add")));
        assert!(described.contains(&"ip link set mtu 1380 dev tsun0".to_string()));
        assert_eq!(described.last().unwrap(), "ip link set up dev tsun0");
    }

    #[test]
    fn updating_an_existing_interface_syncs_instead_of_replacing() {
        let (_, config, _) = sample();
        let current = config.to_state();
        let plan = plan_apply(&config, Some(&current), &Tools::default());
        let described: Vec<String> = plan.iter().map(WgCommand::describe).collect();

        assert!(
            !described.iter().any(|c| c.contains("link add")),
            "an existing interface must not be recreated"
        );
        assert_eq!(described[0], "wg syncconf tsun0 /dev/stdin");
        assert!(
            !described.iter().any(|c| c.starts_with("ip address add")),
            "matching addresses need no change: {described:?}"
        );
    }

    #[test]
    fn addresses_that_should_not_be_there_are_removed() {
        let (_, config, _) = sample();
        let mut current = config.to_state();
        current.addresses.push(Cidr {
            addr: "192.0.2.1".parse().unwrap(),
            prefix_len: 32,
        });
        let plan = plan_apply(&config, Some(&current), &Tools::default());
        let described: Vec<String> = plan.iter().map(WgCommand::describe).collect();
        assert!(
            described.contains(&"ip address del 192.0.2.1/32 dev tsun0".to_string()),
            "{described:?}"
        );
    }

    #[test]
    fn nothing_from_the_network_reaches_an_argument_as_text() {
        let (id, config, peer) = sample();
        let plan = plan_apply(&config, None, &Tools::default());
        for command in &plan {
            for arg in &command.args {
                assert!(
                    !arg.contains(' ') && !arg.contains(';') && !arg.contains('\n'),
                    "argument {arg:?} is not a single clean token"
                );
            }
        }
        // The peer's key and derived prefix travel in the piped configuration,
        // which is a value this crate rendered itself.
        let rendered = plan[1].stdin.as_ref().unwrap();
        assert!(rendered.contains(&peer.encode()));
        assert!(rendered.contains(&Cidr::host(overlay_address(id, &peer)).to_string()));
    }

    #[test]
    fn removal_only_touches_the_named_interface() {
        let plan = plan_remove("tsun0", &Tools::default());
        assert_eq!(
            plan.iter().map(WgCommand::describe).collect::<Vec<_>>(),
            vec!["ip link del dev tsun0".to_string()]
        );
    }

    #[test]
    fn showconf_output_parses_into_comparable_state() {
        let secret = WgSecretKey::generate();
        let peer_a = WgSecretKey::generate().public();
        let peer_b = WgSecretKey::generate().public();
        let text = format!(
            "[Interface]\n\
             ListenPort = 51821\n\
             PrivateKey = {}\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             AllowedIPs = fd00::2/128, fd00::3/128\n\
             Endpoint = 10.0.0.9:51820\n\
             PersistentKeepalive = 25\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             AllowedIPs = fd00::4/128\n\
             PersistentKeepalive = off\n",
            secret.encode().as_str(),
            peer_a.encode(),
            peer_b.encode(),
        );

        let state = parse_showconf("tsun0", &text).unwrap();
        assert_eq!(state.public_key, secret.public());
        assert_eq!(state.listen_port, 51821);
        assert_eq!(state.peers.len(), 2);

        let a = state
            .peers
            .iter()
            .find(|peer| peer.public_key == peer_a)
            .unwrap();
        assert_eq!(a.endpoint, Some("10.0.0.9:51820".parse().unwrap()));
        assert_eq!(a.allowed_ips.len(), 2);
        assert_eq!(a.persistent_keepalive, Some(25));

        let b = state
            .peers
            .iter()
            .find(|peer| peer.public_key == peer_b)
            .unwrap();
        assert_eq!(b.endpoint, None);
        assert_eq!(b.persistent_keepalive, None);
    }

    #[test]
    fn malformed_tool_output_is_an_error_not_a_panic() {
        assert!(parse_showconf("tsun0", "").is_err());
        assert!(parse_showconf("tsun0", "[Interface]\nListenPort = nope\n").is_err());
        assert!(parse_showconf("tsun0", "[Peer]\nAllowedIPs = fd00::1/128\n").is_err());
        assert!(parse_showconf("tsun0", "[Interface]\nPrivateKey = zzzz\n").is_err());
        assert!(parse_ip_addresses("1: tsun0 inet6 not-an-address scope global").is_err());
    }

    #[test]
    fn interface_addresses_parse_and_skip_kernel_managed_ones() {
        let text = "3: tsun0    inet6 fd12:3456::1/128 scope global \\       valid_lft forever\n\
                    3: tsun0    inet6 fd12:3456::/64 scope global \\       valid_lft forever\n\
                    3: tsun0    inet6 fe80::1/64 scope link \\       valid_lft forever\n";
        let addresses = parse_ip_addresses(text).unwrap();
        assert_eq!(
            addresses.iter().map(Cidr::to_string).collect::<Vec<_>>(),
            vec!["fd12:3456::/64".to_string(), "fd12:3456::1/128".to_string()]
        );
    }

    #[test]
    fn a_rendered_config_round_trips_through_the_parser() {
        let (_, config, _) = sample();
        let rendered = config.render();
        let parsed = parse_showconf(&config.name, &rendered).unwrap();
        let mut expected = config.to_state();
        // showconf does not report interface addresses.
        expected.addresses.clear();
        assert_eq!(parsed, expected);
    }
}

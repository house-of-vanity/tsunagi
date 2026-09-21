//! The boundary to the operating system's packet interface.
//!
//! The WireGuard implementation in [`super::device`] is pure userspace and
//! needs no kernel WireGuard module and no `wg` tool. It does still need a way
//! to hand IP packets to the operating system, which is what this trait is.
//!
//! Two implementations:
//!
//! * [`MemoryTun`] keeps packets in memory. It needs no privileges at all and
//!   is what the test suite uses, so the entire data plane — handshake,
//!   encryption, routing — is exercised without touching the host.
//! * `SystemTun`, behind the `tun-device` feature, is a real TUN interface.
//!   Creating one needs `CAP_NET_ADMIN` on Linux or the equivalent elsewhere.

use std::net::Ipv6Addr;
use std::sync::Arc;

use bytes::Bytes;

use crate::BoxFuture;
use crate::dataplane::PluginError;

/// What a device should look like once created.
#[derive(Debug, Clone)]
pub struct TunRequest {
    /// Interface name to ask for.
    pub name: String,
    /// The overlay address this host answers to.
    pub address: Ipv6Addr,
    /// Prefix length of the overlay subnet, so the OS routes it here.
    pub prefix_len: u8,
    /// The IPv4 overlay address this host answers to, when dual stack.
    pub address_v4: Option<std::net::Ipv4Addr>,
    /// Prefix length of the IPv4 overlay range.
    pub prefix_len_v4: u8,
    /// Interface MTU.
    pub mtu: u32,
}

/// A packet interface.
///
/// `recv` yields packets the operating system wants sent; `send` delivers
/// packets that arrived from a peer.
pub trait TunDevice: Send + Sync + std::fmt::Debug + 'static {
    /// The interface name the operating system actually gave us.
    fn name(&self) -> &str;

    /// The interface MTU.
    fn mtu(&self) -> u32;

    /// The next packet the operating system wants to send, or `None` once the
    /// device is gone.
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>>;

    /// Delivers a packet to the operating system.
    fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), PluginError>>;
}

/// Creates packet interfaces.
pub trait TunFactory: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Creates a device.
    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, PluginError>>;
}

/// An in-memory packet interface.
///
/// Nothing reaches the operating system. Packets the device "sends" can be
/// read back with [`MemoryTun::pop_to_os`], and packets can be injected as if
/// the operating system produced them with [`MemoryTun::push_from_os`].
#[derive(Debug)]
pub struct MemoryTun {
    name: String,
    mtu: u32,
    from_os_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    from_os_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Bytes>>,
    to_os_tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    to_os_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Bytes>>,
}

impl MemoryTun {
    /// Creates a device with the given name and MTU.
    pub fn new(name: impl Into<String>, mtu: u32) -> Arc<Self> {
        let (from_os_tx, from_os_rx) = tokio::sync::mpsc::unbounded_channel();
        let (to_os_tx, to_os_rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            name: name.into(),
            mtu,
            from_os_tx,
            from_os_rx: tokio::sync::Mutex::new(from_os_rx),
            to_os_tx,
            to_os_rx: tokio::sync::Mutex::new(to_os_rx),
        })
    }

    /// Injects a packet as if the operating system had produced it.
    pub fn push_from_os(&self, packet: Bytes) {
        let _ = self.from_os_tx.send(packet);
    }

    /// Takes the next packet the device delivered to the operating system.
    pub async fn pop_to_os(&self) -> Option<Bytes> {
        self.to_os_rx.lock().await.recv().await
    }
}

impl TunDevice for MemoryTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move { self.from_os_rx.lock().await.recv().await })
    }

    fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), PluginError>> {
        Box::pin(async move {
            let _ = self.to_os_tx.send(packet);
            Ok(())
        })
    }
}

/// Whether an address is assigned to some interface on this host.
///
/// Binding a UDP socket to a specific address only succeeds when the address
/// is local, which makes this a cheap check that needs no privileges and no
/// platform-specific code. It does not say *which* interface has it, which is
/// enough here: the agent chose the address, so anything else holding it is a
/// problem in its own right.
pub fn address_is_local(address: std::net::IpAddr) -> bool {
    std::net::UdpSocket::bind((address, 0)).is_ok()
}

/// Creates [`MemoryTun`] devices.
#[derive(Debug, Clone, Default)]
pub struct MemoryTunFactory {
    created: Arc<std::sync::Mutex<Vec<Arc<MemoryTun>>>>,
}

impl MemoryTunFactory {
    /// Creates a factory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The device created for an interface name, if any.
    pub fn device(&self, name: &str) -> Option<Arc<MemoryTun>> {
        let guard = match self.created.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .iter()
            .find(|device| device.name() == name)
            .map(Arc::clone)
    }

    /// Every device created so far.
    pub fn devices(&self) -> Vec<Arc<MemoryTun>> {
        let guard = match self.created.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
    }
}

impl TunFactory for MemoryTunFactory {
    fn name(&self) -> &str {
        "memory"
    }

    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, PluginError>> {
        Box::pin(async move {
            let device = MemoryTun::new(request.name, request.mtu);
            let mut guard = match self.created.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push(Arc::clone(&device));
            Ok(device as Arc<dyn TunDevice>)
        })
    }
}

#[cfg(feature = "tun-device")]
pub use system::{
    Assigned, SystemTunFactory, interface_addresses, interface_exists, parse_if_inet6,
    setup_commands,
};

#[cfg(feature = "tun-device")]
mod system {
    use std::net::Ipv6Addr;
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::sync::Mutex;

    use super::{TunDevice, TunFactory, TunRequest};
    use crate::BoxFuture;
    use crate::dataplane::PluginError;

    /// A real TUN interface.
    ///
    /// Two ways to get one, and the difference is who needs privileges:
    ///
    /// * **Attach** to an interface that already exists. Needs no privileges
    ///   at all, as long as the interface was created persistent and owned by
    ///   this user. This is the recommended way to run the agent unprivileged.
    /// * **Create** it here, which needs `CAP_NET_ADMIN`.
    ///
    /// Either way the overlay address has to be assigned by something
    /// privileged: assigning an IPv6 address to an interface is not something
    /// this crate's dependencies can do, so the agent checks that it is there
    /// and says exactly what to run if it is not, rather than coming up in a
    /// state where no traffic could ever arrive.
    pub struct SystemTun {
        name: String,
        mtu: u32,
        reader: Mutex<tokio::io::ReadHalf<tun::AsyncDevice>>,
        writer: Mutex<tokio::io::WriteHalf<tun::AsyncDevice>>,
    }

    impl std::fmt::Debug for SystemTun {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SystemTun")
                .field("name", &self.name)
                .field("mtu", &self.mtu)
                .finish()
        }
    }

    impl TunDevice for SystemTun {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
            Box::pin(async move {
                use tokio::io::AsyncReadExt;
                let mut buffer = vec![0u8; self.mtu as usize + 64];
                let mut reader = self.reader.lock().await;
                match reader.read(&mut buffer).await {
                    Ok(0) => None,
                    Ok(read) => {
                        buffer.truncate(read);
                        Some(Bytes::from(buffer))
                    }
                    Err(err) => {
                        tracing::debug!(%err, "tun read failed");
                        None
                    }
                }
            })
        }

        fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), PluginError>> {
            Box::pin(async move {
                use tokio::io::AsyncWriteExt;
                let mut writer = self.writer.lock().await;
                writer
                    .write_all(&packet)
                    .await
                    .map_err(|err| PluginError::Other(format!("tun write failed: {err}")))
            })
        }
    }

    /// Whether an interface of this name exists.
    pub fn interface_exists(name: &str) -> bool {
        std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
    }

    /// `IFA_F_TENTATIVE`: the address is not usable until DAD finishes, which
    /// never happens on an interface with no carrier.
    const IFA_F_TENTATIVE: u32 = 0x40;
    /// `IFA_F_DADFAILED`: duplicate address detection rejected it.
    const IFA_F_DADFAILED: u32 = 0x08;

    /// One IPv6 address assigned to an interface.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Assigned {
        /// The address.
        pub address: Ipv6Addr,
        /// Raw `IFA_F_*` flags as the kernel reports them.
        pub flags: u32,
    }

    impl Assigned {
        /// Whether the address can actually carry traffic.
        pub fn is_usable(&self) -> bool {
            self.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED) == 0
        }

        /// A short explanation when it cannot.
        pub fn why_unusable(&self) -> Option<&'static str> {
            if self.flags & IFA_F_DADFAILED != 0 {
                Some("duplicate address detection failed")
            } else if self.flags & IFA_F_TENTATIVE != 0 {
                Some(
                    "still tentative; duplicate address detection cannot finish \
                      on an interface with no carrier, so add it with `nodad`",
                )
            } else {
                None
            }
        }
    }

    /// Parses the IPv6 addresses of one interface out of `/proc/net/if_inet6`.
    ///
    /// Each line is `<32 hex address> <ifindex> <prefixlen> <scope> <flags>
    /// <device>`, all hexadecimal.
    pub fn parse_if_inet6(contents: &str, name: &str) -> Vec<Assigned> {
        contents
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 || fields[5] != name {
                    return None;
                }
                let raw = <[u8; 16]>::try_from(hex::decode(fields[0]).ok()?.as_slice()).ok()?;
                Some(Assigned {
                    address: Ipv6Addr::from(raw),
                    flags: u32::from_str_radix(fields[4], 16).unwrap_or(0),
                })
            })
            .collect()
    }

    /// The IPv6 addresses of an interface, or `None` if that cannot be read.
    ///
    /// Reads `/proc/net/if_inet6`, which needs no privileges.
    pub fn interface_addresses(name: &str) -> Option<Vec<Assigned>> {
        let contents = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
        Some(parse_if_inet6(&contents, name))
    }

    /// What is wrong with an interface's addressing, if anything.
    pub(crate) fn check_address(name: &str, wanted: Ipv6Addr) -> Result<(), String> {
        let Some(assigned) = interface_addresses(name) else {
            // Cannot tell. Carry on rather than block on a guess.
            return Ok(());
        };
        match assigned.iter().find(|entry| entry.address == wanted) {
            Some(entry) if entry.is_usable() => Ok(()),
            Some(entry) => Err(format!(
                "interface `{name}` has {wanted} but it is unusable: {}",
                entry.why_unusable().unwrap_or("unknown reason")
            )),
            None => {
                let present = if assigned.is_empty() {
                    "it currently has no IPv6 address at all".to_string()
                } else {
                    format!(
                        "it currently has: {}",
                        assigned
                            .iter()
                            .map(|entry| entry.address.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                Err(format!(
                    "interface `{name}` has no {wanted} address, {present}"
                ))
            }
        }
    }

    /// The commands a privileged user runs once to prepare an interface.
    ///
    /// The order and the two extra settings matter. A persistent TUN
    /// interface has no carrier until a process attaches to it, and Linux
    /// flushes IPv6 addresses from an interface that loses carrier unless
    /// `keep_addr_on_down` is set — so an address added without it silently
    /// disappears before the agent ever starts. `nodad` is needed for the same
    /// reason: duplicate address detection can never finish with no carrier,
    /// and the address would stay tentative and unusable.
    pub fn setup_commands(request: &TunRequest, user: &str) -> Vec<String> {
        let mut commands = vec![
            format!(
                "sudo ip tuntap add dev {} mode tun user {user}",
                request.name
            ),
            format!(
                "sudo ip link set dev {} mtu {} up",
                request.name, request.mtu
            ),
            format!(
                "sudo sysctl -qw net.ipv6.conf.{}.keep_addr_on_down=1",
                request.name
            ),
            format!(
                "sudo ip -6 address add {}/{} dev {} nodad",
                request.address, request.prefix_len, request.name
            ),
        ];
        if let Some(address) = request.address_v4 {
            let prefix_len = request.prefix_len_v4;
            // IPv4 is not sensitive to carrier the way IPv6 is, so it needs
            // no extra settings.
            commands.push(format!(
                "sudo ip address add {address}/{prefix_len} dev {}",
                request.name
            ));
        }
        commands
    }

    fn current_user() -> String {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "$USER".to_string())
    }

    /// Opens real TUN interfaces.
    #[derive(Debug, Clone, Default)]
    pub struct SystemTunFactory;

    impl SystemTunFactory {
        /// Creates the factory.
        pub fn new() -> Self {
            Self
        }
    }

    impl TunFactory for SystemTunFactory {
        fn name(&self) -> &str {
            "system"
        }

        fn create<'a>(
            &'a self,
            request: TunRequest,
        ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, PluginError>> {
            Box::pin(async move {
                let existed = interface_exists(&request.name);

                // Check before attaching. Opening and then dropping the
                // device toggles the carrier, and with the default
                // `keep_addr_on_down=0` that is enough to flush the very
                // address we are looking for.
                if existed && let Err(reason) = check_address(&request.name, request.address) {
                    let commands = setup_commands(&request, &current_user()).join("\n  ");
                    return Err(PluginError::Unavailable(format!(
                        "{reason}.\nAssigning an IPv6 address needs privileges. \
                         Remove the interface and prepare it again:\n  sudo ip link del dev {}\n  {commands}",
                        request.name
                    )));
                }

                let mut config = tun::Configuration::default();
                config.tun_name(&request.name);
                if existed {
                    // Attach only. Reconfiguring an interface somebody
                    // prepared for us would need exactly the privileges we
                    // are avoiding, so no ioctl beyond TUNSETIFF is issued.
                    config.platform_config(|platform| {
                        platform.ensure_root_privileges(false);
                    });
                } else {
                    // We are creating it, so we configure it.
                    config.mtu(request.mtu as u16).up();
                }
                // Packet information stays off, so reads and writes are raw IP
                // packets. `ip tuntap add ... mode tun` also defaults to no
                // packet information, so the flags match when attaching.

                let device = tun::create_as_async(&config).map_err(|err| {
                    let hint = if existed {
                        format!(
                            "interface `{}` exists but could not be opened: {err}. \
                             It must be a persistent TUN interface owned by this user.",
                            request.name
                        )
                    } else {
                        format!(
                            "cannot create the TUN interface `{}`: {err}. \
                             Creating one needs CAP_NET_ADMIN. Either prepare it once as root \
                             (see `tsunagi tun-setup`) and run unprivileged, or grant the \
                             capability.",
                            request.name
                        )
                    };
                    PluginError::Unavailable(hint)
                })?;

                // An interface we just created has no address yet either.
                if let Err(reason) = check_address(&request.name, request.address) {
                    let commands = setup_commands(&request, &current_user()).join("\n  ");
                    return Err(PluginError::Unavailable(format!(
                        "{reason}.\nAssigning an IPv6 address needs privileges. Run:\n  {commands}"
                    )));
                }

                let (reader, writer) = tokio::io::split(device);
                Ok(Arc::new(SystemTun {
                    name: request.name,
                    mtu: request.mtu,
                    reader: Mutex::new(reader),
                    writer: Mutex::new(writer),
                }) as Arc<dyn TunDevice>)
            })
        }
    }
}

#[cfg(all(test, feature = "tun-device", target_os = "linux"))]
mod system_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::Ipv6Addr;

    use super::TunRequest;
    use super::system::{interface_addresses, parse_if_inet6, setup_commands};

    const SAMPLE: &str = "\
fe800000000000008baaeb0c433b635a 04 40 20 80 tailscale0
00000000000000000000000000000001 01 80 10 80       lo
fd559caf9652cb86321feac65c73bd82 05 40 00 80 tsun0
fd559caf9652cb86321feac65c73bd83 05 40 00 40 tsun0
fd559caf9652cb86321feac65c73bd84 05 40 00 08 tsun0
";

    #[test]
    fn addresses_are_read_per_interface_with_their_flags() {
        let found = parse_if_inet6(SAMPLE, "tsun0");
        assert_eq!(found.len(), 3);
        assert_eq!(
            found[0].address,
            "fd55:9caf:9652:cb86:321f:eac6:5c73:bd82"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert!(found[0].is_usable(), "permanent address is usable");

        // Tentative: duplicate address detection never finishes without a
        // carrier, so the address exists but cannot carry traffic.
        assert!(!found[1].is_usable());
        assert!(found[1].why_unusable().unwrap().contains("tentative"));

        // Duplicate address detection failed outright.
        assert!(!found[2].is_usable());
        assert!(found[2].why_unusable().unwrap().contains("duplicate"));

        assert!(parse_if_inet6(SAMPLE, "nosuchdev").is_empty());
        // An interface name that is a prefix of another must not match.
        assert!(parse_if_inet6(SAMPLE, "tsun").is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped_rather_than_panicking() {
        assert!(parse_if_inet6("", "tsun0").is_empty());
        assert!(parse_if_inet6("garbage", "tsun0").is_empty());
        assert!(parse_if_inet6("zz 01 40 00 80 tsun0", "tsun0").is_empty());
        assert!(parse_if_inet6("00 01 40 00 80 tsun0", "tsun0").is_empty());
        // Flags that do not parse fall back to zero rather than dropping the
        // address, so a usable address is never hidden by a formatting change.
        let odd = parse_if_inet6("00000000000000000000000000000001 01 80 10 zz lo", "lo");
        assert_eq!(odd.len(), 1);
        assert!(odd[0].is_usable());
    }

    #[test]
    fn loopback_is_found_on_this_host() {
        // A real read of /proc/net/if_inet6: every Linux host has ::1 on lo.
        let found = interface_addresses("lo").expect("/proc/net/if_inet6 should be readable");
        assert!(
            found
                .iter()
                .any(|entry| entry.address == Ipv6Addr::LOCALHOST),
            "expected ::1 on lo, got {found:?}"
        );
        assert!(
            interface_addresses("definitely-not-an-interface")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_setup_recipe_survives_a_carrier_drop() {
        let request = TunRequest {
            name: "tsun0".into(),
            address: "fd00::1".parse().unwrap(),
            prefix_len: 64,
            address_v4: Some("100.64.1.2".parse().unwrap()),
            prefix_len_v4: 10,
            mtu: 1280,
        };
        let commands = setup_commands(&request, "someone");

        // The interface must be up before the address is added, the address
        // must survive losing carrier, and it must not wait for duplicate
        // address detection that can never complete.
        let joined = commands.join("\n");
        let up = joined.find("link set dev tsun0 mtu 1280 up").unwrap();
        let keep = joined.find("keep_addr_on_down=1").unwrap();
        let add = joined.find("address add fd00::1/64").unwrap();
        assert!(up < keep && keep < add, "wrong order:\n{joined}");
        assert!(joined.contains("nodad"));
        assert!(joined.contains("user someone"));
        // IPv4 needs no carrier tricks, just the address.
        assert!(joined.contains("ip address add 100.64.1.2/10 dev tsun0"));

        // An IPv6-only overlay says nothing about IPv4.
        let v6_only = TunRequest {
            address_v4: None,
            ..request
        };
        assert!(
            !setup_commands(&v6_only, "someone")
                .join("\n")
                .contains("100.64")
        );
    }
}

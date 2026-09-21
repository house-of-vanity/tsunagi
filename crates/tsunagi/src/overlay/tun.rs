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
//!   Creating one needs `CAP_NET_ADMIN`, and it is
//!   [`provision`](super::provision) that holds that and creates it.

use std::net::Ipv6Addr;
use std::sync::Arc;

use bytes::Bytes;

use crate::BoxFuture;
use crate::overlay::OverlayError;

/// What a device should look like once created.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl TunRequest {
    /// A request carrying nothing but a name and an MTU.
    ///
    /// Used where the addresses have already been applied to the host, so the
    /// device itself only needs opening.
    pub fn bare(name: impl Into<String>, mtu: u32) -> Self {
        Self {
            name: name.into(),
            address: Ipv6Addr::UNSPECIFIED,
            prefix_len: 0,
            address_v4: None,
            prefix_len_v4: 0,
            mtu,
        }
    }
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
    fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), OverlayError>>;
}

/// Creates packet interfaces.
pub trait TunFactory: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Creates a device.
    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>>;

    /// Applies a changed request to an interface that already exists.
    ///
    /// The overlay IPv4 address is allocated at run time, so it can change
    /// while the agent runs. A factory that manages the host applies that to
    /// the live interface, without recreating it: recreating would drop every
    /// tunnel riding on it.
    ///
    /// The default does nothing, which is right for a factory that only
    /// attaches to an interface somebody else prepared.
    fn reconfigure<'a>(&'a self, _request: TunRequest) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async move { Ok(()) })
    }

    /// Removes an interface this factory created.
    ///
    /// Runs on the teardown path, so it reports rather than fails: there is
    /// nothing useful to do about a failure at that point, and an interface
    /// that is already gone is the desired outcome anyway.
    fn destroy<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {})
    }
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

    fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), OverlayError>> {
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
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
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
pub(crate) use system::open_tun;

#[cfg(feature = "tun-device")]
mod system {
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::sync::Mutex;

    use super::{TunDevice, TunRequest};
    use crate::BoxFuture;
    use crate::overlay::OverlayError;

    /// A real TUN interface.
    ///
    /// Created by opening `/dev/net/tun`, which needs `CAP_NET_ADMIN` and is
    /// why [`open_tun`] is only ever called from
    /// [`provision`](super::super::provision), where that capability is
    /// raised for the length of the call and no longer.
    ///
    /// It is deliberately **not** made persistent, so the kernel removes the
    /// interface when this value is dropped — however the process ends.
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

        fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), OverlayError>> {
            Box::pin(async move {
                use tokio::io::AsyncWriteExt;
                let mut writer = self.writer.lock().await;
                writer
                    .write_all(&packet)
                    .await
                    .map_err(|err| OverlayError::Other(format!("tun write failed: {err}")))
            })
        }
    }

    /// Creates the TUN interface by opening it.
    ///
    /// Synchronous, and deliberately so: the caller holds a capability guard
    /// across this call, and such a guard must not span an `await` because
    /// Linux capabilities are per thread.
    pub(crate) fn open_tun(request: &TunRequest) -> Result<Arc<dyn TunDevice>, OverlayError> {
        let mut config = tun::Configuration::default();
        config.tun_name(&request.name);
        config.platform_config(|platform| {
            // The crate's own root check is not the check we want: this holds
            // CAP_NET_ADMIN without being root. Whether the open succeeds is
            // the honest answer.
            platform.ensure_root_privileges(false);
        });
        // Packet information stays off, so reads and writes are raw IP
        // packets. `ip tuntap add ... mode tun` also defaults to no packet
        // information, so the flags match when attaching to one.

        let device = tun::create_as_async(&config).map_err(|err| {
            OverlayError::Unavailable(format!(
                "cannot create the TUN interface `{}`: {err}. Creating one needs \
                 CAP_NET_ADMIN; grant it with `setcap cap_net_admin+p`, or run with \
                 `--no-tun` to keep the tunnels off the operating system.",
                request.name
            ))
        })?;

        let (reader, writer) = tokio::io::split(device);
        Ok(Arc::new(SystemTun {
            name: request.name.clone(),
            mtu: request.mtu,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }) as Arc<dyn TunDevice>)
    }
}

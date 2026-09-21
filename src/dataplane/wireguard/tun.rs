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
pub use system::SystemTunFactory;

#[cfg(feature = "tun-device")]
mod system {
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::sync::Mutex;

    use super::{TunDevice, TunFactory, TunRequest};
    use crate::BoxFuture;
    use crate::dataplane::PluginError;

    /// A real TUN interface.
    ///
    /// Creating one needs `CAP_NET_ADMIN` on Linux, or the platform
    /// equivalent. Failure is reported, never fatal for the agent.
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

    /// Creates real TUN interfaces.
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
                let mut config = tun::Configuration::default();
                config.tun_name(&request.name).mtu(request.mtu as u16).up();
                // The overlay address and its subnet, so the operating system
                // routes overlay traffic into this interface.
                let _ = (&request.address, request.prefix_len);

                let device = tun::create_as_async(&config).map_err(|err| {
                    PluginError::Unavailable(format!(
                        "cannot create the TUN interface `{}`: {err}. \
                         This needs CAP_NET_ADMIN (try running as root).",
                        request.name
                    ))
                })?;

                // The name was requested explicitly; creation fails rather
                // than silently picking another one.
                let name = request.name.clone();
                let (reader, writer) = tokio::io::split(device);

                Ok(Arc::new(SystemTun {
                    name,
                    mtu: request.mtu,
                    reader: Mutex::new(reader),
                    writer: Mutex::new(writer),
                }) as Arc<dyn TunDevice>)
            })
        }
    }
}

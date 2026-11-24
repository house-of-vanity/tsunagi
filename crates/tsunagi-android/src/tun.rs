//! A stable packet device over the file descriptors replaced by VpnService.
use crate::dns::{Resolver, stack::DnsPort};
use crate::plan::VpnPlan;
use bytes::Bytes;
use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    sync::Arc,
};
use tokio::{
    io::unix::AsyncFd,
    sync::{Mutex, watch},
};
use tsunagi::{
    BoxFuture,
    overlay::{
        OverlayError, TunDevice, TunFactory, TunRequest,
        hostrules::{
            BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, ExitHostPlan,
            ExitHostReport, ExitHostRules, RuleOutcome,
        },
    },
};

type Establish = dyn Fn(&VpnPlan) -> io::Result<File> + Send + Sync;
type BindSocket =
    dyn Fn(&tokio::net::TcpSocket, std::net::Ipv4Addr) -> io::Result<()> + Send + Sync;
struct Attachment {
    device: Arc<AsyncFd<File>>,
    addresses: Vec<std::net::IpAddr>,
    dns: DnsPort,
}
type Descriptor = Option<Arc<Attachment>>;

/// The only OS call is supplied by the Android service. Tokio owns the detached fd.
#[derive(Clone)]
pub struct AndroidTun(Arc<Inner>);
struct Inner {
    establish: Box<Establish>,
    bind: Box<BindSocket>,
    resolver: Resolver,
    plan: Mutex<VpnPlan>,
    current: watch::Sender<Descriptor>,
}

impl fmt::Debug for AndroidTun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AndroidTun")
    }
}
impl AndroidTun {
    /// Attach a nonblocking device returned by Builder.establish().
    pub fn new(
        resolver: Resolver,
        establish: impl Fn(&VpnPlan) -> io::Result<File> + Send + Sync + 'static,
        bind: impl Fn(&tokio::net::TcpSocket, std::net::Ipv4Addr) -> io::Result<()>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(Arc::new(Inner {
            establish: Box::new(establish),
            bind: Box::new(bind),
            resolver,
            plan: Mutex::default(),
            current: watch::channel(None).0,
        }))
    }

    async fn update(&self, edit: impl FnOnce(&mut VpnPlan)) -> Result<(), OverlayError> {
        let mut applied = self.0.plan.lock().await;
        let mut next = applied.clone();
        edit(&mut next);
        if *applied == next {
            return Ok(());
        }
        let dns_address = next.dns_address();
        let fd = if next.addresses.is_empty() {
            None
        } else {
            let address = dns_address.ok_or_else(|| OverlayError::Unavailable(
                "Mesh ranges overlap every device-local DNS address. Choose a narrower mesh range.".into()
            ))?;
            let file = (self.0.establish)(&next)
                .and_then(AsyncFd::new)
                .map(Arc::new)
                .map_err(|err| OverlayError::Unavailable(err.to_string()))?;
            let dns = DnsPort::start(
                address,
                next.mtu as usize,
                self.0.resolver.clone(),
                file.clone(),
            );
            Some(Arc::new(Attachment {
                device: file,
                addresses: next.addresses.iter().map(|a| a.addr).collect(),
                dns,
            }))
        };
        self.0.current.send_replace(fd);
        self.0.resolver.publish(dns_address);
        *applied = next;
        Ok(())
    }
}

#[derive(Debug)]
struct Device {
    name: String,
    mtu: u32,
    tun: AndroidTun,
}

impl TunDevice for Device {
    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u32 {
        self.mtu
    }
    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut rx = self.tun.0.current.subscribe();
            let mut buffer = vec![0; self.mtu as usize + 1];
            loop {
                let fd = rx.borrow_and_update().clone();
                if let Some(fd) = fd {
                    let result = tokio::select! {
                        biased;
                        _ = rx.changed() => continue,
                        read = fd.device.async_io(tokio::io::Interest::READABLE, |mut file| file.read(&mut buffer)) => read,
                    };
                    if let Ok(len @ 1..) = result {
                        if fd.dns.intercept(&buffer[..len], &fd.addresses) {
                            continue;
                        }
                        buffer.truncate(len);
                        return Some(buffer.into());
                    }
                }
                // No networks yet, last one left, or Android revoked this fd.
                // A later establish wakes the same reader on the new device.
                rx.changed().await.ok()?;
            }
        })
    }
    fn send<'a>(&'a self, packet: Bytes) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async move {
            let mut rx = self.tun.0.current.subscribe();
            let fd = rx
                .borrow_and_update()
                .clone()
                .ok_or_else(|| OverlayError::Unavailable("VPN has no addresses".into()))?;
            let len = tokio::select! {
                biased;
                _ = rx.changed() => return Err(OverlayError::Unavailable("VPN was reconfigured".into())),
                write = fd.device.async_io(tokio::io::Interest::WRITABLE, |mut file| file.write(&packet)) =>
                    write.map_err(|e| OverlayError::Other(e.to_string()))?,
            };
            if len != packet.len() {
                return Err(OverlayError::Other("short VPN datagram write".into()));
            }
            Ok(())
        })
    }
}

impl TunFactory for AndroidTun {
    fn name(&self) -> &str {
        "Android VpnService"
    }
    fn bind_overlay_socket(
        &self,
        socket: &tokio::net::TcpSocket,
        source: std::net::Ipv4Addr,
    ) -> io::Result<()> {
        (self.0.bind)(socket, source)?;
        socket.bind((source, 0).into())
    }
    fn assigned_addresses(&self) -> Vec<std::net::IpAddr> {
        self.0
            .current
            .borrow()
            .as_ref()
            .map(|fd| fd.addresses.clone())
            .unwrap_or_default()
    }
    fn on_host(&self) -> bool {
        true
    }
    fn create<'a>(
        &'a self,
        req: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
        Box::pin(async move {
            let dev = Device {
                name: req.name.clone(),
                mtu: req.mtu,
                tun: self.clone(),
            };
            self.reconfigure(req).await?;
            Ok(Arc::new(dev) as Arc<dyn TunDevice>)
        })
    }
    fn reconfigure<'a>(&'a self, req: TunRequest) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(self.update(move |plan| {
            plan.addresses = req.addresses;
            plan.mtu = req.mtu;
        }))
    }
    fn host_rules(&self) -> Option<Arc<dyn BroadcastHostRules>> {
        Some(Arc::new(self.clone()))
    }
    fn destroy<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {
            let _ = self.update(|plan| *plan = VpnPlan::default()).await;
        })
    }
}

fn outcome(result: Result<(), OverlayError>) -> RuleOutcome {
    match result {
        Ok(()) => RuleOutcome::Applied,
        Err(error) => RuleOutcome::Failed(error.to_string()),
    }
}
impl BroadcastHostRules for AndroidTun {
    fn name(&self) -> &str {
        "Android VpnService"
    }
    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let route = outcome(self.update(|p| p.broadcast = true).await);
            BroadcastRulesReport {
                plan: plan.clone(),
                route,
                // Android delivers accepted traffic directly through the VPN fd.
                firewall: RuleOutcome::Applied,
            }
        })
    }
    fn clear<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {
            let _ = self.update(|p| p.broadcast = false).await;
        })
    }
    fn exit_rules(&self) -> Option<&dyn ExitHostRules> {
        Some(self)
    }
}
impl ExitHostRules for AndroidTun {
    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport> {
        Box::pin(async move {
            let result = self
                .update(|p| {
                    p.full_tunnel = plan.client;
                    p.exit = plan.client_source.map(Into::into);
                })
                .await;
            ExitHostReport {
                offer: plan
                    .offer
                    .iter()
                    .map(|range| {
                        (
                            *range,
                            RuleOutcome::Failed("Android supports exit clients only".into()),
                        )
                    })
                    .collect(),
                forwarding: None,
                client: plan.client.then(|| outcome(result)),
            }
        })
    }
    fn clear<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {
            let _ = self
                .update(|p| {
                    p.full_tunnel = false;
                    p.exit = None;
                })
                .await;
        })
    }
}

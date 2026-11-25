//! A Mac that cannot open a system utun can still serve an explicitly offered
//! exit over bound user sockets. Ordinary host applications need a real utun.
use super::Physical;
use crate::BoxFuture;
use crate::overlay::{
    OverlayError, TunDevice, TunFactory, TunRequest,
    hostrules::{
        BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, ExitHostPlan, ExitHostReport,
        ExitHostRules, RuleOutcome,
    },
};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub(in crate::overlay) struct SocketExit {
    // Only refreshed while offering. Keep the OS route lookup off the packet path.
    uplink: Arc<Mutex<Option<(Instant, Physical)>>>,
}

#[derive(Debug)]
struct NoHostTun(u32);
impl TunDevice for NoHostTun {
    fn name(&self) -> &str {
        "userspace-exit"
    }
    fn mtu(&self) -> u32 {
        self.0
    }
    fn recv(&self) -> BoxFuture<'_, Option<bytes::Bytes>> {
        Box::pin(async { None })
    }
    fn send<'a>(&'a self, _packet: bytes::Bytes) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async {
            Err(OverlayError::Unavailable(
                "this Mac has no host utun".into(),
            ))
        })
    }
}

impl TunFactory for SocketExit {
    fn name(&self) -> &str {
        "userspace-exit"
    }
    fn on_host(&self) -> bool {
        false
    }
    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
        Box::pin(async move { Ok(Arc::new(NoHostTun(request.mtu)) as Arc<dyn TunDevice>) })
    }
    fn host_rules(&self) -> Option<Arc<dyn BroadcastHostRules>> {
        Some(Arc::new(self.clone()))
    }
}
impl BroadcastHostRules for SocketExit {
    fn name(&self) -> &str {
        "userspace-exit"
    }
    fn exit_rules(&self) -> Option<&dyn ExitHostRules> {
        Some(self)
    }
    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let failed = RuleOutcome::Failed("Local broadcast needs the system utun".into());
            BroadcastRulesReport {
                plan: plan.clone(),
                route: failed.clone(),
                firewall: failed,
            }
        })
    }
    fn clear<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

impl SocketExit {
    async fn reconcile(&self, plan: &ExitHostPlan) -> ExitHostReport {
        let physical = if plan.offer.is_empty() {
            Err("exit sharing is off".to_owned())
        } else {
            tokio::task::spawn_blocking(|| {
                let physical = crate::overlay::hostrules::macos_default_uplink()?;
                let iface = netdev::get_interfaces()
                    .into_iter()
                    .find(|i| i.name == physical)
                    .ok_or_else(|| "the physical default interface is unavailable".to_owned())?;
                if iface.index == 0 || iface.is_loopback() || iface.name.starts_with("utun") {
                    return Err("no physical IPv4 interface for exit sharing".into());
                }
                let address = iface
                    .ipv4
                    .iter()
                    .map(|ip| ip.addr())
                    .find(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local())
                    .ok_or_else(|| {
                        "the physical interface has no usable IPv4 address".to_owned()
                    })?;
                Ok(Physical {
                    index: iface.index,
                    address,
                })
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r)
        };
        *self.uplink.lock().unwrap_or_else(|e| e.into_inner()) =
            physical.as_ref().ok().map(|p| (Instant::now(), *p));
        let result = match physical {
            Ok(_) => RuleOutcome::Applied,
            Err(reason) => RuleOutcome::Failed(reason),
        };
        ExitHostReport {
            offer: plan
                .offer
                .iter()
                .map(|range| (*range, result.clone()))
                .collect(),
            forwarding: None,
            client: plan.client.then(|| {
                RuleOutcome::Failed(
                    "Routing this Mac’s applications through a peer needs the system utun".into(),
                )
            }),
        }
    }
}

impl ExitHostRules for SocketExit {
    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport> {
        Box::pin(self.reconcile(plan))
    }
    fn clear<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            *self.uplink.lock().unwrap_or_else(|e| e.into_inner()) = None;
        })
    }
    fn refresh_offer<'a>(
        &'a self,
        plan: &'a ExitHostPlan,
    ) -> BoxFuture<'a, Option<ExitHostReport>> {
        Box::pin(async move {
            if self
                .uplink
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some_and(|(at, _)| at.elapsed() < Duration::from_secs(5))
            {
                return None;
            }
            Some(self.reconcile(plan).await)
        })
    }
    fn forwarded_uplink(&self) -> Option<(u32, Ipv4Addr)> {
        self.uplink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|(_, p)| (p.index, p.address))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::overlay::egress::{Route, echo, ip_packet};
    #[derive(Debug)]
    struct DeniedUtun(bool);
    impl TunFactory for DeniedUtun {
        fn name(&self) -> &str {
            "utun"
        }
        fn on_host(&self) -> bool {
            true
        }
        fn create<'a>(
            &'a self,
            _: TunRequest,
        ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
            Box::pin(async move {
                Err(if self.0 {
                    OverlayError::UtunDenied("permission denied".into())
                } else {
                    OverlayError::Unavailable("system error".into())
                })
            })
        }
    }
    struct Returns(tokio::sync::mpsc::Sender<bytes::Bytes>);
    impl crate::overlay::PacketCarrier for Returns {
        fn carry(&self, _: Route, p: bytes::Bytes) -> bool {
            self.0.try_send(p).is_ok()
        }
    }

    #[tokio::test]
    async fn a_denied_utun_can_offer_while_an_unrelated_interface_failure_is_reported() {
        use crate::overlay::{Interface, RoutingTable};
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        let start = |denied| {
            Interface::start(
                Arc::new(DeniedUtun(denied)),
                "utun",
                1280,
                Arc::new(RoutingTable::new()),
                Arc::new(Returns(tx.clone())),
            )
        };
        assert!(matches!(
            start(false).await,
            Err(OverlayError::Unavailable(_))
        ));
        let interface = start(true).await.unwrap();
        assert!(!interface.on_host());
        assert_eq!(interface.name(), "userspace-exit");
        interface.remove().await;
    }

    #[tokio::test]
    #[ignore = "requires an active physical IPv4 interface on macOS; uses a UDP listener on this Mac"]
    async fn a_user_exit_delivers_udp_and_the_reply_on_its_physical_interface() {
        use crate::{
            overlay::{ExitPolicy, Interface, NetworkRoutes, RoutingTable},
            vip::{Protocol, packet::Tuple},
        };
        use tokio::{net::UdpSocket, time::timeout};
        let net = crate::NetworkId::from_bytes([7; 32]);
        let peer = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let own = Ipv4Addr::new(10, 2, 3, 1);
        let member = Ipv4Addr::new(10, 2, 3, 2);
        let routes = Arc::new(RoutingTable::new());
        routes
            .set_network(
                net,
                NetworkRoutes {
                    local: Some(own),
                    peers: vec![(member, peer)],
                    range: Some("10.2.3.0/24".parse().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();
        let (tx, mut returns) = tokio::sync::mpsc::channel(2);
        let interface = Interface::start(
            Arc::new(DeniedUtun(true)),
            "utun",
            1280,
            routes.clone(),
            Arc::new(Returns(tx)),
        )
        .await
        .unwrap();
        routes.set_exit(
            net,
            ExitPolicy {
                offer: true,
                via: None,
            },
        );
        interface.sync_exit_rules().await;
        assert!(
            interface.exit_offer_ready(net),
            "{:?}",
            interface.exit_rules(net)
        );
        let device = crate::overlay::hostrules::macos_default_uplink().unwrap();
        let iface = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == device)
            .unwrap();
        let external = iface
            .ipv4
            .iter()
            .map(|n| n.addr())
            .find(|a| !a.is_link_local())
            .unwrap();
        let server = UdpSocket::bind((external, 0)).await.unwrap();
        let tuple = Tuple {
            src: member,
            dst: external,
            sport: 51234,
            dport: server.local_addr().unwrap().port(),
            protocol: Protocol::Udp,
        };
        let request = super::super::udp_packet(tuple, b"exit request").unwrap();
        let mut buf = [0; 32];
        timeout(Duration::from_secs(3), async {
            interface.deliver(net, peer, request.clone()).await.unwrap();
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"exit request");
            assert_eq!(from.ip(), external);
            server.send_to(b"exit reply", from).await.unwrap();
            let reply = returns.recv().await.unwrap();
            assert_eq!(crate::vip::packet::tuple(&reply), Some(tuple.reverse()));
            assert_eq!(&reply[28..], b"exit reply");
        })
        .await
        .unwrap();
        routes.set_exit(net, Default::default());
        interface.sync_exit_rules().await;
        assert!(!interface.exit_offer_ready(net));
        assert!(interface.deliver(net, peer, request).await.is_err());
        interface.remove().await;
    }

    #[tokio::test]
    async fn unprivileged_echo_uses_a_bound_datagram_and_restores_the_peer_identifier() {
        let lo = netdev::get_interfaces()
            .into_iter()
            .find(|i| i.is_loopback())
            .unwrap();
        let physical = Physical {
            index: lo.index,
            address: Ipv4Addr::LOCALHOST,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let reply: super::super::Reply = Arc::new(move |_, bytes| {
            let _ = tx.try_send(bytes);
        });
        let origin = Route {
            network: crate::NetworkId::from_bytes([7; 32]),
            peer: iroh::SecretKey::from_bytes(&[8; 32]).public(),
        };
        let mut p = ip_packet(Ipv4Addr::new(10, 2, 3, 9), Ipv4Addr::LOCALHOST, 1, 8).unwrap();
        p[20] = 8;
        p[24..28].copy_from_slice(&[1, 2, 3, 4]);
        let sum = crate::vip::packet::checksum(&p[20..]);
        p[22..24].copy_from_slice(&sum.to_be_bytes());
        echo(physical, origin, p.into(), 20, &reply, 1280)
            .await
            .unwrap();
        let response = rx.try_recv().unwrap();
        assert_eq!(&response[20..22], &[0, 0]);
        assert_eq!(&response[24..28], &[1, 2, 3, 4]);
        assert_eq!(crate::vip::packet::checksum(&response[20..]), 0);
    }
}

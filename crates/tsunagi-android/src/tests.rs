#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::plan::VpnPlan;
use std::net::{IpAddr, Ipv4Addr};
use tsunagi::overlay::Cidr;

fn addr(octet: u8) -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::new(10, octet, 42, 19)), 24).unwrap()
}

#[tokio::test]
async fn a_hidden_service_waits_for_mesh_changes_and_visible_stats_are_on_demand() {
    use crate::service::{Request, State, serve};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot, watch};
    use tsunagi::{
        discovery::SharedMemoryDiscovery,
        testing::{TestAgent, network},
    };
    use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};
    let discovery = SharedMemoryDiscovery::new();
    let phone = TestAgent::spawn(&discovery).await.unwrap();
    let wg = WireguardPlugin::open(WireguardConfig::new(phone.dir.path().join("wg")))
        .await
        .unwrap();
    let (state, mut snapshots) = watch::channel(State::Starting);
    let (stop, stopped) = watch::channel(crate::service::ServiceSignals::default());
    let (commands, requests) = mpsc::channel(4);
    let agent = phone.agent.clone();
    let task = tokio::spawn(async move {
        serve(
            agent,
            wg,
            crate::dns::Resolver::new(|_| None),
            requests,
            &state,
            stopped,
            |_| {},
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(5), snapshots.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(*snapshots.borrow_and_update(), State::Ready(..)));
    assert!(
        tokio::time::timeout(Duration::from_millis(2200), snapshots.changed())
            .await
            .is_err(),
        "a hidden, idle service rebuilt the status"
    );
    let (tx, rx) = oneshot::channel();
    commands.send((Request::Refresh, tx)).await.unwrap();
    rx.await.unwrap().unwrap();
    assert!(snapshots.has_changed().unwrap());
    let (name, secret) = network("background-mesh");
    phone.agent.join_network(&name, &secret).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), snapshots.wait_for(|s| {
        matches!(s, State::Ready(r, _) if r.dns.as_ref().is_some_and(|d| d.zones.iter().any(|z| z == "background-mesh")))
    })).await.unwrap().unwrap();
    stop.send_modify(|s| s.stopped = true);
    task.await.unwrap();
}

#[tokio::test]
async fn notification_tracks_the_selected_exit_and_a_stale_disconnect_keeps_the_current_route() {
    use crate::service::{ExitNotice, Request, State, disconnect_exit, serve, wait_for_exit_offer};
    use tokio::sync::{mpsc, oneshot, watch};
    use tsunagi_wg_quic::{WireguardConfig, WireguardPlugin};
    async fn notice_matching(
        notices: &mut watch::Receiver<Option<ExitNotice>>,
        predicate: impl Fn(&Option<ExitNotice>) -> bool,
    ) -> Option<ExitNotice> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            notices.wait_for(predicate),
        )
        .await
        .unwrap()
        .unwrap()
        .clone()
    }
    use tsunagi::{
        discovery::SharedMemoryDiscovery,
        testing::{TestAgent, network, wait_until},
    };
    let discovery = SharedMemoryDiscovery::new();
    let phone = TestAgent::spawn(&discovery).await.unwrap();
    let rules = std::sync::Arc::new(tsunagi::overlay::MockHostRules::new());
    let tuns = tsunagi::overlay::MemoryTunFactory::new().with_host_rules(rules);
    let exit = TestAgent::spawn_with(
        |cfg| cfg.with_interface(std::sync::Arc::new(tuns), "gateway", 1280),
        &discovery,
    )
    .await
    .unwrap();
    let (name, secret) = network("travel");
    let id = phone.agent.join_network(&name, &secret).await.unwrap();
    exit.agent.set_hostname("gateway").await.unwrap();
    exit.agent.join_network(&name, &secret).await.unwrap();
    exit.agent.set_exit_offer(id, true).await.unwrap();
    let peer = exit.agent.endpoint_id();
    wait_until("authenticated exit offer", || async {
        phone
            .agent
            .network_status(id)
            .await
            .ok()?
            .peers
            .iter()
            .any(|p| p.endpoint_id == peer && p.exit_node)
            .then_some(())
    })
    .await;
    let wg = WireguardPlugin::open(WireguardConfig::new(phone.dir.path().join("wg")))
        .await
        .unwrap();
    let agent = phone.agent.clone();
    let (commands, requests) = mpsc::channel(4);
    let (stop, stopped) = watch::channel(crate::service::ServiceSignals::default());
    let (published, mut notices) = watch::channel(None);
    let (state, mut live) = watch::channel(State::Starting);
    let task = tokio::spawn(async move {
        serve(
            agent,
            wg,
            crate::dns::Resolver::new(|_| None),
            requests,
            &state,
            stopped,
            |notice| {
                published.send_replace(notice.cloned());
            },
        )
        .await;
    });
    phone.agent.set_exit_via(id, Some(peer)).await.unwrap();
    let notice = notice_matching(&mut notices, |n| n.as_ref().is_some_and(|n| n.online))
        .await
        .unwrap();
    assert_eq!(notice.name, "gateway");
    assert_eq!(notice.network_name, "travel");
    assert!(notice.online);
    let restore = |peer: String| {
        let commands = commands.clone();
        let network = notice.network.clone();
        async move {
            let (reply, result) = oneshot::channel();
            commands
                .send((Request::RestoreExit { network, peer }, reply))
                .await
                .unwrap();
            result.await.unwrap()
        }
    };
    disconnect_exit(&phone.agent, &notice.network, &notice.peer)
        .await
        .unwrap();
    notice_matching(&mut notices, Option::is_none).await;
    assert!(
        restore(phone.agent.endpoint_id().to_string())
            .await
            .is_err()
    );
    assert!(
        phone
            .agent
            .network_status(id)
            .await
            .unwrap()
            .exit_via
            .is_none()
    );
    // A cold service can publish its first status before the gateway advertises.
    // Keep the command loop available while waiting for this exact peer.
    exit.agent.set_exit_offer(id, false).await.unwrap();
    drop(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            live.wait_for(|s| {
                matches!(s, State::Ready(report, _) if
            report.networks[0].peers.iter().any(|p| p.endpoint_id == notice.peer && !p.exit_node))
            }),
        )
        .await
        .unwrap()
        .unwrap(),
    );
    let waiting = wait_for_exit_offer(&mut live, &notice.network, &notice.peer);
    tokio::pin!(waiting);
    tokio::select! {
        biased;
        _ = &mut waiting => panic!("restored before the peer offered an exit"),
        result = exit.agent.set_exit_offer(id, true) => result.unwrap(),
    }
    waiting.await.unwrap();
    assert!(restore(notice.peer.clone()).await.is_ok());
    notice_matching(&mut notices, |n| n.as_ref().is_some_and(|n| n.online)).await;
    assert!(
        restore(phone.agent.endpoint_id().to_string())
            .await
            .is_err()
    );
    disconnect_exit(
        &phone.agent,
        &id.to_string(),
        &phone.agent.endpoint_id().to_string(),
    )
    .await
    .unwrap();
    assert_eq!(
        phone.agent.network_status(id).await.unwrap().exit_via,
        Some(peer)
    );
    exit.agent.set_hostname("renamed-gateway").await.unwrap();
    notice_matching(&mut notices, |n| {
        n.as_ref().is_some_and(|n| n.name == "renamed-gateway")
    })
    .await;
    exit.stop().await;
    notice_matching(&mut notices, |n| n.as_ref().is_some_and(|n| !n.online)).await;
    disconnect_exit(&phone.agent, &notice.network, &notice.peer)
        .await
        .unwrap();
    notice_matching(&mut notices, Option::is_none).await;
    assert!(phone.agent.is_active(id).await);
    stop.send_modify(|s| s.stopped = true);
    task.await.unwrap();
}

#[tokio::test]
async fn vpn_dns_answers_hosts_and_vips_in_each_zone_and_only_forwards_external_names() {
    use crate::dns::Resolver;
    use simple_dns::{CLASS, Name, Packet, PacketFlag, Question, RCODE, TYPE, rdata::RData};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tsunagi::dns::{Zone, ZoneName, Zones};

    fn query(name: &str, kind: TYPE) -> Vec<u8> {
        let mut packet = Packet::new_query(119);
        packet.set_flags(PacketFlag::RECURSION_DESIRED);
        packet.questions.push(Question::new(
            Name::new(name).unwrap(),
            kind.into(),
            CLASS::IN.into(),
            false,
        ));
        packet.build_bytes_vec().unwrap()
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let forwarded = calls.clone();
    let resolver = Resolver::new(move |wire| {
        forwarded.fetch_add(1, Ordering::Relaxed);
        let query = Packet::parse(wire).unwrap();
        let mut answer = Packet::new_reply(999);
        answer.questions = query.questions;
        answer.build_bytes_vec().ok()
    });
    let private = query("k8s.tsng", TYPE::A);
    let answer = resolver.answer(&private).await.unwrap();
    assert_eq!(
        Packet::parse(&answer).unwrap().rcode(),
        RCODE::ServerFailure
    );
    let lab = |name, members| Zone::new(ZoneName::new(name).unwrap(), members);
    resolver.replace(Some(Zones::new([
        lab(
            "tsng",
            vec![
                ("ai".into(), [10, 1, 1, 100].into()),
                ("k8s".into(), [10, 1, 1, 106].into()),
            ],
        ),
        lab("lab", vec![("ai".into(), [10, 2, 1, 100].into())]),
    ])));
    for (name, ip) in [
        ("AI.TSNG", [10, 1, 1, 100]),
        ("k8s.tsng", [10, 1, 1, 106]),
        ("ai.lab", [10, 2, 1, 100]),
    ] {
        let reply = resolver.answer(&query(name, TYPE::A)).await.unwrap();
        let packet = Packet::parse(&reply).unwrap();
        assert!(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        assert!(
            matches!(&packet.answers[0].rdata, RData::A(a) if Ipv4Addr::from(a.address) == Ipv4Addr::from(ip))
        );
    }
    for (name, kind, code) in [
        ("missing.tsng", TYPE::A, RCODE::NameError),
        ("k8s.tsng", TYPE::AAAA, RCODE::NoError),
    ] {
        let reply = resolver.answer(&query(name, kind)).await.unwrap();
        let packet = Packet::parse(&reply).unwrap();
        assert_eq!(packet.rcode(), code);
        assert!(packet.answers.is_empty());
        assert!(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
    }
    assert!(resolver.answer(b"invalid").await.is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let reply = resolver
        .answer(&query("example.org", TYPE::HTTPS))
        .await
        .unwrap();
    let packet = Packet::parse(&reply).unwrap();
    assert_eq!(packet.id(), 119);
    assert_eq!(packet.questions[0].qtype, TYPE::HTTPS.into());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn local_dns_address_is_routed_and_cannot_claim_an_overlay_ip() {
    let mut plan = VpnPlan {
        addresses: vec![addr(1)],
        ..Default::default()
    };
    let dns = plan.dns_address().unwrap();
    assert!(plan.routes().contains(&format!("{dns}/32")));
    plan.addresses.push(Cidr::new(dns.into(), 24).unwrap());
    let other = plan.dns_address().unwrap();
    assert_ne!(other, dns);
    assert!(plan.routes().contains(&format!("{other}/32")));
    plan.addresses.clear();
    assert!(plan.dns_address().is_none());
}

#[tokio::test]
async fn service_dns_tracks_signed_hostnames_vip_deletion_and_reverse_ranges() {
    use tsunagi::{
        Agent,
        dns::{Answer, Query, RosterZones},
        testing,
        vip::VipConfig,
    };
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::spawn(testing::local_config(dir.path()))
        .await
        .unwrap();
    let (network, secret) = testing::network("tsng");
    let id = agent.join_network(&network, &secret).await.unwrap();
    agent.set_hostname("worker").await.unwrap();
    let vip = agent
        .save_vip(id, VipConfig::new("k8s"), None, false)
        .await
        .unwrap()
        .remove(0);
    let status = agent.status().await.unwrap();
    let roster = RosterZones::from_networks(&status.networks);
    let worker = status.networks[0]
        .members
        .iter()
        .find(|m| m.hostname.as_deref() == Some("worker"))
        .unwrap()
        .overlay_address_v4
        .unwrap();
    for (name, ip) in [("worker.tsng", worker), ("k8s.tsng", vip.address.unwrap())] {
        assert_eq!(
            roster.zones.lookup(name, Query::A).unwrap().1,
            Answer::Addresses(vec![ip])
        );
        let [a, b, c, d] = ip.octets();
        assert_eq!(
            roster
                .zones
                .lookup(&format!("{d}.{c}.{b}.{a}.in-addr.arpa"), Query::Ptr)
                .unwrap()
                .1,
            Answer::Name(name.into())
        );
    }
    assert!(
        roster
            .zones
            .lookup("8.8.8.8.in-addr.arpa", Query::Ptr)
            .is_none()
    );
    agent
        .save_vip(id, vip.config, Some(vip.revision), true)
        .await
        .unwrap();
    let zones = RosterZones::from_networks(&agent.status().await.unwrap().networks).zones;
    assert_eq!(
        zones.lookup("k8s.tsng", Query::A).unwrap().1,
        Answer::NoSuchName
    );
    agent.shutdown().await;
}

#[test]
fn changing_the_exit_keeps_every_mesh_route_and_prefers_the_selected_source() {
    let first = addr(2);
    let second = addr(5);
    let mut plan = VpnPlan {
        addresses: vec![first, second],
        mtu: 1280,
        ..Default::default()
    };
    assert_eq!(
        plan.routes(),
        ["10.2.42.0/24", "10.5.42.0/24", "192.0.2.53/32"]
    );
    assert_eq!(plan.addresses_in_order(), [first, second]);
    plan.full_tunnel = true;
    plan.exit = Some(second.addr);
    assert_eq!(plan.addresses_in_order(), [second, first]);
    assert!(plan.routes().contains(&"0.0.0.0/0".into()));
    assert!(plan.routes().contains(&"10.2.42.0/24".into()));
    plan.full_tunnel = false;
    plan.exit = None;
    plan.addresses.remove(0);
    assert_eq!(plan.routes(), ["10.5.42.0/24", "192.0.2.53/32"]);
}

#[test]
fn broadcast_route_is_only_present_when_requested() {
    let mut plan = VpnPlan {
        addresses: vec![addr(1)],
        mtu: 1280,
        ..Default::default()
    };
    plan.broadcast = true;
    assert!(plan.routes().contains(&"255.255.255.255/32".into()));
    plan.broadcast = false;
    assert_eq!(plan.routes(), ["10.1.42.0/24", "192.0.2.53/32"]);
}

#[tokio::test]
async fn all_four_desktop_carriers_register_and_each_network_keeps_its_preference() {
    use tsunagi::{Agent, testing};
    use tsunagi_runtime::{Carriers, PROTOCOLS};
    let dir = tempfile::tempdir().unwrap();
    let names = ["wg", "awg", "wg-quic", "tcp-tls"];
    let (network, secret) = testing::network("carriers");
    for restart in [false, true] {
        let config = testing::local_config(dir.path());
        let (config, carriers) = Carriers::configure(config, &[], None, |spec| {
            if spec.name == "tcp-tls" {
                vec![("port".into(), "0".into())]
            } else {
                Vec::new()
            }
        })
        .await
        .unwrap();
        assert_eq!(
            config
                .carriers
                .iter()
                .map(|c| c.protocol_id())
                .collect::<Vec<_>>(),
            names
        );
        assert!(
            config
                .carriers
                .iter()
                .zip(PROTOCOLS)
                .all(|(c, spec)| c.protocol_version() == spec.version)
        );
        let agent = Agent::spawn(config).await.unwrap();
        let _listeners = carriers.listen(&agent);
        let id = agent.join_network(&network, &secret).await.unwrap();
        let saved = agent.network_status(id).await.unwrap().protocols;
        if restart {
            assert_eq!(saved, ["tcp-tls", "wg"]);
        } else {
            assert_eq!(saved, names);
            agent
                .set_protocols(id, vec!["tcp-tls".into(), "wg".into()])
                .await
                .unwrap();
            let (other, secret) = testing::network("other");
            let second = agent.join_network(&other, &secret).await.unwrap();
            assert_eq!(agent.network_status(second).await.unwrap().protocols, names);
        }
        agent.shutdown().await;
    }
}

#[tokio::test]
async fn commands_scope_vip_edits_and_leaving_to_the_selected_network() {
    use crate::service::apply;
    use tsunagi::vip::VipConfig;
    use tsunagi::{Agent, NetworkName, NetworkSecret, testing};
    use tsunagi_ui::client::Command;
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::spawn(testing::local_config(dir.path()))
        .await
        .unwrap();
    let name = NetworkName::new("shared-name").unwrap();
    let one = NetworkSecret::generate();
    let two = NetworkSecret::generate();
    for secret in [&one, &two] {
        apply(
            Command::Join {
                name: name.to_string(),
                secret: secret.encode(),
            },
            &agent,
        )
        .await
        .unwrap();
    }
    let first = tsunagi::identity::NetworkKeys::derive(&name, &one)
        .network_id()
        .to_string();
    let second = tsunagi::identity::NetworkKeys::derive(&name, &two).network_id();
    let config = VipConfig::new("web");
    let save = |expected, delete| Command::SaveVip {
        token: "draft".into(),
        network_id: first.clone(),
        config: config.clone(),
        expected,
        delete,
    };
    apply(save(None, false), &agent).await.unwrap();
    assert!(
        apply(save(Some("stale".into()), true), &agent)
            .await
            .is_err()
    );
    assert_eq!(
        agent
            .network_status(first.parse().unwrap())
            .await
            .unwrap()
            .vips
            .len(),
        1
    );
    assert!(agent.network_status(second).await.unwrap().vips.is_empty());
    assert!(
        apply(
            Command::SetExitNode {
                network_id: second.to_string(),
                peer: Some(agent.endpoint_id().to_string())
            },
            &agent
        )
        .await
        .is_err()
    );
    assert!(
        apply(
            Command::SetExitOffer {
                network_id: second.to_string(),
                enabled: true
            },
            &agent
        )
        .await
        .is_err()
    );
    apply(Command::Leave { network_id: first }, &agent)
        .await
        .unwrap();
    let saved = agent.list_networks().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].network_id, second);
    agent.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn tun_reader_survives_address_changes_failed_establish_and_last_network_leaving() {
    use std::io;
    use std::os::{fd::OwnedFd, unix::net::UnixDatagram};
    use std::sync::{Arc, Mutex};
    use tsunagi::overlay::{TunFactory, TunRequest};
    let sockets = Arc::new(Mutex::new(Vec::new()));
    let peers = sockets.clone();
    let factory = crate::tun::AndroidTun::new(
        crate::dns::Resolver::new(|_| None),
        move |plan| {
            if plan.addresses.contains(&addr(9)) {
                return Err(io::Error::other("permission revoked"));
            }
            let (dev, os) = UnixDatagram::pair()?;
            dev.set_nonblocking(true)?;
            peers.lock().unwrap().push(os);
            Ok(OwnedFd::from(dev).into())
        },
        |_, _| Ok(()),
    );
    let mut req = TunRequest::bare("tsun0", 1280);
    let dev = factory.create(req.clone()).await.unwrap();
    let reader = tokio::spawn({
        let dev = dev.clone();
        async move { dev.recv().await.unwrap() }
    });
    req.addresses = vec![addr(2)];
    factory.reconfigure(req.clone()).await.unwrap();
    assert_eq!(factory.assigned_addresses(), [addr(2).addr]);
    req.addresses.push(addr(9));
    assert!(factory.reconfigure(req.clone()).await.is_err());
    assert_eq!(factory.assigned_addresses(), [addr(2).addr]);
    sockets
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .send(b"first")
        .unwrap();
    assert_eq!(
        &tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap()[..],
        b"first"
    );
    req.addresses.clear();
    factory.reconfigure(req.clone()).await.unwrap();
    assert!(
        dev.send(bytes::Bytes::from_static(b"offline"))
            .await
            .is_err()
    );
    assert!(factory.assigned_addresses().is_empty());
    req.addresses = vec![addr(5)];
    factory.reconfigure(req).await.unwrap();
    sockets
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .send(b"second")
        .unwrap();
    assert_eq!(&dev.recv().await.unwrap()[..], b"second");
}

#[tokio::test]
async fn network_cards_start_closed_and_keep_exit_traffic_visible_when_folded() {
    use crate::{
        service::{State, report},
        view::{Phone, configure},
    };
    use egui::epaint::Shape;
    use std::{sync::Arc, time::Instant};
    let dir = tempfile::tempdir().unwrap();
    let agent = tsunagi::Agent::spawn(tsunagi::testing::local_config(dir.path()))
        .await
        .unwrap();
    let (name, secret) = tsunagi::testing::network("layout");
    agent.join_network(&name, &secret).await.unwrap();
    let mut sample = report(&agent, None, &crate::dns::Resolver::new(|_| None))
        .await
        .unwrap();
    sample.networks[0].overlay = Some(tsunagi::ipc::OverlayReport {
        address: Some("10.1.2.3".into()),
        ..Default::default()
    });
    let mut other = sample.networks[0].clone();
    other.network_id = "another-network".into();
    sample.networks.push(other);
    sample.networks[0].peers.push(tsunagi::ipc::PeerReport {
        endpoint_id: "exit-endpoint-id".into(),
        hostname: Some("gateway".into()),
        ..Default::default()
    });
    sample.networks[0].exit = tsunagi::ipc::ExitReport {
        via: Some("exit-endpoint-id".into()),
        via_online: true,
        traffic: Some(tsunagi::overlay::exit::ExitTraffic {
            tx_bytes: 2048,
            rx_bytes: 512,
        }),
        client_rules: Some(tsunagi::ipc::RuleSetReport {
            ok: true,
            detail: String::new(),
        }),
        ..Default::default()
    };
    let state = State::Ready(Arc::new(sample), Instant::now());
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut phone = Phone::default();
    let mut frame = |events| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(360., 720.),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                phone.draw(ctx, &state, |_| {
                    panic!("drawing the overview issued a command")
                });
            },
        )
    };
    let positions = |frame: &egui::FullOutput, label: &str| {
        frame
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                Shape::Text(text) if text.galley.text() == label => {
                    Some(text.pos + text.galley.rect.center().to_vec2())
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    frame(vec![]);
    let closed = frame(vec![]);
    let titles = positions(&closed, name.as_str());
    assert_eq!(titles.len(), 2);
    assert!(positions(&closed, "Show devices").is_empty());
    use egui_phosphor::regular::{ARROW_DOWN, ARROW_UP};
    let font = egui::TextStyle::Body.resolve(&ctx.style());
    for icon in [ARROW_UP, ARROW_DOWN] {
        assert!(ctx.fonts(|fonts| fonts.has_glyphs(&font, icon)));
    }
    for label in [
        "Exit via gateway".to_owned(),
        format!("{ARROW_UP} 2.0 kB"),
        format!("{ARROW_DOWN} 512 B"),
    ] {
        assert_eq!(positions(&closed, &label).len(), 1, "missing {label}");
    }
    let mut click = |pos| {
        for pressed in [true, false] {
            frame(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                },
            ]);
        }
        frame(vec![])
    };
    let opened = click(titles[0]);
    assert_eq!(positions(&opened, "Show devices").len(), 1);
    use egui_phosphor::regular as icon;
    let vip = format!("{} VIP", icon::NETWORK);
    let y = |label: &str| positions(&opened, label)[0].y;
    assert!((0.0..=26.0).contains(&(y(icon::DESKTOP_TOWER) - y(icon::FINGERPRINT))));
    assert!((0.0..=26.0).contains(&(y(icon::TREE_STRUCTURE) - y(icon::HASH))));
    assert!((0.0..=26.0).contains(&(y(icon::DEVICES) - y(icon::DEVICE_MOBILE))));
    assert!((y(&vip) - y("Show devices")).abs() < 2.0);
    assert!((y(&vip) - y(&format!("{} Copy secret", egui_phosphor::regular::COPY))).abs() < 2.0);
    let folded = click(positions(&opened, name.as_str())[0]);
    assert!(positions(&folded, "Show devices").is_empty());
    assert_eq!(positions(&folded, "Exit via gateway").len(), 1);
    agent.shutdown().await;
}

#[test]
fn the_system_tile_waits_for_the_agent_and_distinguishes_networks_with_the_same_name() {
    use crate::{
        service::State,
        view::{Phone, configure},
    };
    use std::{sync::Arc, time::Instant};
    use tsunagi::ipc::{NetworkReport, StatusReport};
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut phone = Phone::default();
    let draw = |phone: &mut Phone, state: &State| {
        let out = ctx.run(egui::RawInput::default(), |ctx| {
            phone.draw(ctx, state, |_| panic!("opening the tile selected a route"));
        });
        out.shapes
            .into_iter()
            .filter_map(|s| match s.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    phone.request_exit_picker();
    draw(&mut phone, &State::Starting);
    let networks =
        [("alpha", true), ("bravo", true), ("paused", false)].map(|(id, active)| NetworkReport {
            network_id: id.into(),
            name: "home".into(),
            active,
            ..Default::default()
        });
    let state = State::Ready(
        Arc::new(StatusReport {
            networks: networks.into(),
            ..Default::default()
        }),
        Instant::now(),
    );
    draw(&mut phone, &state);
    let chooser = draw(&mut phone, &state);
    assert!(chooser.iter().any(|s| s == "home · alpha"));
    assert!(chooser.iter().any(|s| s == "home · bravo"));
    assert!(!chooser.iter().any(|s| s.contains("paused")));
    assert!(phone.back().is_none());
    assert!(draw(&mut phone, &state).iter().any(|s| s == "tsunagi"));
}

#[test]
fn rotating_the_phone_keeps_the_selected_network_and_unsaved_vip_draft() {
    use crate::service::State;
    use crate::view::{Phone, configure};
    use egui::{Event, PointerButton, Pos2, RawInput, Rect, Shape};
    use std::{sync::Arc, time::Instant};
    use tsunagi::{
        ipc::{NetworkReport, StatusReport},
        vip::{
            Backend, BackendStatus, Counters, Listener, ListenerStatus, Protocol, VipConfig,
            VipStatus,
        },
    };
    let backend = Backend {
        peer: "node".into(),
        port: 8080,
    };
    let mut config = VipConfig::new("web");
    let name_field = egui::Id::new(("vip-name", &config.id));
    let mut listener = Listener::new(Protocol::Tcp, 80);
    listener.backends.push(backend.clone());
    config.listeners.push(listener);
    let network = NetworkReport {
        active: true,
        name: "lab".into(),
        network_id: "network".into(),
        vips: vec![VipStatus {
            config,
            address: None,
            revision: "r1".into(),
            error: None,
            listeners: vec![ListenerStatus {
                protocol: Protocol::Tcp,
                port: 80,
                selected: Some(backend.clone()),
                counters: Counters::default(),
                backends: vec![BackendStatus {
                    backend,
                    state: "ready".into(),
                    rtt_us: Some(1000),
                    measurement_age_ms: Some(1),
                    active_flows: 1,
                    counters: Counters::default(),
                }],
            }],
        }],
        ..Default::default()
    };
    let state = State::Ready(
        Arc::new(StatusReport {
            networks: vec![network],
            ..Default::default()
        }),
        Instant::now(),
    );
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut phone = Phone::default();
    let size = std::cell::Cell::new(egui::vec2(360., 800.));
    let mut frame = |events| {
        ctx.run(
            RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size.get())),
                events,
                ..Default::default()
            },
            |ctx| {
                phone.draw(ctx, &state, |_| panic!("navigation wrote to the network"));
            },
        )
    };
    let position = |output: &egui::FullOutput, label: &str| {
        output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                Shape::Text(t) if t.galley.text() == label => {
                    Some(t.pos + t.galley.rect.center().to_vec2())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {label}"))
    };
    let mut click = |label: &str| {
        frame(vec![]);
        let p = position(&frame(vec![]), label);
        for pressed in [true, false] {
            frame(vec![
                Event::PointerMoved(p),
                Event::PointerButton {
                    pos: p,
                    button: PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                },
            ]);
        }
        frame(vec![])
    };
    click("lab");
    size.set(egui::vec2(800., 360.));
    let live = click(&format!("{} VIP", egui_phosphor::regular::NETWORK));
    for label in ["Overview", "Configuration", "web.lab", "node:8080"] {
        let p = position(&live, label);
        assert!(
            (0.0..800.0).contains(&p.x),
            "{label} is outside the landscape view"
        );
    }
    let editor = click("Configuration");
    position(&editor, "Name");
    ctx.memory_mut(|m| m.request_focus(name_field));
    frame(vec![Event::Text("-draft".into())]);
    size.set(egui::vec2(360., 800.));
    let editor_portrait = frame(vec![]);
    position(&editor_portrait, "Unsaved changes");
    assert!(editor_portrait.shapes.iter().any(|s| matches!(&s.shape,
        Shape::Text(t) if t.galley.text().contains("-draft"))));
    for label in [
        "Active TCP port checks",
        "Checks and flow expiry",
        "+ Backend",
        "+ Listener",
    ] {
        position(&editor_portrait, label);
    }
}

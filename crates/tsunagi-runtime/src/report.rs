//! Combine the core snapshot and live WireGuard observations for local clients.
use tsunagi::ipc::{MemberReport, NetworkReport, OverlayPeerReport, OverlayReport, PeerReport};
use tsunagi::{AgentStatus, agent::OverlayStatus};
use tsunagi_wg_quic::WireguardPlugin;

/// Build the same per-network view for an in-process client and the CLI's IPC server.
pub fn networks(
    status: &AgentStatus,
    overlay: Option<&OverlayStatus>,
    wireguard: Option<&WireguardPlugin>,
) -> Vec<NetworkReport> {
    status
        .networks
        .iter()
        .map(|network| {
            let wg_view = wireguard.and_then(|plugin| plugin.overview(network.network_id));
            let wg_overlay_addr = wg_view.as_ref().and_then(|v| v.overlay_address_v4);
            let wg_prefix_len = wg_view
                .as_ref()
                .and_then(|v| v.ipv4_range)
                .map_or(0, |r| r.prefix_len);
            let has_any_plugin = wg_view.is_some();

            let overlay = if has_any_plugin && overlay.is_some() {
                let mut peers: Vec<OverlayPeerReport> = Vec::new();

                if let Some(view) = &wg_view {
                    for peer in &view.peers {
                        let tunnel = peer.tunnel.as_ref();
                        peers.push(OverlayPeerReport {
                            counter_epoch: tunnel.map_or(0, |t| t.stats.counter_epoch),
                            endpoint_id: peer.endpoint_id.to_string(),
                            protocol: String::new(),
                            public_key: peer.public_key.to_string(),
                            address: peer.overlay_address_v4.map(|a| a.to_string()),
                            handshake_secs_ago: tunnel
                                .and_then(|t| t.health.since_handshake.map(|s| s.as_secs())),
                            tx_packets: tunnel.map_or(0, |t| t.stats.tx_packets),
                            rx_packets: tunnel.map_or(0, |t| t.stats.rx_packets),
                            tx_bytes: tunnel.map_or(0, |t| t.stats.tx_bytes),
                            rx_bytes: tunnel.map_or(0, |t| t.stats.rx_bytes),
                            dropped: tunnel.map_or(0, |t| {
                                t.stats.dropped_wrong_source + t.stats.dropped_oversize
                            }),
                            protocol_errors: tunnel.map_or(0, |t| t.stats.protocol_errors),
                            path: tunnel.map_or_else(|| "no data path".into(), |t| t.path.clone()),
                        });
                    }
                }

                let (address, prefix_len) = if wg_overlay_addr.is_some() {
                    (wg_overlay_addr.map(|addr| addr.to_string()), wg_prefix_len)
                } else {
                    (
                        network
                            .members
                            .iter()
                            .find(|m| m.endpoint_id == status.endpoint_id)
                            .and_then(|m| m.overlay_address_v4)
                            .map(|a| a.to_string()),
                        network.range.map_or(0, |r| r.prefix_len),
                    )
                };

                Some(OverlayReport {
                    interface: overlay.map_or_else(String::new, |o| o.interface.clone()),
                    on_host: overlay.is_some_and(|o| o.on_host),
                    mtu: overlay.map_or(0, |o| o.mtu),
                    address,
                    prefix_len,
                    peers,
                    unroutable_packets: overlay.map_or(0, |o| o.counters.unroutable),
                    multicast_packets: overlay.map_or(0, |o| o.counters.multicast),
                    unroutable_sample: overlay
                        .and_then(|o| o.counters.unroutable_sample.map(|a| a.to_string())),
                    broadcast_rules: overlay.and_then(|o| o.broadcast_rules.as_ref()).map(
                        |rules| tsunagi::ipc::HostRulesReport {
                            ok: rules.is_ok(),
                            detail: rules.summary(),
                            source: rules.plan.source.to_string(),
                        },
                    ),
                })
            } else {
                None
            };

            NetworkReport {
                vips: network.vips.clone(),
                protocols: network.protocols.clone(),
                auto_start: network.auto_start,
                exit: exit_report(network),
                broadcast: network.broadcast,
                name: network.name.to_string(),
                network_id: network.network_id.to_string(),
                active: matches!(network.state, tsunagi::agent::NetworkState::Active),
                candidates: network.candidates.len() as u32,
                relay_forwarded: network.relay.forwarded,
                relay_sent_via: network.relay.sent_via,
                relay_received_via: network.relay.received_via,
                peers: network
                    .peers
                    .iter()
                    .map(|peer| PeerReport {
                        data_error: peer.data_error.clone(),
                        endpoint_id: peer.endpoint_id.to_string(),
                        hostname: peer.hostname.clone(),
                        transport: peer.transport.to_string(),
                        rtt_ms: peer.rtt.map(|rtt| rtt.as_millis() as u64),
                        data_rtt_ms: peer.data_rtt.map(|rtt| rtt.as_millis() as u64),
                        data_transport_detail: peer.data_transport_detail.clone(),
                        exit_node: peer.exit_node,
                        path: data_path_report(&peer.data_path),
                    })
                    .collect(),
                members: network
                    .members
                    .iter()
                    .map(|member| MemberReport {
                        record_version: member.record_version,
                        endpoint_id: member.endpoint_id.to_string(),
                        overlay_address_v4: member.overlay_address_v4.map(|addr| addr.to_string()),
                        // What this agent is currently experiencing trying to
                        // reach it, so a dial-failure count can be attributed
                        // to the member it belongs to instead of floating
                        // free as a network-wide number.
                        failed_dials: network
                            .candidates
                            .iter()
                            .find(|candidate| candidate.endpoint_id == member.endpoint_id)
                            .map_or(0, |candidate| candidate.consecutive_failures),
                        hostname: member
                            .last_hostname
                            .clone()
                            .or_else(|| member.hostname.clone()),
                        online: member.online,
                        path: data_path_report(&member.data_path),
                        hostname_conflict: member.hostname_conflict.as_ref().map(conflict_report),
                    })
                    .collect(),
                range: network.range.map(|range| range.to_string()),
                range_conflict: network.range_conflict.map(|range| range.to_string()),
                range_conflicts: network
                    .range_conflicts
                    .iter()
                    .map(|c| tsunagi::ipc::RangeConflictReport {
                        network_id: c.network_id.to_string(),
                        name: c.name.to_string(),
                        range: c.range.to_string(),
                    })
                    .collect(),
                dial_failures: network.metrics.dial_failures,
                handshake_failures: network.metrics.handshake_failures,
                control_messages: (
                    network.metrics.control_messages_sent,
                    network.metrics.control_messages_received,
                ),
                overlay,
                hostname_conflict: network.hostname_conflict.as_ref().map(conflict_report),
            }
        })
        .collect()
}

fn data_path_report(path: &tsunagi::agent::DataPath) -> tsunagi::ipc::DataPathReport {
    match path {
        tsunagi::agent::DataPath::None => tsunagi::ipc::DataPathReport::None,
        tsunagi::agent::DataPath::Direct { transport } => tsunagi::ipc::DataPathReport::Direct {
            transport: transport.clone(),
        },
        tsunagi::agent::DataPath::Relayed { hops, via } => tsunagi::ipc::DataPathReport::Relayed {
            hops: *hops,
            via: via.to_string(),
        },
    }
}

fn conflict_report(
    conflict: &tsunagi::agent::HostnameConflict,
) -> tsunagi::ipc::HostnameConflictReport {
    tsunagi::ipc::HostnameConflictReport {
        name: conflict.name.clone(),
        holder: conflict.holder.to_string(),
    }
}

/// One network's exit-node settings, as the control interface reports them.
fn exit_report(network: &tsunagi::agent::NetworkStatus) -> tsunagi::ipc::ExitReport {
    let rules = |report: &Option<tsunagi::overlay::RuleSetReport>| {
        report.as_ref().map(|report| tsunagi::ipc::RuleSetReport {
            ok: report.ok,
            detail: report.detail.clone(),
        })
    };
    tsunagi::ipc::ExitReport {
        offering: network.exit_offer,
        offer_rules: rules(&network.exit_rules.offer),
        forwarding: network.exit_rules.forwarding,
        via: network.exit_via.map(|peer| peer.to_string()),
        via_online: network.exit_via_online,
        client_rules: rules(&network.exit_rules.client),
    }
}

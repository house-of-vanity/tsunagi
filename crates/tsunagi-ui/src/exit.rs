//! Exit nodes as the windows show them: what to call one, and what is wrong
//! with the ones in play.

use tsunagi::ipc::NetworkReport;

use crate::format;

/// An exit node that is working.
pub(crate) const GOOD: egui::Color32 = egui::Color32::from_rgb(0x3c, 0xb0, 0x4a);
/// Something about exit nodes the user has to look at.
pub(crate) const LOUD: egui::Color32 = egui::Color32::from_rgb(0xe0, 0x4a, 0x3c);

/// Platform instructions for hosts where an administrator manages forwarding.
#[cfg(target_os = "windows")]
pub(crate) const FORWARDING_COMMAND: &str =
    "Get-NetIPInterface | Set-NetIPInterface -Forwarding Enabled";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) const FORWARDING_COMMAND: &str = "sudo sysctl -w net.ipv4.ip_forward=1";

/// One thing wrong, loud enough to read at a glance.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Warning {
    pub(crate) text: String,
    /// A command the user will want, copied by clicking the warning.
    pub(crate) copy: Option<&'static str>,
}

/// What to call a device in a network, even while it is away.
pub fn name_of(network: &NetworkReport, id: &str) -> String {
    network
        .peers
        .iter()
        .find(|peer| peer.endpoint_id == id)
        .and_then(|peer| peer.hostname.clone())
        .or_else(|| {
            network
                .members
                .iter()
                .find(|member| member.endpoint_id == id)
                .and_then(|member| member.hostname.clone())
        })
        .unwrap_or_else(|| format::short(id))
}

/// Everything wrong with a network's exit-node settings, most urgent first.
pub(crate) fn warnings(network: &NetworkReport) -> Vec<Warning> {
    let exit = &network.exit;
    let mut out = Vec::new();

    if let Some(via) = &exit.via {
        let name = name_of(network, via);
        if !exit.via_online {
            out.push(Warning {
                text: format!(
                    "Exit node {name} is offline. Internet traffic is blocked until it returns or you disconnect it."
                ),
                copy: None,
            });
        } else {
            match &exit.client_rules {
                Some(rules) if rules.ok => {}
                Some(rules) => out.push(Warning {
                    text: format!(
                        "the routes to exit node {name} are incomplete: {}",
                        rules.detail
                    ),
                    copy: None,
                }),
                None => out.push(Warning {
                    text: format!("the routes to exit node {name} are not installed"),
                    copy: None,
                }),
            }
        }
    }

    if exit.offering {
        match &exit.offer_rules {
            Some(rules) if !rules.ok => out.push(Warning {
                text: format!("exit node: its rules are incomplete: {}", rules.detail),
                copy: None,
            }),
            None => out.push(Warning {
                text: "exit node: its rules are not installed yet".to_string(),
                copy: None,
            }),
            Some(_) => {}
        }
        if exit.forwarding == Some(false) {
            #[cfg(target_os = "macos")]
            out.push(Warning { text: "IPv4 forwarding is off. Enable the exit to authorize sharing this Mac’s internet.".into(),copy:None });
            #[cfg(not(target_os = "macos"))]
            out.push(Warning {
                text: format!("exit node: kernel forwarding is OFF — run: {FORWARDING_COMMAND}"),
                copy: Some(FORWARDING_COMMAND),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsunagi::ipc::{ExitReport, PeerReport, RuleSetReport};

    fn network(exit: ExitReport) -> NetworkReport {
        NetworkReport {
            peers: vec![PeerReport {
                data_error: None,
                endpoint_id: "abcdef0123456789".into(),
                hostname: Some("music".into()),
                exit_node: true,
                ..Default::default()
            }],
            exit,
            ..Default::default()
        }
    }

    fn ok() -> Option<RuleSetReport> {
        Some(RuleSetReport {
            ok: true,
            detail: "ok".into(),
        })
    }

    #[test]
    fn a_network_with_no_exit_settings_has_nothing_to_warn_about() {
        assert!(warnings(&network(ExitReport::default())).is_empty());
    }

    #[test]
    fn a_lost_exit_node_says_the_traffic_is_blocked() {
        let found = warnings(&network(ExitReport {
            via: Some("abcdef0123456789".into()),
            via_online: false,
            client_rules: ok(),
            ..Default::default()
        }));
        assert_eq!(found.len(), 1);
        assert!(
            found[0].text.contains("music is offline"),
            "{}",
            found[0].text
        );
        assert!(found[0].text.contains("blocked"), "{}", found[0].text);
    }

    #[test]
    fn a_working_exit_is_quiet_and_forwarding_off_explains_the_platform_action() {
        let working = ExitReport {
            via: Some("abcdef0123456789".into()),
            via_online: true,
            client_rules: ok(),
            ..Default::default()
        };
        assert!(warnings(&network(working)).is_empty());

        let offering = warnings(&network(ExitReport {
            offering: true,
            offer_rules: ok(),
            forwarding: Some(false),
            ..Default::default()
        }));
        assert_eq!(offering.len(), 1);
        #[cfg(target_os = "macos")]
        assert!(offering[0].copy.is_none() && offering[0].text.contains("authorize"));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(offering[0].copy, Some(FORWARDING_COMMAND));
    }
}

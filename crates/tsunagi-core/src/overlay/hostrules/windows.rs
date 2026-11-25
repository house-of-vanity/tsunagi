//! Broadcast host rules on Windows: a route and a Defender Firewall rule.
//!
//! Both are written with the `NetTCPIP` and `NetSecurity` PowerShell modules,
//! run by absolute path from `%SystemRoot%` like the DNS publisher does: the
//! in-process alternatives are `unsafe` IP Helper calls this crate forbids.
//!
//! * The route is `255.255.255.255/32` on the overlay interface, on-link, with
//!   metric 1, written to the active store only so it cannot outlive a reboot.
//!   Windows picks the interface's own address as the source of a packet sent
//!   along it; with several networks on one interface that is whichever
//!   address Windows treats as primary, which this cannot choose.
//! * The firewall rule allows inbound UDP on that interface alias from the
//!   overlay range only, in every profile. Wintun adapters are usually
//!   classified as a public network, where inbound UDP is otherwise dropped.
//!   Its display name is the tag `tsunagi:<interface>`, which is how it is
//!   found again, replaced and removed.
//!
//! Every value in a script is one this agent produced: the interface name is
//! derived from the network id and the range comes from signed state. They are
//! still single-quoted and escaped, so nothing could be read as PowerShell
//! rather than as data. Changing routes and firewall rules needs an elevated
//! process, which is reported as its own cause.
//!
//! This module is compiled everywhere so its script building is tested
//! everywhere. It could not be run against a real Windows host while it was
//! written.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use crate::BoxFuture;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::exit::{ExitHostPlan, ExitHostReport, ExitHostRules};
use super::windows_exit;
use super::{BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, RuleOutcome, tag_for};

/// A PowerShell single-quoted literal, with any embedded quote doubled.
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The step that makes the route match the plan.
///
/// A leftover route (from a crashed run, or for an old interface index) is
/// removed first so the result is exactly one route.
fn route_script(plan: &BroadcastRulesPlan) -> String {
    let alias = ps_literal(&plan.interface);
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $alias = {alias}\n\
         Get-NetRoute -DestinationPrefix '255.255.255.255/32' -InterfaceAlias $alias \
         -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n\
         New-NetRoute -DestinationPrefix '255.255.255.255/32' -InterfaceAlias $alias \
         -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null\n"
    )
}

/// The step that makes the firewall hold exactly one rule for the interface.
fn firewall_script(plan: &BroadcastRulesPlan) -> String {
    let alias = ps_literal(&plan.interface);
    let tag = ps_literal(&plan.tag());
    let range = ps_literal(&plan.range.to_string());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $alias = {alias}\n\
         $tag = {tag}\n\
         Get-NetFirewallRule -DisplayName $tag -ErrorAction SilentlyContinue | \
         Remove-NetFirewallRule -ErrorAction SilentlyContinue\n\
         New-NetFirewallRule -DisplayName $tag -Direction Inbound -Action Allow -Protocol UDP \
         -InterfaceAlias $alias -RemoteAddress {range} -Profile Any | Out-Null\n"
    )
}

/// The script that removes both, ignoring what is not there.
fn clear_script(interface: &str) -> String {
    let alias = ps_literal(interface);
    let tag = ps_literal(&tag_for(interface));
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         Get-NetRoute -DestinationPrefix '255.255.255.255/32' -InterfaceAlias {alias} \
         -PolicyStore ActiveStore | Remove-NetRoute -Confirm:$false\n\
         Get-NetFirewallRule -DisplayName {tag} | Remove-NetFirewallRule\n\
         exit 0\n"
    )
}

/// Turns what PowerShell said into a cause a person can act on.
fn classify(what: &str, text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("access is denied")
        || lower.contains("requires elevation")
        || lower.contains("run as administrator")
        || lower.contains("permissiondenied")
    {
        format!("{what}: Windows refused; run tsng from an elevated (administrator) process")
    } else if lower.contains("is not recognized") || lower.contains("commandnotfound") {
        format!("{what}: the NetTCPIP/NetSecurity PowerShell modules are not available: {text}")
    } else if text.is_empty() {
        format!("{what}: failed without saying why")
    } else {
        format!("{what}: {text}")
    }
}

/// The absolute path to Windows PowerShell, so nothing on `PATH` can stand in
/// for it.
fn powershell_path() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::Path::new(&root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// Runs a script and returns what it said on failure.
fn run_powershell(script: &str) -> Result<(), String> {
    run_powershell_output(script).map(|_| ())
}

/// Runs a script and returns what it printed, or what it said on failure.
pub(super) fn run_powershell_output(script: &str) -> Result<String, String> {
    let output = std::process::Command::new(powershell_path())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|err| format!("could not run PowerShell: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = if stderr.trim().is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(text)
}

async fn step(what: &'static str, script: String) -> RuleOutcome {
    match tokio::task::spawn_blocking(move || run_powershell(&script)).await {
        Ok(Ok(())) => RuleOutcome::Applied,
        Ok(Err(text)) => RuleOutcome::Failed(classify(what, &text)),
        Err(err) => RuleOutcome::Failed(format!("{what}: the task failed: {err}")),
    }
}

/// The Windows implementation, through PowerShell.
#[derive(Debug, Default)]
pub struct WindowsHostRules {
    relay_cache: Arc<Mutex<RelayCache>>,
}

impl WindowsHostRules {
    /// Creates it. Nothing is run until [`BroadcastHostRules::apply`].
    pub fn new() -> Self {
        Self::default()
    }
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DNS_GRACE: Duration = Duration::from_secs(120);
const MAX_RELAY_ADDRESSES: usize = 16;

/// DNS may rotate while the old relay connection is still carrying packets.
/// Keep recent answers for the relays still in use, with a fixed expiry and cap.
#[derive(Debug, Default)]
struct RelayCache {
    hosts: HashMap<String, BTreeMap<Ipv4Addr, Instant>>,
    last_refresh: Option<Instant>,
}

impl RelayCache {
    fn lookup(
        &mut self,
        hosts: &[String],
        now: Instant,
        resolve: windows_exit::Resolve<'_>,
    ) -> HashMap<String, Vec<Ipv4Addr>> {
        self.hosts.retain(|host, _| hosts.contains(host));
        let due = self
            .last_refresh
            .is_none_or(|last| now.duration_since(last) >= REFRESH_INTERVAL);
        for host in hosts {
            let known = self.hosts.entry(host.clone()).or_default();
            known.retain(|_, seen| now.duration_since(*seen) < DNS_GRACE);
            if due || known.is_empty() {
                for address in resolve(host).into_iter().take(MAX_RELAY_ADDRESSES) {
                    known.insert(address, now);
                }
                while known.len() > MAX_RELAY_ADDRESSES {
                    if let Some((&oldest, _)) = known.iter().min_by_key(|(_, seen)| **seen) {
                        known.remove(&oldest);
                    }
                }
            }
        }
        if due {
            self.last_refresh = Some(now);
        }
        self.hosts
            .iter()
            .map(|(host, addresses)| (host.clone(), addresses.keys().copied().collect()))
            .collect()
    }
}

/// The IPv4 addresses a host name resolves to; empty when it does not.
fn resolve_host(host: &str) -> Vec<std::net::Ipv4Addr> {
    use std::net::{IpAddr, ToSocketAddrs};
    (host, 443)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter_map(|addr| match addr.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .take(MAX_RELAY_ADDRESSES)
                .collect()
        })
        .unwrap_or_default()
}

impl ExitHostRules for WindowsHostRules {
    fn needs_bypass(&self) -> bool {
        true
    }

    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport> {
        Box::pin(async move {
            let job = plan.clone();
            let cache = Arc::clone(&self.relay_cache);
            tokio::task::spawn_blocking(move || {
                let hosts = cache.lock().unwrap_or_else(|p| p.into_inner()).lookup(
                    &job.bypass_hosts,
                    Instant::now(),
                    &resolve_host,
                );
                windows_exit::apply_plan(
                    &|script| run_powershell_output(script),
                    &|host| hosts.get(host).cloned().unwrap_or_default(),
                    &job,
                )
            })
            .await
            .unwrap_or_else(|err| {
                let failed = RuleOutcome::Failed(format!("the task failed: {err}"));
                ExitHostReport {
                    offer: plan
                        .offer
                        .iter()
                        .map(|range| (*range, failed.clone()))
                        .collect(),
                    forwarding: None,
                    client: plan.client.then_some(failed),
                }
            })
        })
    }

    fn refresh<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, Option<RuleOutcome>> {
        Box::pin(async move {
            if !plan.client {
                return None;
            }
            let job = plan.clone();
            let cache = Arc::clone(&self.relay_cache);
            tokio::task::spawn_blocking(move || {
                let now = Instant::now();
                let mut cache = cache.lock().unwrap_or_else(|p| p.into_inner());
                if cache
                    .last_refresh
                    .is_some_and(|last| now.duration_since(last) < REFRESH_INTERVAL)
                {
                    return None;
                }
                let hosts = cache.lookup(&job.bypass_hosts, now, &resolve_host);
                drop(cache);
                Some(
                    match windows_exit::refresh_bypass(
                        &run_powershell_output,
                        &|host| hosts.get(host).cloned().unwrap_or_default(),
                        &job,
                    ) {
                        Ok(()) => RuleOutcome::Applied,
                        Err(reason) => RuleOutcome::Failed(reason),
                    },
                )
            })
            .await
            .unwrap_or_else(|err| Some(RuleOutcome::Failed(format!("the task failed: {err}"))))
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let name = interface.to_string();
            let cache = Arc::clone(&self.relay_cache);
            let _ = tokio::task::spawn_blocking(move || {
                *cache.lock().unwrap_or_else(|p| p.into_inner()) = RelayCache::default();
                windows_exit::clear_all(&|script| run_powershell_output(script), &name)
            })
            .await;
        })
    }
}

impl BroadcastHostRules for WindowsHostRules {
    fn name(&self) -> &str {
        "windows-netsecurity"
    }

    fn exit_rules(&self) -> Option<&dyn ExitHostRules> {
        Some(self)
    }

    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let route = step("route", route_script(plan)).await;
            let firewall = step("firewall", firewall_script(plan)).await;
            BroadcastRulesReport {
                plan: plan.clone(),
                route,
                firewall,
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let RuleOutcome::Failed(reason) = step("clear", clear_script(interface)).await {
                tracing::warn!(
                    interface,
                    "cannot remove the broadcast host rules: {reason}"
                );
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn relay_dns_survives_a_transient_failure_and_retires_rotated_addresses() {
        use std::time::{Duration, Instant};
        let mut cache = RelayCache::default();
        let hosts = vec!["relay.example".into()];
        let old = [192, 0, 2, 1].into();
        let new = [192, 0, 2, 2].into();
        let now = Instant::now();
        assert_eq!(cache.lookup(&hosts, now, &|_| vec![old])[&hosts[0]], [old]);
        let later = |secs| now + Duration::from_secs(secs);
        assert_eq!(
            cache.lookup(&hosts, later(32), &|_| Vec::new())[&hosts[0]],
            [old]
        );
        let rotated = cache.lookup(&hosts, later(64), &|_| vec![new]);
        assert!(rotated[&hosts[0]].contains(&old) && rotated[&hosts[0]].contains(&new));
        assert_eq!(
            cache.lookup(&hosts, later(121), &|_| vec![new])[&hosts[0]],
            [new]
        );
        assert!(cache.lookup(&[], later(122), &|_| Vec::new()).is_empty());
    }
    use std::net::Ipv4Addr;

    fn plan() -> BroadcastRulesPlan {
        BroadcastRulesPlan {
            interface: "tsun0".into(),
            source: Ipv4Addr::new(10, 13, 37, 142),
            range: "10.13.37.0/24".parse().unwrap(),
        }
    }

    #[test]
    fn a_quote_in_a_value_cannot_escape_the_literal() {
        assert_eq!(ps_literal("a'b"), "'a''b'");
        let mut hostile = plan();
        hostile.interface = "x'; Remove-Item C:\\ #".into();
        let script = route_script(&hostile);
        assert!(
            script.contains("$alias = 'x''; Remove-Item C:\\ #'"),
            "{script}"
        );
        assert!(firewall_script(&hostile).contains("'x''; Remove-Item C:\\ #'"));
    }

    #[test]
    fn the_route_is_on_link_metric_one_in_the_active_store_and_replaces_its_own() {
        let script = route_script(&plan());
        assert!(script.contains("'255.255.255.255/32'"));
        assert!(script.contains("-NextHop '0.0.0.0'"));
        assert!(script.contains("-RouteMetric 1"));
        assert!(script.contains("-PolicyStore ActiveStore"));
        assert!(
            script.find("Remove-NetRoute").unwrap() < script.find("New-NetRoute").unwrap(),
            "a stale route goes before the new one:\n{script}"
        );
    }

    #[test]
    fn the_firewall_rule_is_udp_only_from_the_overlay_range_on_this_interface() {
        let script = firewall_script(&plan());
        assert!(script.contains("-Protocol UDP"));
        assert!(script.contains("-Direction Inbound -Action Allow"));
        assert!(script.contains("-InterfaceAlias $alias"));
        assert!(script.contains("-RemoteAddress '10.13.37.0/24'"));
        assert!(script.contains("$tag = 'tsunagi:tsun0'"));
        assert!(!script.contains("-Protocol Any") && !script.contains("-Protocol TCP"));
        assert!(
            script.find("Remove-NetFirewallRule").unwrap()
                < script.find("New-NetFirewallRule").unwrap(),
            "{script}"
        );
    }

    #[test]
    fn clearing_touches_only_our_route_and_our_tagged_rule() {
        let script = clear_script("tsun0");
        assert!(script.contains("-InterfaceAlias 'tsun0'"));
        assert!(script.contains("Get-NetFirewallRule -DisplayName 'tsunagi:tsun0'"));
        assert!(script.contains("exit 0"));
    }

    #[test]
    fn a_refusal_names_elevation_and_a_missing_module_names_the_module() {
        assert!(classify("route", "Access is denied").contains("elevated"));
        assert!(
            classify(
                "firewall",
                "The term 'New-NetFirewallRule' is not recognized"
            )
            .contains("modules are not available")
        );
        assert_eq!(classify("route", "boom"), "route: boom");
        assert!(classify("route", "").contains("without saying why"));
    }

    #[test]
    fn powershell_is_found_by_absolute_path() {
        let path = powershell_path();
        assert!(path.ends_with("powershell.exe"));
        assert!(path.to_string_lossy().contains("System32"), "{path:?}");
    }
}

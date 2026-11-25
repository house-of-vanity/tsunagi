//! Physical exit socket selection and client routes on Windows, through PowerShell.
//!
//! Compiled on every platform so the scripts and the plan logic are tested
//! everywhere; only `WindowsHostRules` runs them, and only on Windows. It
//! could not be run against a real Windows host while it was written.
//!
//! # Offering
//!
//! Forwarded TCP/UDP and ICMP echo use sockets pinned to the physical
//! interface and address. This keeps a member's traffic independent of local
//! split routes even for the same destination. The userspace gateway owns the
//! flows; changing a local upstream does not recreate them.
//!
//! # Using
//!
//! Windows has no per-user or per-process routing, so the Linux scheme (an
//! exemption for the agent's user) does not carry over. Instead the agent's
//! own underlay traffic is exempted by *destination*:
//!
//! ```text
//! New-NetRoute 0.0.0.0/1   on the overlay interface, metric 1
//! New-NetRoute 128.0.0.0/1 on the overlay interface, metric 1
//! New-NetRoute <ip>/32 via the physical default gateway, metric 7373
//! ```
//!
//! The halves out-rank the default route without replacing it, so every more
//! specific route (LAN, another VPN) keeps working. A `/32` per address the
//! agent talks to directly (the verified direct paths of its connections, and
//! the relays it uses, resolved when the rules are applied) keeps that traffic
//! on the physical network instead of looping into the tunnel it carries. The
//! metric 7373 marks those routes as ours, which is how stale ones are found
//! and removed. Everything is written to the active store, so a reboot clears
//! it. IPv6 is blackholed with `::/1` and `8000::/1` on the overlay interface,
//! which has no IPv6: applications fall back to IPv4 after a delay, where
//! Linux and macOS answer at once. The bypass follows the agent's paths as
//! they change; a path that appears after the last apply is reached through
//! the tunnel until the next one.
//!
//! The bypass routes are written before the halves, and removed after them.

use super::RuleOutcome;
use std::net::Ipv4Addr;

use super::exit::{ExitHostPlan, ExitHostReport, exit_tag_prefix};
use crate::state::Ipv4Range;

/// The route metric that marks a bypass route as this agent's.
const BYPASS_METRIC: u32 = 7373;

/// Runs a PowerShell script and returns what it printed.
pub(super) type RunScript<'a> = &'a dyn Fn(&str) -> Result<String, String>;

/// Resolves a host name to its IPv4 addresses.
pub(super) type Resolve<'a> = &'a dyn Fn(&str) -> Vec<Ipv4Addr>;

/// A PowerShell single-quoted literal, with any embedded quote doubled.
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Remove only obsolete WinNAT objects created by older Tsunagi releases.
fn legacy_nat_cleanup(interface: &str) -> String {
    let prefix = ps_literal(&exit_tag_prefix(interface));
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
        $prefix = {prefix}\n\
        Get-NetNat | Where-Object {{ $_.Name.StartsWith($prefix) }} | Remove-NetNat -Confirm:$false\n\
        exit 0"
    )
}

/// Both client bypasses and forwarded sockets use the winning /0 outside Wintun.
fn select_gateway(interface: &str) -> String {
    let alias = ps_literal(interface);
    format!(
        "$ErrorActionPreference = 'Stop'\n\
        $alias = {alias}\n\
        $best = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 \
        -PolicyStore ActiveStore | Where-Object {{ $_.InterfaceAlias -ne $alias -and \
        $_.NextHop -ne '0.0.0.0' -and $_.State -ne 'Dead' }} | Sort-Object {{ $_.RouteMetric + \
        (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }} | \
        Select-Object -First 1\n\
        if (-not $best) {{ throw 'the host has no default gateway outside the overlay' }}\n"
    )
}

/// Read a usable source on the selected physical interface, even while the two
/// client /1 routes point at Wintun. Never ask the default via the test target.
fn uplink_script(interface: &str) -> String {
    format!(
        "{}$source = Get-NetIPAddress -InterfaceIndex $best.InterfaceIndex -AddressFamily IPv4 \
        -AddressState Preferred | Where-Object {{ -not $_.SkipAsSource }} | Select-Object -First 1\n\
        if (-not $source) {{ throw 'the physical interface has no usable IPv4 address' }}\n\
        \"$($best.InterfaceIndex) $($source.IPAddress)\"",
        select_gateway(interface)
    )
}

pub(super) fn uplink(run: RunScript<'_>, interface: &str) -> Result<(u32, Ipv4Addr), String> {
    let text = run(&uplink_script(interface))?;
    parse_gateway(&text)
        .filter(|(i, ip)| {
            *i != 0
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_broadcast()
        })
        .ok_or_else(|| {
            "cannot determine the physical interface and IPv4 source for forwarding".into()
        })
}

fn gateway_script(interface: &str) -> String {
    format!(
        "{}\"$($best.InterfaceIndex) $($best.NextHop)\"\n\
         Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{ \
         $_.InterfaceAlias -ne $alias -and $_.State -ne 'Dead' -and \
         -not ($_.RouteMetric -eq {BYPASS_METRIC} -and $_.DestinationPrefix.EndsWith('/32')) }} | \
         Select-Object -ExpandProperty DestinationPrefix\n",
        select_gateway(interface)
    )
}

/// The default gateway as the script above printed it.
fn parse_gateway(text: &str) -> Option<(u32, Ipv4Addr)> {
    let mut words = text.split_whitespace();
    let index = words.next()?.parse().ok()?;
    let hop = words.next()?.parse().ok()?;
    words.next().is_none().then_some((index, hop))
}

/// Replaces the bypass routes with one per address, through the gateway.
fn bypass_script(index: u32, gateway: Ipv4Addr, addresses: &[Ipv4Addr]) -> String {
    let list: Vec<String> = addresses
        .iter()
        .map(|address| ps_literal(&address.to_string()))
        .collect();
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $keep = @(@({}) | ForEach-Object {{ \"$_/32\" }})\n\
         foreach ($p in $keep) {{\n\
         if (-not (Get-NetRoute -DestinationPrefix $p -InterfaceIndex {index} -NextHop '{gateway}' \
         -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {{\n\
         New-NetRoute -DestinationPrefix $p -InterfaceIndex {index} -NextHop '{gateway}' \
         -RouteMetric {BYPASS_METRIC} -PolicyStore ActiveStore | Out-Null\n\
         }}\n\
         }}\n\
         Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.RouteMetric -eq {BYPASS_METRIC} -and $_.DestinationPrefix.EndsWith('/32') -and \
         ($keep -notcontains $_.DestinationPrefix -or $_.InterfaceIndex -ne {index} -or $_.NextHop -ne '{gateway}') }} | \
         Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n",
        list.join(", ")
    )
}

/// Sends everything else through the overlay interface.
fn halves_script(interface: &str) -> String {
    let alias = ps_literal(interface);
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $alias = {alias}\n\
         foreach ($p in '0.0.0.0/1', '128.0.0.0/1') {{\n\
         if (Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop '0.0.0.0' \
         -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {{ continue }}\n\
         New-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop '0.0.0.0' \
         -RouteMetric 1 -PolicyStore ActiveStore | Out-Null\n\
         }}\n\
         foreach ($p in '::/1', '8000::/1') {{\n\
         if (Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop '::' \
         -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {{ continue }}\n\
         New-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop '::' \
         -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\n\
         }}\n"
    )
}

/// Removes the halves and every bypass route. What is not there is the state
/// wanted.
fn remove_client_script(interface: &str) -> String {
    let alias = ps_literal(interface);
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         $alias = {alias}\n\
         foreach ($p in '0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1') {{\n\
         Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -PolicyStore ActiveStore | \
         Remove-NetRoute -Confirm:$false\n\
         }}\n\
         Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | \
         Where-Object {{ $_.RouteMetric -eq {BYPASS_METRIC} -and $_.DestinationPrefix.EndsWith('/32') }} | \
         Remove-NetRoute -Confirm:$false\n\
         exit 0\n"
    )
}

/// Every address to keep direct: the ones given and what the names resolve
/// to, sorted and without duplicates.
fn bypass_addresses(
    resolve: Resolve<'_>,
    addresses: &[Ipv4Addr],
    hosts: &[String],
    overlay: &[Ipv4Range],
) -> Vec<Ipv4Addr> {
    let mut all: std::collections::BTreeSet<Ipv4Addr> = addresses.iter().copied().collect();
    for host in hosts {
        all.extend(resolve(host));
    }
    all.into_iter()
        .filter(|a| {
            !a.is_loopback()
                && !a.is_unspecified()
                && !a.is_multicast()
                && !a.is_link_local()
                && !a.is_broadcast()
                && !overlay.iter().any(|range| range.contains(*a))
        })
        .collect()
}

pub(super) fn refresh_bypass(
    run: RunScript<'_>,
    resolve: Resolve<'_>,
    plan: &ExitHostPlan,
) -> Result<(), String> {
    let interface = plan.interface.as_str();
    let gateway = run(&gateway_script(interface))?;
    let mut lines = gateway.lines();
    let first = lines.next().unwrap_or_default();
    let (index, hop) = parse_gateway(first)
        .ok_or_else(|| format!("cannot read the default gateway from `{first}`"))?;
    let mut addresses = bypass_addresses(resolve, &plan.bypass, &plan.bypass_hosts, &plan.overlay);
    for line in lines {
        let prefix = line.trim();
        let (network, bits) = prefix
            .split_once('/')
            .and_then(|(address, bits)| {
                Some((address.parse::<Ipv4Addr>().ok()?, bits.parse::<u8>().ok()?))
            })
            .filter(|(_, bits)| *bits <= 32)
            .ok_or_else(|| format!("cannot read physical route prefix `{prefix}`"))?;
        if bits > 1 {
            let mask = u32::MAX << (32 - bits);
            addresses.retain(|addr| u32::from(*addr) & mask != u32::from(network) & mask);
        }
    }
    run(&bypass_script(index, hop, &addresses)).map(|_| ())
}

fn apply_client(
    run: RunScript<'_>,
    resolve: Resolve<'_>,
    plan: &ExitHostPlan,
) -> Result<(), String> {
    refresh_bypass(run, resolve, plan)?;
    let interface = &plan.interface;
    if let Err(why) = run(&halves_script(interface)) {
        // Do not leave a half-installed set: bypass routes alone are harmless
        // but the next apply starts clean.
        let _ = run(&remove_client_script(interface));
        return Err(why);
    }
    Ok(())
}

/// Decide the egress for all offered memberships, then reconcile the separate
/// destination routes used by this device's applications.
pub(super) fn reconcile(
    run: RunScript<'_>,
    resolve: Resolve<'_>,
    plan: &ExitHostPlan,
) -> (ExitHostReport, Option<(u32, Ipv4Addr)>) {
    let interface = plan.interface.as_str();
    let physical = (!plan.offer.is_empty()).then(|| uplink(run, interface));
    let offer = plan
        .offer
        .iter()
        .map(|range| {
            let result = match &physical {
                Some(Ok(_)) => RuleOutcome::Applied,
                Some(Err(why)) => RuleOutcome::Failed(why.clone()),
                None => RuleOutcome::Failed("no exit offer".into()),
            };
            (*range, result)
        })
        .collect();
    let client = if plan.client {
        Some(match apply_client(run, resolve, plan) {
            Ok(()) => RuleOutcome::Applied,
            Err(why) => RuleOutcome::Failed(why),
        })
    } else {
        // Whatever an earlier plan left must not stay in force.
        let _ = run(&remove_client_script(interface));
        None
    };
    (
        ExitHostReport {
            offer,
            forwarding: None,
            client,
        },
        physical.and_then(Result::ok),
    )
}

/// Removes every NAT object of this agent's for the interface.
pub(super) fn clear_all(run: RunScript<'_>, interface: &str) {
    if let Err(why) = run(&legacy_nat_cleanup(interface)) {
        tracing::warn!(interface, "cannot remove the exit node NAT: {why}");
    }
    if let Err(why) = run(&remove_client_script(interface)) {
        tracing::warn!(interface, "cannot remove the exit node routes: {why}");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;

    use super::*;

    fn range() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    fn plan(client: bool) -> ExitHostPlan {
        ExitHostPlan {
            interface: "tsun0".into(),
            offer: vec![range()],
            client,
            overlay: vec![range()],
            ..Default::default()
        }
    }

    #[test]
    fn selecting_an_upstream_never_recreates_a_forwarded_session_or_installs_a_destination_exception()
     {
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| -> Result<String, String> {
            calls.borrow_mut().push(script.to_string());
            Ok(if script.contains("Get-NetIPAddress") {
                "7 192.0.2.15".into()
            } else if script.contains("Select-Object -ExpandProperty DestinationPrefix") {
                "7 192.0.2.1".into()
            } else {
                String::new()
            })
        };
        for client in [false, true, false] {
            let (report, physical) = reconcile(&run, &no_names, &plan(client));
            assert_eq!(physical, Some((7, "192.0.2.15".parse().unwrap())));
            assert_eq!(report.offer, vec![(range(), RuleOutcome::Applied)]);
            assert_eq!(report.forwarding, None);
        }
        assert!(
            !calls
                .borrow()
                .iter()
                .any(|s| s.contains("NetNat") || s.contains("Set-NetIPInterface"))
        );
        assert!(uplink_script("x'y").contains("'x''y'"));
    }

    #[test]
    fn failure_to_find_a_physical_source_never_advertises_a_working_exit() {
        for line in [
            "",
            "0 198.51.100.3",
            "5 0.0.0.0",
            "5 127.0.0.1",
            "3 10.0.0.1 extra",
        ] {
            let (report, physical) = reconcile(&|_| Ok(line.into()), &no_names, &plan(false));
            assert_eq!(physical, None);
            assert!(matches!(&report.offer[0].1, RuleOutcome::Failed(_)));
        }
    }

    fn apply_plan(run: RunScript<'_>, resolve: Resolve<'_>, plan: &ExitHostPlan) -> ExitHostReport {
        reconcile(run, resolve, plan).0
    }

    fn no_names(_: &str) -> Vec<Ipv4Addr> {
        Vec::new()
    }

    /// Run the real refresh against the Windows ActiveStore. The fixture
    /// only permits its TEST-NET /32 and refuses to prune pre-existing routes.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated disposable Windows runner with a physical default gateway"]
    fn windows_refresh_installs_only_the_external_test_address() {
        use super::super::windows::run_powershell_output;

        let target = Ipv4Addr::new(198, 51, 100, 207);
        let inventory = run_powershell_output(&gateway_script("tsng-native-test")).unwrap();
        let (index, gateway) = parse_gateway(inventory.lines().next().unwrap()).unwrap();
        let plan = ExitHostPlan {
            interface: "tsng-native-test".into(),
            bypass: vec![gateway, target],
            client: true,
            ..Default::default()
        };
        let run = |script: &str| {
            if script == gateway_script(&plan.interface) {
                return Ok(inventory.clone());
            }
            // Catch a failure to recognize the gateway's connected LAN before
            // executing a script which might create a route to the gateway.
            assert!(script.contains(&format!("$keep = @(@('{target}') |")));
            let guarded = format!(
                r#"$ErrorActionPreference = 'Stop'
$prefix = '{target}/32'
$before = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{
    $_.DestinationPrefix -eq $prefix -or ($_.RouteMetric -eq {BYPASS_METRIC} -and $_.DestinationPrefix.EndsWith('/32'))
}})
if ($before.Count) {{ throw 'fixture requires an unused test prefix and no pre-existing bypass routes' }}
try {{
    {script}
    $actual = @(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction Stop)
    if ($actual.Count -ne 1 -or $actual[0].InterfaceIndex -ne {index} -or
        $actual[0].NextHop -ne '{gateway}' -or $actual[0].RouteMetric -ne {BYPASS_METRIC}) {{
        throw 'unexpected physical bypass route'
    }}
}} finally {{
    Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex {index} -NextHop '{gateway}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object {{ $_.RouteMetric -eq {BYPASS_METRIC} }} | Remove-NetRoute -Confirm:$false
}}
if (Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {{
    throw 'test route still present after cleanup'
}}
exit 0"#
            );
            run_powershell_output(&guarded)
        };
        refresh_bypass(&run, &no_names, &plan).unwrap();
    }

    fn client_plan() -> ExitHostPlan {
        ExitHostPlan {
            interface: "tsun0".into(),
            offer: Vec::new(),
            client: true,
            overlay: vec![range()],
            bypass: vec![Ipv4Addr::new(138, 201, 61, 182)],
            bypass_hosts: vec!["relay.example".into()],
            ..Default::default()
        }
    }

    #[test]
    fn the_gateway_is_read_from_the_script_output() {
        assert_eq!(
            parse_gateway("12 192.168.1.1\r\n"),
            Some((12, Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(parse_gateway(""), None);
        assert_eq!(parse_gateway("12"), None);
        assert_eq!(parse_gateway("12 gw"), None);
        assert_eq!(parse_gateway("12 1.1.1.1 extra"), None);
        let script = gateway_script("tsun0");
        assert!(script.contains("-ne $alias"));
        assert!(script.contains("-ne '0.0.0.0'"));
    }

    #[test]
    fn bypass_routes_are_marked_host_routes_through_the_physical_gateway() {
        let script = bypass_script(
            12,
            Ipv4Addr::new(192, 168, 1, 1),
            &[Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
        );
        assert!(script.contains("@('1.2.3.4', '5.6.7.8')"), "{script}");
        assert!(script.contains("-InterfaceIndex 12 -NextHop '192.168.1.1'"));
        assert!(script.contains("-RouteMetric 7373"));
        assert!(script.contains("-PolicyStore ActiveStore"));
        // Install missing routes before pruning stale entries. Existing paths
        // continue carrying the tunnel throughout another network's update.
        assert!(script.find("New-NetRoute").unwrap() < script.find("Remove-NetRoute").unwrap());
        assert!(script.contains("$keep -notcontains $_.DestinationPrefix"));
        assert!(script.contains("RouteMetric -eq 7373"));
        assert!(script.contains("EndsWith('/32')"));
    }

    #[test]
    fn the_halves_go_through_the_overlay_and_ipv6_is_blackholed() {
        let script = halves_script("tsun0");
        assert!(
            !script.contains("Remove-NetRoute"),
            "reapplying must keep existing split defaults: {script}"
        );
        assert!(script.contains("'0.0.0.0/1', '128.0.0.0/1'"));
        assert!(script.contains("-InterfaceAlias $alias -NextHop '0.0.0.0'"));
        assert!(script.contains("'::/1', '8000::/1'"));
        assert!(script.contains("-PolicyStore ActiveStore"));
        assert!(
            !script.contains("0.0.0.0/0"),
            "the default route is left alone"
        );
        assert!(halves_script("x'y").contains("'x''y'"));
    }

    #[test]
    fn addresses_are_resolved_merged_and_cleaned() {
        let resolve = |host: &str| -> Vec<Ipv4Addr> {
            match host {
                "relay.example" => vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 2, 3, 4)],
                _ => Vec::new(),
            }
        };
        let all = bypass_addresses(
            &resolve,
            &[
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::UNSPECIFIED,
            ],
            &["relay.example".into(), "gone.example".into()],
            &[],
        );
        assert_eq!(
            all,
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(9, 9, 9, 9)]
        );
    }

    #[test]
    fn the_bypass_is_written_before_the_halves_that_need_it() {
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| -> Result<String, String> {
            calls.borrow_mut().push(script.to_string());
            Ok(if script.contains("Select-Object -First 1") {
                "12 192.168.1.1\n".to_string()
            } else {
                String::new()
            })
        };
        let resolve = |_: &str| vec![Ipv4Addr::new(9, 9, 9, 9)];
        let report = apply_plan(&run, &resolve, &client_plan());
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        let calls = calls.borrow();
        let at = |needle: &str| calls.iter().position(|c| c.contains(needle)).unwrap();
        assert!(at("Select-Object -First 1") < at("-RouteMetric 7373"));
        assert!(at("-RouteMetric 7373") < at("'0.0.0.0/1', '128.0.0.0/1'"));
        let bypass = &calls[at("-RouteMetric 7373")];
        assert!(
            bypass.contains("'9.9.9.9'") && bypass.contains("'138.201.61.182'"),
            "{bypass}"
        );
    }

    #[test]
    fn relay_dns_cannot_install_a_host_route_over_either_overlay() {
        let mut plan = client_plan();
        plan.overlay.push("10.99.0.0/24".parse().unwrap());
        let resolve = |_: &str| {
            ["10.13.37.4", "10.99.0.6", "9.9.9.9"]
                .map(|ip| ip.parse().unwrap())
                .to_vec()
        };
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| {
            calls.borrow_mut().push(script.to_string());
            Ok("12 192.168.1.1".to_string())
        };
        apply_client(&run, &resolve, &plan).unwrap();
        let calls = calls.borrow();
        let bypass = calls
            .iter()
            .find(|c| c.contains("-RouteMetric 7373"))
            .unwrap();
        assert!(bypass.contains("'9.9.9.9'") && bypass.contains("'138.201.61.182'"));
        assert!(!bypass.contains("'10.13.37.4'") && !bypass.contains("'10.99.0.6'"));
    }

    #[test]
    fn a_connected_lan_and_an_existing_host_route_stay_on_their_own_paths() {
        let mut plan = client_plan();
        for addr in ["192.168.1.11", "198.51.100.7", "198.51.100.9"] {
            plan.bypass.push(addr.parse().unwrap());
        }
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| {
            calls.borrow_mut().push(script.to_string());
            Ok("12 192.168.1.1\n192.168.1.0/24\n198.51.100.7/32\n".into())
        };
        apply_client(&run, &no_names, &plan).unwrap();
        let calls = calls.borrow();
        let bypass = calls.iter().find(|s| s.contains("New-NetRoute")).unwrap();
        assert!(!bypass.contains("'192.168.1.11'"));
        assert!(!bypass.contains("'198.51.100.7'"));
        assert!(bypass.contains("'198.51.100.9'"));
    }

    #[test]
    fn refreshing_uses_the_new_physical_gateway_without_touching_the_exit_routes() {
        let plan = client_plan();
        let routes = RefCell::new(Vec::new());
        for gateway in ["12 192.168.1.1", "17 10.0.0.1"] {
            let run = |script: &str| {
                if script.contains("Select-Object -First 1") {
                    Ok(gateway.into())
                } else {
                    routes.borrow_mut().push(script.to_owned());
                    Ok(String::new())
                }
            };
            refresh_bypass(&run, &no_names, &plan).unwrap();
        }
        let routes = routes.into_inner();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("-InterfaceIndex 12 -NextHop '192.168.1.1'"));
        assert!(routes[1].contains("-InterfaceIndex 17 -NextHop '10.0.0.1'"));
        assert!(routes.iter().all(|s| !s.contains("'0.0.0.0/1'")));
    }

    #[test]
    fn nothing_goes_through_the_overlay_when_the_bypass_cannot_be_written() {
        let run = |script: &str| -> Result<String, String> {
            if script.contains("Select-Object -First 1") {
                Ok("12 192.168.1.1".to_string())
            } else if script.contains("-RouteMetric 7373") && script.contains("New-NetRoute") {
                Err("Access is denied".to_string())
            } else {
                assert!(!script.contains("-NextHop '0.0.0.0'"), "{script}");
                Ok(String::new())
            }
        };
        let report = apply_plan(&run, &no_names, &client_plan());
        assert_eq!(
            report.client,
            Some(RuleOutcome::Failed("Access is denied".into()))
        );
    }

    #[test]
    fn a_missing_gateway_is_a_failure_that_installs_no_route() {
        let run = |script: &str| -> Result<String, String> {
            assert!(!script.contains("New-NetRoute"), "{script}");
            if script.contains("Select-Object -First 1") {
                Err("the host has no default gateway outside the overlay".into())
            } else {
                Ok(String::new())
            }
        };
        let report = apply_plan(&run, &no_names, &client_plan());
        let Some(RuleOutcome::Failed(why)) = report.client else {
            panic!("{report:?}");
        };
        assert!(why.contains("no default gateway"), "{why}");
    }

    #[test]
    fn a_failed_halves_step_removes_what_was_written() {
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| -> Result<String, String> {
            calls.borrow_mut().push(script.to_string());
            if script.contains("Select-Object -First 1") {
                Ok("12 192.168.1.1".to_string())
            } else if script.contains("'128.0.0.0/1'") && script.contains("New-NetRoute") {
                Err("boom".to_string())
            } else {
                Ok(String::new())
            }
        };
        let report = apply_plan(&run, &no_names, &client_plan());
        assert!(matches!(report.client, Some(RuleOutcome::Failed(_))));
        assert!(calls.borrow().last().unwrap().contains("Remove-NetRoute"));
    }

    #[test]
    fn dropping_the_client_removes_its_routes_and_clearing_does_too() {
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| -> Result<String, String> {
            calls.borrow_mut().push(script.to_string());
            Ok(String::new())
        };
        let report = apply_plan(&run, &no_names, &plan(false));
        assert_eq!(report.client, None);
        assert!(
            calls
                .borrow()
                .iter()
                .any(|c| c.contains("RouteMetric -eq 7373"))
        );
        let script = remove_client_script("tsun0");
        assert!(script.contains("'0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'"));
        assert!(script.contains("exit 0"));
        // Only routes on our interface, or marked ours, are touched.
        assert!(script.contains("-InterfaceAlias $alias"));
        calls.borrow_mut().clear();
        clear_all(&run, "tsun0");
        assert!(
            calls
                .borrow()
                .iter()
                .any(|c| c.contains("RouteMetric -eq 7373"))
        );
    }

    #[test]
    fn clearing_prunes_everything_for_the_interface() {
        let seen = RefCell::new(Vec::<String>::new());
        let run = |script: &str| -> Result<String, String> {
            seen.borrow_mut().push(script.to_string());
            Ok(String::new())
        };
        clear_all(&run, "tsun0");
        let seen = seen.borrow();
        assert!(seen[0].contains("StartsWith($prefix)"));
        assert!(seen[0].contains("'tsunagi-exit:tsun0:'"));
    }
}

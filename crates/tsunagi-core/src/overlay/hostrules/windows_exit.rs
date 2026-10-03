//! Exit-node host rules on Windows: WinNAT through PowerShell.
//!
//! Compiled on every platform so the scripts and the plan logic are tested
//! everywhere; only `WindowsHostRules` runs them, and only on Windows. It
//! could not be run against a real Windows host while it was written.
//!
//! # Offering
//!
//! One NAT object per offered range, named with the usual tag
//! `tsunagi-exit:<if>:<range>`:
//!
//! ```text
//! New-NetNat -Name <tag> -InternalIPInterfaceAddressPrefix <range>
//! ```
//!
//! WinNAT translates that range out of whichever interface the traffic leaves
//! by, which is the Windows counterpart of the Linux masquerade. Windows
//! forwards per interface, and the egress is not known here, so forwarding is
//! only *read* for the overlay interface; turning it on for the interfaces
//! involved is the owner's decision (`Set-NetIPInterface -Forwarding Enabled`).
//! Some Windows versions allow a single NAT per host: a second offered range
//! then reports its own failure.
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

use super::exit::{ExitHostPlan, ExitHostReport, exit_tag, exit_tag_prefix};
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

/// Creates the NAT of one range, replacing one this agent made before.
fn nat_script(interface: &str, range: &Ipv4Range) -> String {
    let name = ps_literal(&exit_tag(interface, range));
    let prefix = ps_literal(&range.to_string());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $name = {name}\n\
         Get-NetNat -Name $name -ErrorAction SilentlyContinue | \
         Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue\n\
         New-NetNat -Name $name -InternalIPInterfaceAddressPrefix {prefix} | Out-Null\n"
    )
}

/// Removes this interface's NAT objects except those named in `keep`.
fn prune_script(interface: &str, keep: &[Ipv4Range]) -> String {
    let prefix = ps_literal(&exit_tag_prefix(interface));
    let keep: Vec<String> = keep
        .iter()
        .map(|range| ps_literal(&exit_tag(interface, range)))
        .collect();
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\n\
         $prefix = {prefix}\n\
         $keep = @({})\n\
         Get-NetNat | Where-Object {{ $_.Name.StartsWith($prefix) -and \
         ($keep -notcontains $_.Name) }} | Remove-NetNat -Confirm:$false\n\
         exit 0\n",
        keep.join(", ")
    )
}

/// Prints `Enabled` or `Disabled` for the interface's IPv4 forwarding.
fn forwarding_script(interface: &str) -> String {
    let alias = ps_literal(interface);
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         (Get-NetIPInterface -InterfaceAlias {alias} -AddressFamily IPv4).Forwarding\n"
    )
}

/// Prints `<interface index> <next hop>` of the best default route that is
/// not through the overlay interface.
fn gateway_script(interface: &str) -> String {
    let alias = ps_literal(interface);
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $alias = {alias}\n\
         $best = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 \
         -PolicyStore ActiveStore | Where-Object {{ $_.InterfaceAlias -ne $alias -and \
         $_.NextHop -ne '0.0.0.0' }} | Sort-Object {{ $_.RouteMetric + \
         (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }} | \
         Select-Object -First 1\n\
         if (-not $best) {{ throw 'the host has no default gateway outside the overlay' }}\n\
         \"$($best.InterfaceIndex) $($best.NextHop)\"\n"
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
         Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.RouteMetric -eq {BYPASS_METRIC} -and $_.DestinationPrefix.EndsWith('/32') }} | \
         Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n\
         foreach ($ip in @({})) {{\n\
         New-NetRoute -DestinationPrefix \"$ip/32\" -InterfaceIndex {index} -NextHop '{gateway}' \
         -RouteMetric {BYPASS_METRIC} -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null\n\
         }}\n",
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
         Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -PolicyStore ActiveStore \
         -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n\
         New-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -NextHop '0.0.0.0' \
         -RouteMetric 1 -PolicyStore ActiveStore | Out-Null\n\
         }}\n\
         foreach ($p in '::/1', '8000::/1') {{\n\
         Get-NetRoute -DestinationPrefix $p -InterfaceAlias $alias -PolicyStore ActiveStore \
         -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n\
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
) -> Vec<Ipv4Addr> {
    let mut all: std::collections::BTreeSet<Ipv4Addr> = addresses.iter().copied().collect();
    for host in hosts {
        all.extend(resolve(host));
    }
    all.into_iter()
        .filter(|a| !a.is_loopback() && !a.is_unspecified() && !a.is_multicast())
        .collect()
}

fn apply_client(
    run: RunScript<'_>,
    resolve: Resolve<'_>,
    plan: &ExitHostPlan,
) -> Result<(), String> {
    let interface = plan.interface.as_str();
    let gateway = run(&gateway_script(interface))?;
    let (index, hop) = parse_gateway(&gateway)
        .ok_or_else(|| format!("cannot read the default gateway from `{}`", gateway.trim()))?;
    let addresses = bypass_addresses(resolve, &plan.bypass, &plan.bypass_hosts);
    run(&bypass_script(index, hop, &addresses))?;
    if let Err(why) = run(&halves_script(interface)) {
        // Do not leave a half-installed set: bypass routes alone are harmless
        // but the next apply starts clean.
        let _ = run(&remove_client_script(interface));
        return Err(why);
    }
    Ok(())
}

fn parse_forwarding(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "enabled" | "1" => Some(true),
        "disabled" | "0" => Some(false),
        _ => None,
    }
}

/// Makes the host match the plan.
pub(super) fn apply_plan(
    run: RunScript<'_>,
    resolve: Resolve<'_>,
    plan: &ExitHostPlan,
) -> ExitHostReport {
    let interface = plan.interface.as_str();
    // What an earlier plan left and this one no longer wants.
    let pruned = run(&prune_script(interface, &plan.offer));
    let offer = plan
        .offer
        .iter()
        .map(|range| {
            let outcome = match &pruned {
                Err(why) => RuleOutcome::Failed(why.clone()),
                Ok(_) => match run(&nat_script(interface, range)) {
                    Ok(_) => RuleOutcome::Applied,
                    Err(why) => RuleOutcome::Failed(why),
                },
            };
            (*range, outcome)
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
    let forwarding = if plan.offer.is_empty() {
        None
    } else {
        run(&forwarding_script(interface))
            .ok()
            .and_then(|text| parse_forwarding(&text))
    };
    ExitHostReport {
        offer,
        forwarding,
        client,
    }
}

/// Removes every NAT object of this agent's for the interface.
pub(super) fn clear_all(run: RunScript<'_>, interface: &str) {
    if let Err(why) = run(&prune_script(interface, &[])) {
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
    fn the_nat_is_named_with_the_tag_and_replaces_its_own() {
        let script = nat_script("tsun0", &range());
        assert!(
            script.contains("$name = 'tsunagi-exit:tsun0:10.13.37.0/24'"),
            "{script}"
        );
        assert!(script.contains("-InternalIPInterfaceAddressPrefix '10.13.37.0/24'"));
        assert!(
            script.find("Remove-NetNat").unwrap() < script.find("New-NetNat").unwrap(),
            "{script}"
        );
    }

    #[test]
    fn a_quote_in_a_value_cannot_escape_the_literal() {
        let script = nat_script("x'; Remove-Item C:\\ #", &range());
        assert!(script.contains("'tsunagi-exit:x''; Remove-Item C:\\ #:10.13.37.0/24'"));
        assert!(prune_script("x'y", &[]).contains("'tsunagi-exit:x''y:'"));
        assert!(forwarding_script("x'y").contains("'x''y'"));
    }

    #[test]
    fn pruning_keeps_wanted_ranges_and_only_selects_this_interfaces_nats() {
        let script = prune_script("tsun0", &[range()]);
        assert!(script.contains("$prefix = 'tsunagi-exit:tsun0:'"));
        assert!(script.contains("$keep = @('tsunagi-exit:tsun0:10.13.37.0/24')"));
        assert!(script.contains("StartsWith($prefix)"));
        assert!(script.contains("exit 0"));
        assert!(prune_script("tsun0", &[]).contains("$keep = @()"));
    }

    #[test]
    fn forwarding_text_is_read_never_written() {
        assert_eq!(parse_forwarding("Enabled\r\n"), Some(true));
        assert_eq!(parse_forwarding("Disabled"), Some(false));
        assert_eq!(parse_forwarding("what"), None);
        let script = forwarding_script("tsun0");
        assert!(script.contains("Get-NetIPInterface"));
        assert!(!script.contains("Set-NetIPInterface"));
    }

    #[test]
    fn offering_prunes_then_creates_and_reads_forwarding() {
        let calls = RefCell::new(Vec::new());
        let run = |script: &str| -> Result<String, String> {
            calls.borrow_mut().push(script.to_string());
            Ok(if script.contains("Get-NetIPInterface") {
                "Disabled\n".to_string()
            } else {
                String::new()
            })
        };
        let report = apply_plan(&run, &no_names, &plan(false));
        assert_eq!(report.offer, vec![(range(), RuleOutcome::Applied)]);
        assert_eq!(report.forwarding, Some(false));
        assert_eq!(report.client, None);
        let calls = calls.borrow();
        assert!(calls[0].contains("StartsWith"), "{calls:?}");
        assert!(calls[1].contains("New-NetNat"), "{calls:?}");
        // Without a client, the routes of an earlier plan are taken away.
        assert!(calls[2].contains("RouteMetric -eq 7373"), "{calls:?}");
        assert!(calls[3].contains("Get-NetIPInterface"), "{calls:?}");
    }

    #[test]
    fn a_failing_nat_is_that_ranges_failure() {
        let run = |script: &str| -> Result<String, String> {
            if script.contains("New-NetNat") {
                Err("A NAT with this prefix already exists".into())
            } else {
                Ok(String::new())
            }
        };
        let report = apply_plan(&run, &no_names, &plan(false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("already exists"), "{why}");
    }

    fn no_names(_: &str) -> Vec<Ipv4Addr> {
        Vec::new()
    }

    fn client_plan() -> ExitHostPlan {
        ExitHostPlan {
            interface: "tsun0".into(),
            offer: Vec::new(),
            client: true,
            overlay: vec![range()],
            bypass: vec![Ipv4Addr::new(138, 201, 61, 182)],
            bypass_hosts: vec!["relay.example".into()],
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
        // Stale marked routes go first, and only /32 ones with our metric.
        assert!(script.find("Remove-NetRoute").unwrap() < script.find("New-NetRoute").unwrap());
        assert!(script.contains("RouteMetric -eq 7373"));
        assert!(script.contains("EndsWith('/32')"));
    }

    #[test]
    fn the_halves_go_through_the_overlay_and_ipv6_is_blackholed() {
        let script = halves_script("tsun0");
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
    fn nothing_goes_through_the_overlay_when_the_bypass_cannot_be_written() {
        let run = |script: &str| -> Result<String, String> {
            if script.contains("Select-Object -First 1") {
                Ok("12 192.168.1.1".to_string())
            } else if script.contains("-RouteMetric 7373") && script.contains("foreach ($ip") {
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
        assert!(seen[0].contains("$keep = @()"));
        assert!(seen[0].contains("'tsunagi-exit:tsun0:'"));
    }
}

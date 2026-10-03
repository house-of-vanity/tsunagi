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
//! Not available. Windows has no per-user or per-process routing, so the
//! agent's own QUIC, relay and DHT traffic cannot be kept out of a default
//! route through the overlay: it would loop into the tunnel it carries. Rather
//! than install something that stops the agent working, the using side
//! reports why it is not in place and changes nothing.

use super::RuleOutcome;
use super::exit::{ExitHostPlan, ExitHostReport, exit_tag, exit_tag_prefix};
use crate::state::Ipv4Range;

/// Why the using side is not installed.
pub(super) const CLIENT_UNAVAILABLE: &str = "using an exit node is not available on Windows yet: \
     Windows cannot keep the agent's own traffic out of a default route through the overlay, \
     so it would loop";

/// Runs a PowerShell script and returns what it printed.
pub(super) type RunScript<'a> = &'a dyn Fn(&str) -> Result<String, String>;

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

fn parse_forwarding(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "enabled" | "1" => Some(true),
        "disabled" | "0" => Some(false),
        _ => None,
    }
}

/// Makes the host match the plan.
pub(super) fn apply_plan(run: RunScript<'_>, plan: &ExitHostPlan) -> ExitHostReport {
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
        client: plan
            .client
            .then(|| RuleOutcome::Failed(CLIENT_UNAVAILABLE.to_string())),
    }
}

/// Removes every NAT object of this agent's for the interface.
pub(super) fn clear_all(run: RunScript<'_>, interface: &str) {
    if let Err(why) = run(&prune_script(interface, &[])) {
        tracing::warn!(interface, "cannot remove the exit node NAT: {why}");
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
        let report = apply_plan(&run, &plan(false));
        assert_eq!(report.offer, vec![(range(), RuleOutcome::Applied)]);
        assert_eq!(report.forwarding, Some(false));
        assert_eq!(report.client, None);
        let calls = calls.borrow();
        assert!(calls[0].contains("StartsWith"), "{calls:?}");
        assert!(calls[1].contains("New-NetNat"), "{calls:?}");
        assert!(calls[2].contains("Get-NetIPInterface"), "{calls:?}");
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
        let report = apply_plan(&run, &plan(false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("already exists"), "{why}");
    }

    #[test]
    fn using_an_exit_node_is_refused_and_changes_nothing() {
        let calls = RefCell::new(0usize);
        let run = |script: &str| -> Result<String, String> {
            *calls.borrow_mut() += 1;
            // No script may touch routes.
            assert!(!script.contains("Route"), "{script}");
            Ok(String::new())
        };
        let report = apply_plan(&run, &plan(true));
        let Some(RuleOutcome::Failed(why)) = report.client else {
            panic!("{report:?}");
        };
        assert!(why.contains("not available on Windows"), "{why}");
        assert!(why.contains("loop"), "{why}");
    }

    #[test]
    fn clearing_prunes_everything_for_the_interface() {
        let seen = RefCell::new(String::new());
        let run = |script: &str| -> Result<String, String> {
            *seen.borrow_mut() = script.to_string();
            Ok(String::new())
        };
        clear_all(&run, "tsun0");
        assert!(seen.borrow().contains("$keep = @()"));
        assert!(seen.borrow().contains("'tsunagi-exit:tsun0:'"));
    }
}

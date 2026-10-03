//! Broadcast host rules on macOS: a `route` entry; the firewall is deferred.
//!
//! The limited-broadcast route is installed with `/sbin/route`, so a game's
//! LAN discovery packet leaves through the overlay interface. It belongs to
//! the interface and is removed when broadcast is turned off, the network
//! leaves, or the agent stops — and, because a utun is torn down with the
//! process, it also goes away on its own if the agent is killed.
//!
//! The inbound-UDP firewall allowance is **not** implemented here. On macOS
//! that means a `pf` anchor, which is a good deal more machinery; until it is
//! written the firewall half reports itself as missing with what to allow by
//! hand, and the route is still installed. Failure is contained: neither half
//! can stop the agent, and `status` shows exactly which is in place.
//!
//! `route` is a program, not a system call, so it is run by absolute path from
//! `/sbin` rather than off `PATH`, and its arguments are built from values
//! this agent computed — the interface name the kernel assigned, nothing a
//! peer said.

use crate::BoxFuture;

use super::{BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, RuleOutcome};

/// The limited-broadcast destination routed through the overlay interface.
const LIMITED_BROADCAST: &str = "255.255.255.255";

/// The `route` arguments that direct the limited broadcast out an interface.
fn route_add_args(interface: &str) -> Vec<String> {
    vec![
        "-q".into(),
        "-n".into(),
        "add".into(),
        "-host".into(),
        LIMITED_BROADCAST.into(),
        "-interface".into(),
        interface.into(),
    ]
}

/// The `route` arguments that remove it again.
fn route_del_args(interface: &str) -> Vec<String> {
    vec![
        "-q".into(),
        "-n".into(),
        "delete".into(),
        "-host".into(),
        LIMITED_BROADCAST.into(),
        "-interface".into(),
        interface.into(),
    ]
}

/// What to do by hand while the `pf` allowance is unimplemented.
fn firewall_todo(plan: &BroadcastRulesPlan) -> String {
    format!(
        "the inbound-UDP firewall allowance is not implemented on macOS yet; if the host \
         firewall drops discovery replies, allow inbound UDP from {} on `{}` with a pf rule \
         yourself",
        plan.range, plan.interface
    )
}

/// The macOS implementation: `route` for the route, no firewall yet.
#[derive(Debug, Default)]
pub struct MacosHostRules;

impl MacosHostRules {
    /// Creates the host rules.
    pub fn new() -> Self {
        Self
    }

    /// Installs the route, replacing one this agent added earlier so the call
    /// can be repeated. The delete is best effort: a route that is not there
    /// is the state the add then reaches anyway.
    async fn set_route(&self, interface: String) -> RuleOutcome {
        let _ = run(route_del_args(&interface)).await;
        match run(route_add_args(&interface)).await {
            Ok(()) => RuleOutcome::Applied,
            Err(reason) => RuleOutcome::Failed(reason),
        }
    }
}

impl BroadcastHostRules for MacosHostRules {
    fn name(&self) -> &str {
        "route"
    }

    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let route = self.set_route(plan.interface.clone()).await;
            BroadcastRulesReport {
                plan: plan.clone(),
                route,
                firewall: RuleOutcome::Failed(firewall_todo(plan)),
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Err(reason) = run(route_del_args(interface)).await {
                tracing::debug!(interface = %interface, %reason, "cannot remove the broadcast route");
            }
        })
    }
}

/// Runs `/sbin/route`, turning a non-zero exit into the message it printed.
async fn run(args: Vec<String>) -> Result<(), String> {
    let display = format!("route {}", args.join(" "));
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/sbin/route")
            .args(&args)
            .output()
    })
    .await
    .map_err(|err| format!("could not run {display}: {err}"))?
    .map_err(|err| format!("could not run {display}: {err}"))?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = stderr.trim();
    if text.is_empty() {
        Err(format!("{display} failed with {}", output.status))
    } else {
        Err(format!("{display} failed: {text}"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::Ipv4Addr;

    use super::*;

    fn plan() -> BroadcastRulesPlan {
        BroadcastRulesPlan {
            interface: "utun5".into(),
            source: Ipv4Addr::new(10, 13, 37, 142),
            range: "10.13.37.0/24".parse().unwrap(),
        }
    }

    #[test]
    fn the_route_is_the_limited_broadcast_out_the_interface() {
        assert_eq!(
            route_add_args("utun5"),
            vec![
                "-q",
                "-n",
                "add",
                "-host",
                "255.255.255.255",
                "-interface",
                "utun5"
            ]
        );
        assert_eq!(
            route_del_args("utun5"),
            vec![
                "-q",
                "-n",
                "delete",
                "-host",
                "255.255.255.255",
                "-interface",
                "utun5"
            ]
        );
    }

    #[test]
    fn the_firewall_todo_names_the_range_and_interface() {
        let todo = firewall_todo(&plan());
        assert!(todo.contains("10.13.37.0/24"), "{todo}");
        assert!(todo.contains("utun5"), "{todo}");
        assert!(todo.contains("pf"), "{todo}");
        // Deferred, so the firewall half is always reported as not in place;
        // the route runs for real and so is left to an on-host check. Running
        // `route` here would need root and would change the host routing
        // table, which the default test suite must never do.
    }
}

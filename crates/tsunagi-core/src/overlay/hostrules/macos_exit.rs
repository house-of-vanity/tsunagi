//! Exit-node host rules on macOS: a `pf` anchor and `route` entries.
//!
//! Compiled on every platform so the rule text and the parsers are tested
//! everywhere; only `MacosHostRules` runs them, and only on macOS.
//!
//! # Offering
//!
//! Per offered range, in the anchor `com.apple/tsunagi-exit-<if>`:
//!
//! ```text
//! nat on <egress> inet from <range> to any -> (<egress>)
//! pass in quick on <if> inet from <range> to ! <range>
//! ```
//!
//! The anchor lives under `com.apple/` on purpose: the stock `/etc/pf.conf`
//! evaluates `nat-anchor "com.apple/*"` and `anchor "com.apple/*"`, so the
//! rules take effect without editing the user's ruleset. `pf` cannot say
//! "every interface but one" in a translation address, so the egress is the
//! interface of the default route **when the rules are applied**; after the
//! default route moves (Wi-Fi to Ethernet) the rules are re-applied by
//! switching the exit node off and on, or restarting the agent.
//!
//! The kernel's `net.inet.ip.forwarding` is only read, never written: it
//! changes how the whole host behaves, which is the owner's decision.
//!
//! # Using
//!
//! macOS has no `uidrange` policy routing, and the agent is root, so the
//! Linux scheme does not carry over. Instead:
//!
//! ```text
//! route add -net 0.0.0.0/1   -interface <if>
//! route add -net 128.0.0.0/1 -interface <if>
//! pass out quick on <if> route-to (<egress> <gateway>) inet proto { tcp udp }
//!     from any to ! <overlay ranges> user <agent uid>
//! nat on <egress> inet from (<if>) to any -> (<egress>)
//! ```
//!
//! The two halves outrank the default route without replacing it, and every
//! more specific route (LAN, another VPN) keeps working. The `route-to` rule
//! sends the *agent's own* traffic — QUIC, relay, DHT, which would otherwise
//! loop into the tunnel it carries — back out the physical interface, and the
//! translation gives it that interface's address, since an unbound socket
//! picked the overlay address when the route pointed at the overlay. Like the
//! Linux exemption this is by user id, so anything else running as root also
//! bypasses the tunnel.
//!
//! IPv6 is blocked while an exit node is in use, as on Linux: `::/1` and
//! `8000::/1` are rejecting routes, so applications fall back to IPv4 at once
//! instead of leaking.
//!
//! Every object is derived from local state and the interface the agent owns;
//! none of it comes from a peer.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use crate::state::Ipv4Range;

use super::RuleOutcome;
use super::exit::{ExitHostPlan, ExitHostReport};

/// The programs this module runs, always by absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tool {
    Route,
    Pfctl,
    Sysctl,
    Id,
}

impl Tool {
    fn path(self) -> &'static str {
        match self {
            Self::Route => "/sbin/route",
            Self::Pfctl => "/sbin/pfctl",
            Self::Sysctl => "/usr/sbin/sysctl",
            Self::Id => "/usr/bin/id",
        }
    }
}

/// What running a tool came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ran {
    /// The program is not there.
    Missing,
    /// It ran.
    Exited {
        success: bool,
        stdout: String,
        stderr: String,
    },
}

/// Runs a tool with optional standard input; injectable so the logic is
/// tested without touching the host.
pub(super) type Run<'a> = &'a dyn Fn(Tool, &[String], Option<&str>) -> Ran;

/// Runs a real tool. Blocking: callers use `spawn_blocking`.
pub(super) fn run_tool(tool: Tool, args: &[String], stdin: Option<&str>) -> Ran {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut command = Command::new(tool.path());
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ran::Missing,
        Err(err) => {
            return Ran::Exited {
                success: false,
                stdout: String::new(),
                stderr: format!("could not run {}: {err}", tool.path()),
            };
        }
    };
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A write error shows up as the tool's own failure below.
        let _ = pipe.write_all(text.as_bytes());
    }
    match child.wait_with_output() {
        Ok(output) => Ran::Exited {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(err) => Ran::Exited {
            success: false,
            stdout: String::new(),
            stderr: format!("could not run {}: {err}", tool.path()),
        },
    }
}

fn owned(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| word.to_string()).collect()
}

/// A name that is safe in a `pf` rule, an anchor path and a table name.
fn safe_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_alphanumeric())
}

/// The anchor holding every rule of one interface.
fn anchor_name(interface: &str) -> Result<String, String> {
    if safe_name(interface) {
        Ok(format!("com.apple/tsunagi-exit-{interface}"))
    } else {
        Err(format!(
            "`{interface}` is not an interface name this agent can write a pf rule for"
        ))
    }
}

/// The default route as `route -n get default` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

/// Reads `interface:` and `gateway:` out of `route -n get default`.
fn parse_default_route(text: &str) -> Option<DefaultRoute> {
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
    };
    let interface = field("interface").filter(|name| safe_name(name))?;
    let gateway = field("gateway").and_then(|value| value.parse().ok());
    Some(DefaultRoute { interface, gateway })
}

fn failure(stderr: &str, stdout: &str) -> String {
    let text = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if text.is_empty() {
        "the command failed without saying why".to_string()
    } else {
        text.to_string()
    }
}

/// Runs a tool and turns a failure into a sentence a person can act on.
fn run_ok(
    run: Run<'_>,
    tool: Tool,
    args: &[String],
    stdin: Option<&str>,
) -> Result<String, String> {
    match run(tool, args, stdin) {
        Ran::Missing => Err(format!("{} not found", tool.path())),
        Ran::Exited {
            success: true,
            stdout,
            ..
        } => Ok(stdout),
        Ran::Exited { stderr, stdout, .. } => Err(format!(
            "{} {} failed: {}",
            tool.path(),
            args.join(" "),
            failure(&stderr, &stdout)
        )),
    }
}

/// The route traffic leaves by now, which is the egress for translation and
/// for the agent's own sockets. Read *before* the overlay routes are added.
fn default_route(run: Run<'_>, overlay: &str) -> Result<DefaultRoute, String> {
    let out = run_ok(run, Tool::Route, &owned(&["-n", "get", "default"]), None)
        .map_err(|why| format!("cannot find the default route: {why}"))?;
    let route = parse_default_route(&out)
        .ok_or_else(|| "the host has no default route to send traffic out of".to_string())?;
    if route.interface == overlay {
        return Err(format!(
            "the default route already goes through `{overlay}`"
        ));
    }
    Ok(route)
}

/// Whether the kernel forwards IPv4. Read only.
fn forwarding_state(run: Run<'_>) -> Option<bool> {
    let out = run_ok(
        run,
        Tool::Sysctl,
        &owned(&["-n", "net.inet.ip.forwarding"]),
        None,
    )
    .ok()?;
    match out.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// The effective user id of this process, from `id -u`.
fn agent_uid(run: Run<'_>) -> Result<u32, String> {
    run_ok(run, Tool::Id, &owned(&["-u"]), None)
        .ok()
        .and_then(|out| out.trim().parse().ok())
        .ok_or_else(|| "cannot tell which user this agent runs as".to_string())
}

/// What the using side adds to the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientRules<'a> {
    uid: u32,
    /// Every overlay range: the agent's own traffic *to* those still goes
    /// through the interface.
    overlay: &'a [Ipv4Range],
}

/// The text of the anchor: translation first, filtering after, which is the
/// order `pf` insists on.
fn pf_rules(
    interface: &str,
    egress: &DefaultRoute,
    offer: &[Ipv4Range],
    client: Option<&ClientRules<'_>>,
) -> String {
    let out = &egress.interface;
    let mut nat = Vec::new();
    let mut filter = Vec::new();
    for range in offer {
        nat.push(format!("nat on {out} inet from {range} to any -> ({out})"));
        filter.push(format!(
            "pass in quick on {interface} inet from {range} to ! {range}"
        ));
    }
    let mut tables = Vec::new();
    if let Some(client) = client {
        nat.push(format!(
            "nat on {out} inet from ({interface}) to any -> ({out})"
        ));
        let target = if client.overlay.is_empty() {
            "any".to_string()
        } else {
            let ranges: Vec<String> = client.overlay.iter().map(|r| r.to_string()).collect();
            // A table, because `! { a, b }` expands to one rule per element
            // in older `pf`, which matches everything.
            tables.push(format!(
                "table <tsunagi_overlay_{interface}> const {{ {} }}",
                ranges.join(", ")
            ));
            format!("! <tsunagi_overlay_{interface}>")
        };
        let via = match egress.gateway {
            Some(gateway) => format!("({out} {gateway})"),
            None => out.clone(),
        };
        filter.push(format!(
            "pass out quick on {interface} route-to {via} inet proto {{ tcp udp }} \
             from any to {target} user {}",
            client.uid
        ));
    }
    tables
        .into_iter()
        .chain(nat)
        .chain(filter)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Turns `pf` on if nobody has, holding the reference `pfctl` hands out so it
/// can be released when the agent is done. One reference at most.
fn acquire_pf(run: Run<'_>, slot: &Mutex<Option<String>>) -> Result<(), String> {
    if lock(slot).is_some() {
        return Ok(());
    }
    match run(Tool::Pfctl, &owned(&["-E"]), None) {
        Ran::Missing => Err(format!("{} not found", Tool::Pfctl.path())),
        Ran::Exited {
            success,
            stdout,
            stderr,
        } => {
            // `pfctl -E` reports `Token : <n>` on stderr, and also says so
            // when pf is already enabled.
            let token = stdout.lines().chain(stderr.lines()).find_map(parse_token);
            if !success && token.is_none() {
                return Err(format!("cannot enable pf: {}", failure(&stderr, &stdout)));
            }
            *lock(slot) = token;
            Ok(())
        }
    }
}

fn parse_token(line: &str) -> Option<String> {
    let (key, value) = line.split_once(':')?;
    let value = value.trim();
    (key.trim().eq_ignore_ascii_case("token")
        && !value.is_empty()
        && value.chars().all(|c| c.is_ascii_digit()))
    .then(|| value.to_string())
}

fn release_pf(run: Run<'_>, slot: &Mutex<Option<String>>) {
    if let Some(token) = lock(slot).take()
        && let Err(why) = run_ok(run, Tool::Pfctl, &["-X".to_string(), token], None)
    {
        tracing::debug!(%why, "cannot release the pf reference");
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn flush_args(anchor: &str) -> Vec<String> {
    owned(&["-q", "-a", anchor, "-F", "all"])
}

fn load_args(anchor: &str) -> Vec<String> {
    owned(&["-q", "-a", anchor, "-f", "-"])
}

/// The two halves that out-rank the default route.
const HALVES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
/// The IPv6 halves, made unreachable.
const HALVES_V6: [&str; 2] = ["::/1", "8000::/1"];

fn route_add_args(half: &str, interface: &str) -> Vec<String> {
    owned(&["-q", "-n", "add", "-net", half, "-interface", interface])
}

fn route_del_args(half: &str, interface: &str) -> Vec<String> {
    owned(&["-q", "-n", "delete", "-net", half, "-interface", interface])
}

fn route_add_v6_args(half: &str) -> Vec<String> {
    owned(&["-q", "-n", "add", "-inet6", "-net", half, "::1", "-reject"])
}

fn route_del_v6_args(half: &str) -> Vec<String> {
    owned(&["-q", "-n", "delete", "-inet6", "-net", half, "::1"])
}

/// Takes away the overlay default routes. Best effort: what is not there is
/// the state wanted.
fn clear_routes(run: Run<'_>, interface: &str) {
    for half in HALVES {
        let _ = run(Tool::Route, &route_del_args(half, interface), None);
    }
    for half in HALVES_V6 {
        let _ = run(Tool::Route, &route_del_v6_args(half), None);
    }
}

fn set_routes(run: Run<'_>, interface: &str) -> Result<(), String> {
    clear_routes(run, interface);
    for half in HALVES {
        if let Err(why) = run_ok(run, Tool::Route, &route_add_args(half, interface), None) {
            clear_routes(run, interface);
            return Err(why);
        }
    }
    for half in HALVES_V6 {
        // A host without IPv6 has nothing to block; not a failure.
        if let Err(why) = run_ok(run, Tool::Route, &route_add_v6_args(half), None) {
            tracing::debug!(%why, "cannot block IPv6 for the exit node");
        }
    }
    Ok(())
}

/// Makes the host match the plan.
pub(super) fn apply_plan(
    run: Run<'_>,
    token: &Mutex<Option<String>>,
    plan: &ExitHostPlan,
) -> ExitHostReport {
    let forwarding = if plan.offer.is_empty() {
        None
    } else {
        forwarding_state(run)
    };
    let outcome = apply_rules(run, token, plan);
    let verdict = |ok: bool, why: &str| {
        if ok {
            RuleOutcome::Applied
        } else {
            RuleOutcome::Failed(why.to_string())
        }
    };
    match outcome {
        Ok(()) => ExitHostReport {
            offer: plan
                .offer
                .iter()
                .map(|range| (*range, RuleOutcome::Applied))
                .collect(),
            forwarding,
            client: plan.client.then_some(RuleOutcome::Applied),
        },
        Err(why) => ExitHostReport {
            offer: plan
                .offer
                .iter()
                .map(|range| (*range, verdict(false, &why)))
                .collect(),
            forwarding,
            client: plan.client.then(|| verdict(false, &why)),
        },
    }
}

fn apply_rules(
    run: Run<'_>,
    token: &Mutex<Option<String>>,
    plan: &ExitHostPlan,
) -> Result<(), String> {
    let interface = plan.interface.as_str();
    let anchor = anchor_name(interface)?;
    let egress = default_route(run, interface)?;
    let uid = if plan.client {
        Some(agent_uid(run)?)
    } else {
        None
    };
    let client = uid.map(|uid| ClientRules {
        uid,
        overlay: &plan.overlay,
    });
    let rules = pf_rules(interface, &egress, &plan.offer, client.as_ref());

    acquire_pf(run, token)?;
    run_ok(run, Tool::Pfctl, &load_args(&anchor), Some(&rules))
        .map_err(|why| format!("cannot load the pf rules: {why}"))?;
    // The routes come after the rules that keep the agent's own traffic off
    // them: the other order would loop for as long as it takes.
    if plan.client {
        set_routes(run, interface)?;
    } else {
        clear_routes(run, interface);
    }
    Ok(())
}

/// Removes everything this agent put there for the interface.
pub(super) fn clear_all(run: Run<'_>, token: &Mutex<Option<String>>, interface: &str) {
    clear_routes(run, interface);
    if let Ok(anchor) = anchor_name(interface) {
        // Flushing an anchor nothing was ever loaded into is not an error
        // worth reporting.
        if let Err(why) = run_ok(run, Tool::Pfctl, &flush_args(&anchor), None) {
            tracing::debug!(%why, "cannot flush the exit node pf anchor");
        }
    }
    release_pf(run, token);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;

    use super::*;

    fn range() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    const DEFAULT_ROUTE: &str = "   route to: default\n\
destination: default\n\
       mask: default\n\
    gateway: 192.168.1.1\n\
  interface: en0\n\
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";

    fn egress() -> DefaultRoute {
        DefaultRoute {
            interface: "en0".into(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    /// A scripted host that records every call.
    struct Fake {
        calls: RefCell<Vec<String>>,
        stdins: RefCell<Vec<String>>,
        default_route: Option<String>,
        forwarding: &'static str,
        pf_missing: bool,
        pf_load_fails: bool,
        route_add_fails: bool,
        pf_enable_output: &'static str,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                stdins: RefCell::new(Vec::new()),
                default_route: Some(DEFAULT_ROUTE.to_string()),
                forwarding: "1\n",
                pf_missing: false,
                pf_load_fails: false,
                route_add_fails: false,
                pf_enable_output: "pf enabled\nToken : 4242\n",
            }
        }

        fn run(&self, tool: Tool, args: &[String], stdin: Option<&str>) -> Ran {
            let line = format!("{:?} {}", tool, args.join(" "));
            self.calls.borrow_mut().push(line);
            if let Some(text) = stdin {
                self.stdins.borrow_mut().push(text.to_string());
            }
            let ok = |stdout: &str, stderr: &str| Ran::Exited {
                success: true,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            };
            let fail = |why: &str| Ran::Exited {
                success: false,
                stdout: String::new(),
                stderr: why.to_string(),
            };
            match tool {
                Tool::Id => ok("0\n", ""),
                Tool::Sysctl => ok(self.forwarding, ""),
                Tool::Route if args.first().map(String::as_str) == Some("-n") => {
                    match &self.default_route {
                        Some(text) => ok(text, ""),
                        None => fail("route: writing to routing socket: not in table"),
                    }
                }
                Tool::Route if args.contains(&"add".to_string()) && self.route_add_fails => {
                    fail("route: writing to routing socket: File exists")
                }
                Tool::Route => ok("", ""),
                Tool::Pfctl if self.pf_missing => Ran::Missing,
                Tool::Pfctl if args == ["-E"] => ok("", self.pf_enable_output),
                Tool::Pfctl if args.contains(&"-f".to_string()) && self.pf_load_fails => {
                    fail("pfctl: Syntax error")
                }
                Tool::Pfctl => ok("", ""),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn position(&self, needle: &str) -> Option<usize> {
            self.calls.borrow().iter().position(|c| c.contains(needle))
        }

        fn count(&self, needle: &str) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|c| c.contains(needle))
                .count()
        }
    }

    fn plan(offer: bool, client: bool) -> ExitHostPlan {
        ExitHostPlan {
            interface: "utun5".into(),
            offer: if offer { vec![range()] } else { Vec::new() },
            client,
            overlay: vec![range()],
            ..Default::default()
        }
    }

    #[test]
    fn the_default_route_is_read_from_route_output() {
        assert_eq!(parse_default_route(DEFAULT_ROUTE), Some(egress()));
        // A point-to-point default has no gateway line to use.
        let ppp = "destination: default\n  interface: ppp0\n";
        assert_eq!(
            parse_default_route(ppp),
            Some(DefaultRoute {
                interface: "ppp0".into(),
                gateway: None
            })
        );
        assert_eq!(parse_default_route("route: not in table"), None);
        // An interface name that is not plain letters and digits never ends
        // up in a rule.
        assert_eq!(parse_default_route("interface: en0; pass all\n"), None);
    }

    #[test]
    fn the_anchor_is_under_com_apple_and_only_for_plain_names() {
        assert_eq!(
            anchor_name("utun5").unwrap(),
            "com.apple/tsunagi-exit-utun5"
        );
        assert!(anchor_name("").is_err());
        assert!(anchor_name("utun5 pass all").is_err());
        assert!(anchor_name("../x").is_err());
    }

    #[test]
    fn offering_translates_the_range_and_admits_it_in() {
        let text = pf_rules("utun5", &egress(), &[range()], None);
        assert_eq!(
            text,
            "nat on en0 inet from 10.13.37.0/24 to any -> (en0)\n\
             pass in quick on utun5 inet from 10.13.37.0/24 to ! 10.13.37.0/24\n"
        );
        // Translation precedes filtering, as pf requires.
        assert!(text.find("nat on").unwrap() < text.find("pass in").unwrap());
    }

    #[test]
    fn using_sends_the_agents_own_traffic_back_out_the_physical_interface() {
        let other: Ipv4Range = "10.99.0.0/16".parse().unwrap();
        let overlay = [range(), other];
        let client = ClientRules {
            uid: 0,
            overlay: &overlay,
        };
        let text = pf_rules("utun5", &egress(), &[], Some(&client));
        assert!(
            text.starts_with(
                "table <tsunagi_overlay_utun5> const { 10.13.37.0/24, 10.99.0.0/16 }\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("nat on en0 inet from (utun5) to any -> (en0)\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "pass out quick on utun5 route-to (en0 192.168.1.1) inet proto { tcp udp } \
                 from any to ! <tsunagi_overlay_utun5> user 0\n"
            ),
            "{text}"
        );
        // Only the agent's user, and only what is not the overlay.
        assert!(!text.contains("from any to any"));

        let direct = DefaultRoute {
            interface: "ppp0".into(),
            gateway: None,
        };
        let text = pf_rules(
            "utun5",
            &direct,
            &[],
            Some(&ClientRules {
                uid: 501,
                overlay: &[],
            }),
        );
        assert!(text.contains("route-to ppp0 inet"), "{text}");
        assert!(text.contains("to any user 501"), "{text}");
        assert!(!text.contains("table"), "{text}");
    }

    #[test]
    fn the_overlay_default_routes_are_halves_and_ipv6_is_rejected() {
        assert_eq!(
            route_add_args("0.0.0.0/1", "utun5").join(" "),
            "-q -n add -net 0.0.0.0/1 -interface utun5"
        );
        assert_eq!(
            route_del_args("128.0.0.0/1", "utun5").join(" "),
            "-q -n delete -net 128.0.0.0/1 -interface utun5"
        );
        assert_eq!(
            route_add_v6_args("8000::/1").join(" "),
            "-q -n add -inet6 -net 8000::/1 ::1 -reject"
        );
        assert_eq!(
            route_del_v6_args("::/1").join(" "),
            "-q -n delete -inet6 -net ::/1 ::1"
        );
    }

    #[test]
    fn the_pf_token_is_found_in_either_stream() {
        assert_eq!(parse_token("Token : 1234"), Some("1234".into()));
        assert_eq!(parse_token("token: 9"), Some("9".into()));
        assert_eq!(parse_token("pf enabled"), None);
        assert_eq!(parse_token("Token : x; rm"), None);
    }

    #[test]
    fn offering_loads_the_anchor_and_reads_but_never_writes_forwarding() {
        let fake = Fake::new();
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        assert_eq!(report.offer, vec![(range(), RuleOutcome::Applied)]);
        assert_eq!(report.forwarding, Some(true));
        assert_eq!(report.client, None);
        let calls = fake.calls();
        assert!(
            calls
                .iter()
                .any(|c| c == "Pfctl -q -a com.apple/tsunagi-exit-utun5 -f -"),
            "{calls:?}"
        );
        assert_eq!(
            fake.stdins.borrow()[0],
            "nat on en0 inet from 10.13.37.0/24 to any -> (en0)\n\
             pass in quick on utun5 inet from 10.13.37.0/24 to ! 10.13.37.0/24\n"
        );
        // sysctl is only ever asked, never told.
        assert!(
            calls
                .iter()
                .filter(|c| c.starts_with("Sysctl"))
                .all(|c| c == "Sysctl -n net.inet.ip.forwarding"),
            "{calls:?}"
        );
        // No client routes were added for an offer alone.
        assert_eq!(fake.count(" add "), 0);
        assert_eq!(token.lock().unwrap().as_deref(), Some("4242"));
    }

    #[test]
    fn forwarding_off_is_reported_and_unreadable_is_none() {
        let mut fake = Fake::new();
        fake.forwarding = "0\n";
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        assert_eq!(report.forwarding, Some(false));
        fake.forwarding = "junk";
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        assert_eq!(report.forwarding, None);
    }

    #[test]
    fn the_client_rules_are_loaded_before_the_routes_that_need_them() {
        let fake = Fake::new();
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(false, true));
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        assert!(report.offer.is_empty());
        let load = fake.position("-f -").unwrap();
        let add = fake.position(" add -net 0.0.0.0/1").unwrap();
        assert!(load < add, "{:?}", fake.calls());
        assert!(fake.position("add -net 128.0.0.0/1").is_some());
        assert!(fake.position("-inet6 -net ::/1 ::1 -reject").is_some());
        assert!(fake.stdins.borrow()[0].contains("user 0"));
        // The default route was read before any overlay route existed.
        assert!(fake.position("-n get default").unwrap() < add);
    }

    #[test]
    fn no_routes_are_added_when_the_rules_did_not_load() {
        let mut fake = Fake::new();
        fake.pf_load_fails = true;
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, true));
        let Some(RuleOutcome::Failed(why)) = report.client else {
            panic!("{report:?}");
        };
        assert!(why.contains("cannot load the pf rules"), "{why}");
        assert!(why.contains("Syntax error"), "{why}");
        assert!(matches!(report.offer[0].1, RuleOutcome::Failed(_)));
        // Nothing sent the host's traffic into a tunnel it could not exempt
        // the agent from.
        assert_eq!(fake.count(" add "), 0);
    }

    #[test]
    fn a_failing_route_is_a_failure_and_leaves_nothing_behind() {
        let mut fake = Fake::new();
        fake.route_add_fails = true;
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(false, true));
        let Some(RuleOutcome::Failed(why)) = report.client else {
            panic!("{report:?}");
        };
        assert!(why.contains("File exists"), "{why}");
        // The cleanup after the failed add removed whatever did land.
        let last_add = fake
            .calls()
            .iter()
            .rposition(|c| c.contains(" add "))
            .unwrap();
        assert!(
            fake.calls()[last_add..]
                .iter()
                .any(|c| c.contains("delete"))
        );
    }

    #[test]
    fn a_missing_pfctl_or_default_route_says_what_is_wrong() {
        let mut fake = Fake::new();
        fake.pf_missing = true;
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("/sbin/pfctl not found"), "{why}");

        let mut fake = Fake::new();
        fake.default_route = None;
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("default route"), "{why}");
        assert_eq!(fake.count("-f -"), 0);
    }

    #[test]
    fn a_default_route_through_the_overlay_is_refused() {
        let mut fake = Fake::new();
        fake.default_route = Some("gateway: 10.13.37.1\ninterface: utun5\n".into());
        let token = Mutex::new(None);
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("already goes through"), "{why}");
    }

    #[test]
    fn pf_is_enabled_once_and_released_once_on_clear() {
        let fake = Fake::new();
        let token = Mutex::new(None);
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        apply_plan(&run, &token, &plan(true, false));
        apply_plan(&run, &token, &plan(true, true));
        assert_eq!(fake.count("Pfctl -E"), 1, "{:?}", fake.calls());

        clear_all(&run, &token, "utun5");
        assert_eq!(fake.count("Pfctl -X 4242"), 1);
        assert!(
            fake.position("-a com.apple/tsunagi-exit-utun5 -F all")
                .is_some()
        );
        assert!(
            fake.position("delete -net 0.0.0.0/1 -interface utun5")
                .is_some()
        );
        assert_eq!(*token.lock().unwrap(), None);
        // A second clear has nothing to release and still succeeds.
        clear_all(&run, &token, "utun5");
        assert_eq!(fake.count("Pfctl -X"), 1);
    }

    #[test]
    fn dropping_the_client_removes_its_routes() {
        let fake = Fake::new();
        let token = Mutex::new(None);
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        apply_plan(&run, &token, &plan(true, false));
        assert!(fake.position("delete -net 0.0.0.0/1").is_some());
        assert_eq!(fake.count(" add "), 0);
    }
}

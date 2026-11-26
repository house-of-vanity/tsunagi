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
//! nat on <egress> inet from <range> to any tagged <forwarded> -> (<egress>)
//! pass in quick on <if> inet from <range> to ! <range> tag <forwarded> no state
//! pass out quick on <if> route-to (<egress> <gateway>) inet from <range> to ! <range> tagged <forwarded> no state
//! pass out quick on <egress> inet from any to any flags any tagged <forwarded> keep state (if-bound)
//! ```
//!
//! The anchor lives under `com.apple/` on purpose: the stock `/etc/pf.conf`
//! evaluates `nat-anchor "com.apple/*"` and `anchor "com.apple/*"`, so the
//! rules take effect without editing the user's ruleset. `pf` cannot say
//! "every interface but one" in a translation address, so the egress is the
//! interface of the physical default route. Both roles follow egress changes.
//!
//! A local offer enables IPv4 forwarding after its rules are loaded. This
//! host-wide switch has no ownership token, so cleanup only releases our PF
//! reference and removes our own rules.
//!
//! # Using
//!
//! macOS has no `uidrange` policy routing, and the agent is root, so the
//! Linux scheme does not carry over. Instead:
//!
//! ```text
//! route add -net 0.0.0.0/1   <gateway> -ifscope <egress>
//! route add -net 128.0.0.0/1 <gateway> -ifscope <egress>
//! route add -net 0.0.0.0/1   -interface <if> -ifa <selected overlay address>
//! route add -net 128.0.0.0/1 -interface <if> -ifa <selected overlay address>
//! pass out quick on <if> route-to (<egress> <gateway>) inet proto { tcp udp }
//!     from any to ! <overlay ranges> user <agent uid> tag <underlay> no state
//! nat on <egress> inet from (<if>) to any tagged <underlay> -> (<egress>) static-port
//! pass out quick on <egress> reply-to (lo0 127.0.0.1) inet proto { tcp udp }
//!     from any to any flags any tagged <underlay> keep state (if-bound)
//! ```
//!
//! The scoped routes preserve the physical path for sockets that already
//! use its source address. The unscoped halves capture ordinary internet
//! traffic. More specific routes (LAN and active meshes) keep working. The `route-to` rule
//! sends the *agent's own* traffic — QUIC, relay, DHT, which would otherwise
//! loop into the tunnel it carries — back out the physical interface, and the
//! translation gives it that interface's address, since an unbound socket
//! picked the overlay address when the route pointed at the overlay. The
//! first pass is stateless: a floating `route-to` state would match again
//! on physical egress before PF could apply the translation. Only the egress
//! pass tracks the connection and reverses NAT on replies there. Once NAT
//! restores the socket's utun address, macOS's default hybrid end-system
//! model would discard the reply arriving over the physical interface.
//! `reply-to` delivers that state's replies locally through loopback. Like
//! the Linux exemption this is by user id, so anything else running as root
//! also bypasses the tunnel.
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

#[cfg(all(test, unix))]
#[path = "macos_exit_helper_tests.rs"]
mod helper_tests;
#[cfg(all(test, target_os = "macos", feature = "tun-device"))]
#[path = "macos_exit_kernel.rs"]
mod kernel;
#[path = "macos_scoped.rs"]
mod scoped;
use scoped::ScopedRoutes;

use super::macos_authorization::NEEDS_AUTHORIZATION;
#[cfg(test)]
use super::macos_authorization::{macos_exit_authorization_uid, macos_exit_needs_authorization};

const OFFER_HELPER: &str = "/private/etc/tsunagi-exit/offer-v1";

fn offer_helper_available(path: &std::path::Path, action: &str) -> bool {
    // A previous release can still remove its own PF anchors. Applying its
    // obsolete rules would silently restore the broken return path.
    if action == "clear" {
        return path.is_file();
    }
    std::fs::read(path).is_ok_and(|bytes| bytes == include_bytes!("macos/exit-offer.sh").as_slice())
}

/// The programs this module runs, always by absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tool {
    Route,
    Pfctl,
    Sysctl,
    Id,
    OfferHelper,
}

impl Tool {
    fn path(self) -> &'static str {
        match self {
            Self::Route => "/sbin/route",
            Self::Pfctl => "/sbin/pfctl",
            Self::Sysctl => "/usr/sbin/sysctl",
            Self::Id => "/usr/bin/id",
            Self::OfferHelper => OFFER_HELPER,
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

    let mut command = if tool == Tool::OfferHelper {
        let path = std::path::Path::new(OFFER_HELPER);
        if !args
            .first()
            .is_some_and(|op| offer_helper_available(path, op))
        {
            return Ran::Missing;
        }
        let mut sudo = Command::new("/usr/bin/sudo");
        sudo.args(["-n", "--", OFFER_HELPER])
            .arg(std::process::id().to_string());
        sudo
    } else {
        Command::new(tool.path())
    };
    command
        .env("LC_ALL", "C")
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Debug, Default)]
pub(super) struct HostState {
    token: Mutex<Option<String>>,
    routes: Mutex<ScopedRoutes>,
    helper_offers: Mutex<Vec<Ipv4Range>>,
}

impl HostState {
    pub(super) fn with_state_dir(dir: &std::path::Path) -> Self {
        Self {
            routes: Mutex::new(ScopedRoutes::with_journal(dir.join("macos-exit-routes"))),
            ..Self::default()
        }
    }
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
            stderr,
        } if tool != Tool::Route || stderr.is_empty() => Ok(stdout),
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

/// Physical default interface shared with the socket-based exit forwarder.
#[cfg(target_os = "macos")]
pub(in crate::overlay) fn macos_default_uplink() -> Result<String, String> {
    default_route(&run_tool, "").map(|route| route.interface)
}

/// Whether the kernel forwards IPv4.
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

fn enable_forwarding(run: Run<'_>) -> Result<(), String> {
    match forwarding_state(run) {
        Some(true) => return Ok(()),
        Some(false) => {}
        None => return Err("cannot determine whether macOS forwards IPv4".into()),
    }
    run_ok(
        run,
        Tool::Sysctl,
        &owned(&["-w", "net.inet.ip.forwarding=1"]),
        None,
    )?;
    if forwarding_state(run) == Some(true) {
        Ok(())
    } else {
        Err("macOS did not enable IPv4 forwarding".into())
    }
}

fn permission_denied(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("permission denied") || reason.contains("operation not permitted")
}

fn authorized_offer(
    run: Run<'_>,
    action: &str,
    interface: &str,
    range: Ipv4Range,
) -> Result<(), String> {
    let args = owned(&[action, interface, &range.to_string()]);
    match run(Tool::OfferHelper, &args, None) {
        Ran::Exited { success: true, .. } => Ok(()),
        Ran::Exited { stdout, stderr, .. }
            if !stderr.contains("sudo:") && !stderr.contains(NEEDS_AUTHORIZATION) =>
        {
            Err(failure(&stderr, &stdout))
        }
        _ => Err(NEEDS_AUTHORIZATION.into()),
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
    let mut tables = Vec::new();
    let via = match egress.gateway {
        Some(gateway) => format!("({out} {gateway})"),
        None => out.clone(),
    };
    if let Some(client) = client {
        let tag = format!("tsng_underlay_{interface}");
        nat.push(format!(
            "nat on {out} inet from ({interface}) to any tagged {tag} -> ({out}) static-port"
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
        filter.push(format!(
            "pass out quick on {interface} route-to {via} inet proto {{ tcp udp }} \
             from any to {target} user {} tag {tag} no state",
            client.uid
        ));
        // A relay TCP stream may already be established when exit routing changes.
        // Only responses to tagged underlay traffic get local loopback delivery.
        filter.push(format!(
            "pass out quick on {out} reply-to (lo0 127.0.0.1) inet proto {{ tcp udp }} \
             from any to any flags any tagged {tag} keep state (if-bound)"
        ));
    }
    if let [first, rest @ ..] = offer {
        let members = if rest.is_empty() {
            first.to_string()
        } else {
            let name = format!("<tsunagi_offer_{interface}>");
            let ranges: Vec<_> = offer.iter().map(ToString::to_string).collect();
            tables.push(format!("table {name} const {{ {} }}", ranges.join(", ")));
            name
        };
        let tag = format!("tsng_forward_{interface}");
        nat.push(format!(
            "nat on {out} inet from {members} to any tagged {tag} -> ({out})"
        ));
        // Classify at authenticated overlay ingress. Only packets the host
        // actually forwards AND its routes send back to our utun need steering.
        // Local services, connected LANs and the owner's forwarding switch
        // retain their native kernel behavior.
        filter.push(format!(
            "pass in quick on {interface} inet from {members} to ! {members} tag {tag} no state"
        ));
        // PF restores the state's tag on replies after undoing NAT. A reply
        // routed back to a member must leave on the overlay with that tag.
        filter.insert(0, format!(
            "pass out quick on {interface} route-to {via} inet from {members} to ! {members} tagged {tag} no state"
        ));
        // Keep the outbound NAT state on the physical interface. A floating
        // state could consume packets on the utun before the reroute rule runs.
        filter.push(format!(
            "pass out quick on {out} inet from any to any flags any tagged {tag} keep state (if-bound)"
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

fn load_args(anchor: &str) -> Vec<String> {
    owned(&["-q", "-a", anchor, "-f", "-"])
}

/// The two halves that out-rank the default route.
const HALVES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
/// The IPv6 halves, made unreachable.
const HALVES_V6: [&str; 2] = ["::/1", "8000::/1"];

/// A scoped route is available to sockets already using this egress. It
/// coexists with the unscoped route for ordinary applications.
fn scoped_args(action: &str, prefix: &str, egress: &DefaultRoute) -> Vec<String> {
    let mut args = owned(&["-q", "-n", action, "-net", prefix]);
    if let Some(gateway) = egress.gateway {
        args.push(gateway.to_string());
    } else {
        args.extend(owned(&["-interface", &egress.interface]));
    }
    args.extend(owned(&["-ifscope", &egress.interface]));
    if action != "delete" {
        args.push("-proto2".into());
    }
    args
}

fn route_set_args(
    action: &str,
    half: &str,
    interface: &str,
    source: Option<Ipv4Addr>,
) -> Vec<String> {
    let mut args = owned(&["-q", "-n", action, "-net", half, "-interface", interface]);
    if let Some(source) = source {
        args.extend(["-ifa".into(), source.to_string()]);
    }
    args
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

fn captures_half(run: Run<'_>, half: &str, interface: &str) -> bool {
    run_ok(run, Tool::Route, &owned(&["-n", "get", "-net", half]), None).is_ok_and(|text| {
        scoped::field(&text, "mask") == Some("128.0.0.0")
            && scoped::field(&text, "interface") == Some(interface)
            && !scoped::flag(&text, "IFSCOPE")
    })
}

/// Takes away the overlay default routes. Best effort: what is not there is
/// the state wanted.
fn clear_routes(run: Run<'_>, interface: &str) {
    for half in HALVES {
        if captures_half(run, half, interface) {
            let _ = run(Tool::Route, &route_del_args(half, interface), None);
        }
    }
}

fn ipv6_reject(run: Run<'_>, half: &str) -> Result<Option<String>, String> {
    let args = owned(&["-n", "get", "-inet6", "-net", half]);
    match run_ok(run, Tool::Route, &args, None) {
        Ok(text)
            if scoped::flag(&text, "REJECT") && scoped::field(&text, "gateway") == Some("::1") =>
        {
            Ok(Some(text))
        }
        Ok(_) => Ok(None),
        Err(why)
            if why.contains("not in table")
                || why.contains("No such process")
                || why.contains("Address family not supported") =>
        {
            Ok(None)
        }
        Err(why) => Err(why),
    }
}

fn clear_v6(run: Run<'_>, scoped: &mut ScopedRoutes) -> Result<(), String> {
    let Some(marker) = scoped.ipv6_marker() else {
        return Ok(());
    };
    for half in HALVES_V6 {
        if ipv6_reject(run, half)?.is_some_and(|text| {
            scoped::flag(&text, "PROTO2") && scoped::marker(&text) == Some(marker)
        }) {
            run_ok(run, Tool::Route, &route_del_v6_args(half), None)?;
        }
    }
    scoped.record_ipv6(false).map(|_| ())
}

/// Installs a split default, or changes its source in place when the route
/// already belongs to this utun. Returns whether this call added it.
fn set_half(
    run: Run<'_>,
    half: &str,
    interface: &str,
    source: Option<Ipv4Addr>,
) -> Result<bool, String> {
    match run_ok(
        run,
        Tool::Route,
        &route_set_args("add", half, interface, source),
        None,
    ) {
        Ok(_) if captures_half(run, half, interface) => Ok(true),
        Ok(_) => Err(format!(
            "the unscoped route for {half} does not use {interface}"
        )),
        Err(why) if why.contains("File exists") => {
            if !captures_half(run, half, interface) {
                return Err(why);
            }
            run_ok(
                run,
                Tool::Route,
                &route_set_args("change", half, interface, source),
                None,
            )?;
            Ok(false)
        }
        Err(why) => Err(why),
    }
}

fn set_routes(
    run: Run<'_>,
    interface: &str,
    source: Option<Ipv4Addr>,
    scoped: &mut ScopedRoutes,
) -> Result<(), String> {
    let already_using_v6 = scoped.ipv6_marker().is_some();
    let marker = scoped.record_ipv6(true)?;
    let mut added = Vec::new();
    for half in HALVES {
        match set_half(run, half, interface, source) {
            Ok(true) => added.push(half),
            Ok(false) => {}
            Err(why) => {
                for half in added {
                    let _ = run(Tool::Route, &route_del_args(half, interface), None);
                }
                if !already_using_v6 {
                    scoped.record_ipv6(false)?;
                }
                return Err(why);
            }
        }
    }
    for half in HALVES_V6 {
        let mut args = route_add_v6_args(half);
        args.extend(["-proto2".into(), "-hopcount".into(), marker.to_string()]);
        if let Err(why) = run_ok(run, Tool::Route, &args, None) {
            if why.contains("Address family not supported")
                || (why.contains("File exists")
                    && ipv6_reject(run, half).is_ok_and(|route| route.is_some()))
            {
                continue;
            }
            for half in added {
                let _ = run(Tool::Route, &route_del_args(half, interface), None);
            }
            if !already_using_v6 {
                clear_v6(run, scoped)?;
            }
            return Err(why);
        }
    }
    Ok(())
}

/// Makes the host match the plan.
pub(super) fn apply_plan(run: Run<'_>, state: &HostState, plan: &ExitHostPlan) -> ExitHostReport {
    let native = apply_rules(run, state, plan, None);
    let client = plan.client.then(|| verdict(native.clone()));
    let offer = native.clone().and_then(|()| {
        if plan.offer.is_empty() {
            Ok(())
        } else {
            enable_forwarding(run)
        }
    });
    // Permission errors can be fixed by a previously approved local helper.
    // Configuration and tool errors retain their original diagnostics.
    let helper_uid =
        if !plan.offer.is_empty() && offer.as_ref().is_err_and(|why| permission_denied(why)) {
            agent_uid(run).ok().filter(|uid| *uid != 0)
        } else {
            None
        };
    let action = if native.is_ok() { "forward" } else { "apply" };
    let mut active = lock(&state.helper_offers);
    let mut wanted = Vec::new();
    let mut outcomes = Vec::new();
    for &range in &plan.offer {
        let outcome = if let Some(uid) = helper_uid {
            let outcome = authorized_offer(run, action, &plan.interface, range).map_err(|why| {
                if why == NEEDS_AUTHORIZATION {
                    format!("{NEEDS_AUTHORIZATION} for UID {uid}")
                } else {
                    why
                }
            });
            if action == "apply" && outcome.is_ok() {
                wanted.push(range);
            }
            outcome
        } else {
            offer.clone()
        };
        outcomes.push((range, verdict(outcome)));
    }
    for range in std::mem::take(&mut *active) {
        if !wanted.contains(&range)
            && let Err(why) = authorized_offer(run, "clear", &plan.interface, range)
        {
            tracing::warn!(%range, %why, "could not clear the authorized exit rules");
            wanted.push(range);
        }
    }
    *active = wanted;
    if !active.is_empty() && !plan.client {
        lock(&state.routes).active = default_route(run, &plan.interface).ok();
    }
    let forwarding = if plan.offer.is_empty() {
        None
    } else {
        forwarding_state(run)
    };
    if forwarding != Some(true) {
        for (_, outcome) in &mut outcomes {
            if outcome.is_applied() {
                *outcome = RuleOutcome::Failed("macOS could not confirm IPv4 forwarding".into());
            }
        }
    }
    ExitHostReport {
        offer: outcomes,
        forwarding,
        client,
    }
}

fn verdict(result: Result<(), String>) -> RuleOutcome {
    match result {
        Ok(()) => RuleOutcome::Applied,
        Err(why) => RuleOutcome::Failed(why),
    }
}

fn apply_rules(
    run: Run<'_>,
    state: &HostState,
    plan: &ExitHostPlan,
    checked_egress: Option<DefaultRoute>,
) -> Result<(), String> {
    let interface = plan.interface.as_str();
    let anchor = anchor_name(interface)?;
    let egress = match checked_egress {
        Some(egress) => egress,
        None => default_route(run, interface)?,
    };
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

    let mut scoped = lock(&state.routes);
    scoped.load()?;
    acquire_pf(run, &state.token)?;
    run_ok(run, Tool::Pfctl, &load_args(&anchor), Some(&rules))
        .map_err(|why| format!("cannot load the pf rules: {why}"))?;
    // The routes come after the rules that keep the agent's own traffic off
    // them: the other order would loop for as long as it takes.
    if plan.client {
        let previous = scoped.previous();
        let wanted = ScopedRoutes::desired(&egress);
        let result = scoped
            .ensure(run, &wanted)
            .and_then(|()| set_routes(run, interface, plan.client_source, &mut scoped));
        if let Err(reason) = result {
            // A same-interface gateway change may already have updated one
            // scoped route. Restore the former gateway before dropping new adds.
            if let Err(cleanup) = scoped
                .ensure(run, &previous)
                .and_then(|()| scoped.retain(run, &previous))
            {
                return Err(format!(
                    "{reason}; restoring prior scoped routes failed: {cleanup}"
                ));
            }
            return Err(reason);
        }
        scoped.retain(run, &wanted)?;
    } else {
        clear_routes(run, interface);
        clear_v6(run, &mut scoped)?;
        scoped.retain(run, &[])?;
    }
    scoped.active = Some(egress);
    Ok(())
}

/// Removes everything this agent put there for the interface.
pub(super) fn clear_all(run: Run<'_>, state: &HostState, interface: &str) {
    if safe_name(interface) {
        let _ = run(Tool::OfferHelper, &owned(&["clear", interface]), None);
        lock(&state.helper_offers).clear();
    }
    let mut scoped = lock(&state.routes);
    clear_routes(run, interface);
    if let Err(why) = scoped
        .load()
        .and_then(|()| clear_v6(run, &mut scoped))
        .and_then(|()| scoped.retain(run, &[]))
    {
        tracing::warn!(%why, "cannot remove scoped exit routes");
    }
    scoped.active = None;
    if let Ok(anchor) = anchor_name(interface) {
        // Flushing an anchor nothing was ever loaded into is not an error
        // worth reporting.
        if let Err(why) = run_ok(run, Tool::Pfctl, &load_args(&anchor), Some("")) {
            tracing::debug!(%why, "cannot flush the exit node pf anchor");
        }
    }
    release_pf(run, &state.token);
}

/// An offer's NAT follows the host's physical default even without a local exit client.
pub(super) fn refresh_offer(
    run: Run<'_>,
    state: &HostState,
    plan: &ExitHostPlan,
) -> Option<ExitHostReport> {
    let mut routes = lock(&state.routes);
    if plan.client || plan.offer.is_empty() || !routes.check_due(std::time::Instant::now()) {
        return None;
    }
    if let Ok(egress) = default_route(run, &plan.interface)
        && Some(&egress) == routes.active.as_ref()
        && forwarding_state(run) == Some(true)
    {
        return None;
    }
    drop(routes);
    Some(apply_plan(run, state, plan))
}

/// The logical plan can be unchanged while Wi-Fi changes gateway or moves
/// to Ethernet. Rebuild both PF and physical scope against that new egress.
pub(super) fn refresh_client(
    run: Run<'_>,
    state: &HostState,
    plan: &ExitHostPlan,
) -> Option<RuleOutcome> {
    if !plan.client || !lock(&state.routes).check_due(std::time::Instant::now()) {
        return None;
    }
    let egress = match default_route(run, &plan.interface) {
        Ok(egress) => egress,
        Err(reason) => return Some(RuleOutcome::Failed(reason)),
    };
    {
        let mut routes = lock(&state.routes);
        if routes.active.as_ref() == Some(&egress) {
            // A physical link may reconnect with the same name and gateway
            // after the kernel has discarded that interface's scoped routes.
            if let Err(reason) = routes.ensure(run, &ScopedRoutes::desired(&egress)) {
                return Some(RuleOutcome::Failed(reason));
            }
            if HALVES
                .iter()
                .all(|half| captures_half(run, half, &plan.interface))
            {
                return None;
            }
        }
    }
    Some(match apply_rules(run, state, plan, Some(egress)) {
        Ok(()) => RuleOutcome::Applied,
        Err(reason) => RuleOutcome::Failed(reason),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::{Cell, RefCell};

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
        forwarding: Cell<&'static str>,
        deny_forwarding: bool,
        deny_pf: bool,
        helper: bool,
        pf_missing: bool,
        pf_load_fails: bool,
        route_add_fails: bool,
        half_interface: Option<&'static str>,
        v6: RefCell<std::collections::BTreeMap<String, u32>>,
        capture: RefCell<std::collections::BTreeMap<String, String>>,
        scoped: RefCell<std::collections::BTreeMap<(String, String), String>>,
        pf_enable_output: &'static str,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                stdins: RefCell::new(Vec::new()),
                default_route: Some(DEFAULT_ROUTE.to_string()),
                forwarding: Cell::new("1\n"),
                deny_forwarding: false,
                deny_pf: false,
                helper: false,
                pf_missing: false,
                pf_load_fails: false,
                route_add_fails: false,
                half_interface: None,
                v6: RefCell::default(),
                capture: RefCell::default(),
                scoped: RefCell::default(),
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
                Tool::Id if self.deny_forwarding || self.deny_pf => ok("501\n", ""),
                Tool::Id => ok("0\n", ""),
                Tool::Sysctl if args == ["-w", "net.inet.ip.forwarding=1"] => {
                    if self.deny_forwarding {
                        return fail("Operation not permitted");
                    }
                    self.forwarding.set("1\n");
                    ok("net.inet.ip.forwarding: 0 -> 1", "")
                }
                Tool::Sysctl => ok(self.forwarding.get(), ""),
                Tool::OfferHelper if self.helper => {
                    self.forwarding.set("1\n");
                    ok("", "")
                }
                Tool::OfferHelper => fail("sudo: a password is required"),
                Tool::Route if args.iter().any(|a| a == "-inet6") => {
                    let half = args[args.iter().position(|a| a == "-net").unwrap() + 1].clone();
                    let mut table = self.v6.borrow_mut();
                    if args.iter().any(|a| a == "get") {
                        return table.get(&half).map_or_else(|| fail("not in table"),|marker|
                            ok(&format!("gateway: ::1\nflags: <UP,REJECT,PROTO2>\nhopcount mtu\n{marker} 16384\n"),""));
                    }
                    if args.iter().any(|a| a == "delete") {
                        table.remove(&half);
                    } else if let std::collections::btree_map::Entry::Vacant(entry) =
                        table.entry(half)
                    {
                        entry.insert(args.last().unwrap().parse().unwrap());
                    } else {
                        return fail("File exists");
                    }
                    ok("", "")
                }
                Tool::Route if args.iter().any(|a| a == "-ifscope") => {
                    let after = |name: &str| {
                        args.iter()
                            .position(|a| a == name)
                            .map(|i| args[i + 1].clone())
                    };
                    let scope = after("-ifscope").unwrap();
                    let prefix = after("-net").unwrap();
                    let key = (scope.clone(), prefix.clone());
                    let mut table = self.scoped.borrow_mut();
                    if args.iter().any(|a| a == "get") {
                        return table
                            .get(&key)
                            .map_or_else(|| fail("not in table"), |text| ok(text, ""));
                    }
                    if args.iter().any(|a| a == "delete") {
                        table.remove(&key);
                    } else {
                        let gateway = args
                            .iter()
                            .find(|a| a.parse::<Ipv4Addr>().is_ok())
                            .cloned()
                            .unwrap_or_default();
                        let marker = after("-hopcount").unwrap();
                        table.insert(key, format!("destination: {}\nmask: 128.0.0.0\ninterface: {scope}\ngateway: {gateway}\nflags: <UP,PROTO2,IFSCOPE>\nhopcount mtu\n{marker} 1500\n", prefix.split('/').next().unwrap()));
                    }
                    ok("", "")
                }
                Tool::Route
                    if args.iter().any(|arg| arg == "get")
                        && args.iter().any(|arg| arg == "-net") =>
                {
                    let half = args.last().unwrap();
                    match self
                        .capture
                        .borrow()
                        .get(half)
                        .map(String::as_str)
                        .or(self.half_interface)
                    {
                        Some(name) => ok(&format!("mask: 128.0.0.0\ninterface: {name}\n"), ""),
                        None => fail("not in table"),
                    }
                }
                Tool::Route if args.first().map(String::as_str) == Some("-n") => {
                    match &self.default_route {
                        Some(text) => ok(text, ""),
                        None => fail("route: writing to routing socket: not in table"),
                    }
                }
                Tool::Route
                    if args.contains(&"add".to_string())
                        && ((self.route_add_fails && args.iter().any(|a| a == HALVES[1]))
                            || args.iter().any(|a| self.capture.borrow().contains_key(a))
                            || (self.half_interface.is_some()
                                && HALVES.iter().any(|half| args.iter().any(|a| a == half)))) =>
                {
                    // Darwin route can return success after a routing-socket write failed.
                    ok("", "route: writing to routing socket: File exists")
                }
                Tool::Route if args.iter().any(|a| a == "-interface") => {
                    let half = args
                        .iter()
                        .position(|a| a == "-net")
                        .map(|i| args[i + 1].clone())
                        .unwrap();
                    let iface = args
                        .iter()
                        .position(|a| a == "-interface")
                        .map(|i| args[i + 1].clone())
                        .unwrap();
                    if args.iter().any(|a| a == "delete") {
                        self.capture.borrow_mut().remove(&half);
                    } else {
                        self.capture.borrow_mut().insert(half, iface);
                    }
                    ok("", "")
                }
                Tool::Route => ok("", ""),
                Tool::Pfctl if self.pf_missing => Ran::Missing,
                Tool::Pfctl if self.deny_pf => fail("pfctl: /dev/pf: Permission denied"),
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
            "nat on en0 inet from 10.13.37.0/24 to any tagged tsng_forward_utun5 -> (en0)\n\
             pass out quick on utun5 route-to (en0 192.168.1.1) inet from 10.13.37.0/24 to ! 10.13.37.0/24 tagged tsng_forward_utun5 no state\n\
             pass in quick on utun5 inet from 10.13.37.0/24 to ! 10.13.37.0/24 tag tsng_forward_utun5 no state\n\
             pass out quick on en0 inet from any to any flags any tagged tsng_forward_utun5 keep state (if-bound)\n"
        );
        // Translation precedes filtering, as pf requires.
        assert!(text.find("nat on").unwrap() < text.find("pass in").unwrap());
    }

    #[test]
    fn forwarding_excludes_replies_to_every_offered_mesh() {
        let ranges = [range(), "10.99.0.0/16".parse().unwrap()];
        let client = ClientRules {
            uid: 0,
            overlay: &ranges,
        };
        for local_exit in [None, Some(&client)] {
            let text = pf_rules("utun5", &egress(), &ranges, local_exit);
            let offered = "<tsunagi_offer_utun5>";
            assert!(text.contains(&format!(
                "table {offered} const {{ 10.13.37.0/24, 10.99.0.0/16 }}"
            )));
            let mut steering = text
                .lines()
                .filter(|r| r.contains("route-to") && r.contains("tagged tsng_forward_"));
            assert!(
                steering
                    .next()
                    .unwrap()
                    .contains(&format!("from {offered} to ! {offered} "))
            );
            assert!(steering.next().is_none());
        }
    }

    #[test]
    fn the_agents_tagged_nat_precedes_any_general_masquerade_for_offered_ranges() {
        let ranges = [range()];
        let client = ClientRules {
            uid: 0,
            overlay: &ranges,
        };
        let text = pf_rules("utun5", &egress(), &ranges, Some(&client));
        let mut nat = text.lines().filter(|line| line.starts_with("nat "));
        assert!(
            nat.next()
                .unwrap()
                .ends_with("tagged tsng_underlay_utun5 -> (en0) static-port")
        );
        assert_eq!(
            nat.next(),
            Some("nat on en0 inet from 10.13.37.0/24 to any tagged tsng_forward_utun5 -> (en0)")
        );
    }

    #[test]
    fn using_keeps_the_reroute_and_the_physical_nat_in_separate_pf_passes() {
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
        let rules: Vec<_> = text.lines().skip(1).collect();
        assert_eq!(
            rules,
            [
                "nat on en0 inet from (utun5) to any tagged tsng_underlay_utun5 -> (en0) static-port",
                "pass out quick on utun5 route-to (en0 192.168.1.1) inet proto { tcp udp } \
                 from any to ! <tsunagi_overlay_utun5> user 0 tag tsng_underlay_utun5 no state",
                "pass out quick on en0 reply-to (lo0 127.0.0.1) inet proto { tcp udp } from any to any flags any \
                 tagged tsng_underlay_utun5 keep state (if-bound)",
            ]
        );

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
            scoped_args("add", "128.0.0.0/1", &egress()).join(" "),
            "-q -n add -net 128.0.0.0/1 192.168.1.1 -ifscope en0 -proto2"
        );
        assert_eq!(
            route_set_args("add", "0.0.0.0/1", "utun5", None).join(" "),
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
    fn offering_leaves_preexisting_forwarding_on() {
        let fake = Fake::new();
        let token = HostState::default();
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
            "nat on en0 inet from 10.13.37.0/24 to any tagged tsng_forward_utun5 -> (en0)\n\
             pass out quick on utun5 route-to (en0 192.168.1.1) inet from 10.13.37.0/24 to ! 10.13.37.0/24 tagged tsng_forward_utun5 no state\n\
             pass in quick on utun5 inet from 10.13.37.0/24 to ! 10.13.37.0/24 tag tsng_forward_utun5 no state\n\
             pass out quick on en0 inet from any to any flags any tagged tsng_forward_utun5 keep state (if-bound)\n"
        );
        // Forwarding was already enabled by the owner.
        assert!(
            calls
                .iter()
                .filter(|c| c.starts_with("Sysctl"))
                .all(|c| c == "Sysctl -n net.inet.ip.forwarding"),
            "{calls:?}"
        );
        // No client routes were added for an offer alone.
        assert_eq!(fake.count(" add "), 0);
        assert_eq!(token.token.lock().unwrap().as_deref(), Some("4242"));
    }

    #[test]
    fn a_local_offer_enables_forwarding_after_nat_and_never_disables_other_routers() {
        let fake = Fake::new();
        fake.forwarding.set("0\n");
        let state = HostState::default();
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        apply_plan(&run, &state, &plan(false, true));
        assert_eq!(fake.count("Sysctl"), 0);
        let report = apply_plan(&run, &state, &plan(true, false));
        assert_eq!(report.forwarding, Some(true));
        assert_eq!(report.offer[0].1, RuleOutcome::Applied);
        assert!(fake.position("Pfctl -q -a").unwrap() < fake.position("Sysctl -w").unwrap());
        apply_plan(&run, &state, &plan(true, false));
        clear_all(&run, &state, "utun5");
        assert_eq!(fake.count("Sysctl -w"), 1);
    }

    #[test]
    fn unknown_forwarding_or_an_unwritable_switch_never_advertises_a_working_offer() {
        let mut fake = Fake::new();
        fake.forwarding.set("0\n");
        fake.deny_forwarding = true;
        let token = HostState::default();
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, true));
        assert_eq!(report.forwarding, Some(false));
        assert!(
            matches!(&report.offer[0].1, RuleOutcome::Failed(why) if macos_exit_needs_authorization(why))
        );
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        fake.forwarding.set("junk");
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        assert_eq!(report.forwarding, None);
        assert!(matches!(&report.offer[0].1, RuleOutcome::Failed(_)));
    }

    #[test]
    fn a_denied_native_pf_uses_only_a_previously_authorized_offer_helper() {
        let mut fake = Fake::new();
        fake.deny_pf = true;
        fake.forwarding.set("0\n");
        let state = HostState::default();
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &state, &plan(true, false));
        assert!(
            matches!(&report.offer[0].1, RuleOutcome::Failed(why) if macos_exit_needs_authorization(why))
        );
        assert!(
            matches!(&report.offer[0].1, RuleOutcome::Failed(why) if macos_exit_authorization_uid(why) == Some(501))
        );
        for suffix in ["0", "", "501: denied", "+501", "4294967296"] {
            assert_eq!(
                macos_exit_authorization_uid(&format!("{NEEDS_AUTHORIZATION} for UID {suffix}")),
                None
            );
        }
        assert!(fake.position("Pfctl -E").unwrap() < fake.position("OfferHelper").unwrap());
        fake.helper = true;
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        let report = apply_plan(&run, &state, &plan(true, false));
        assert_eq!(report.offer[0].1, RuleOutcome::Applied);
        assert_eq!(report.forwarding, Some(true));
        clear_all(&run, &state, "utun5");
        assert!(fake.position("OfferHelper clear utun5").is_some());
    }

    #[test]
    fn the_client_rules_are_loaded_before_the_routes_that_need_them() {
        let fake = Fake::new();
        let token = HostState::default();
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(false, true));
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        assert!(report.offer.is_empty());
        let load = fake.position("-f -").unwrap();
        let scoped = fake
            .position(" add -net 128.0.0.0/1 192.168.1.1 -ifscope en0")
            .unwrap();
        let add = fake
            .position(" add -net 0.0.0.0/1 -interface utun5")
            .unwrap();
        assert!(load < scoped && scoped < add);
        assert!(load < add, "{:?}", fake.calls());
        assert!(fake.position("add -net 128.0.0.0/1").is_some());
        assert!(fake.position("-inet6 -net ::/1 ::1 -reject").is_some());
        assert!(fake.stdins.borrow()[0].contains("user 0"));
        // The default route was read before any overlay route existed.
        assert!(fake.position("-n get default").unwrap() < add);
    }

    #[test]
    fn both_exit_halves_use_the_selected_networks_address_on_a_shared_utun() {
        let fake = Fake::new();
        let token = HostState::default();
        let mut selected = plan(false, true);
        selected.overlay.push("10.99.0.0/24".parse().unwrap());
        for (action, source) in [("add", "10.99.0.17"), ("change", "10.13.37.34")] {
            selected.client_source = Some(source.parse().unwrap());
            let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &selected);
            assert_eq!(report.client, Some(RuleOutcome::Applied));
            for half in HALVES {
                assert!(
                    fake.position(&format!(
                        "{action} -net {half} -interface utun5 -ifa {source}"
                    ))
                    .is_some()
                );
            }
        }
    }

    #[test]
    fn changing_the_active_exit_keeps_both_halves_routed_through_its_utun() {
        let mut selected = plan(false, true);
        selected.client_source = Some("10.99.0.17".parse().unwrap());
        let mut fake = Fake::new();
        fake.half_interface = Some("utun5");
        let report = apply_plan(
            &|t, a, s| fake.run(t, a, s),
            &HostState::default(),
            &selected,
        );
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        for half in HALVES {
            assert!(
                fake.position(&format!(
                    "change -net {half} -interface utun5 -ifa 10.99.0.17"
                ))
                .is_some()
            );
        }
        assert_eq!(fake.count(" delete "), 0);

        let mut foreign = Fake::new();
        foreign.half_interface = Some("utun9");
        let report = apply_plan(
            &|t, a, s| foreign.run(t, a, s),
            &HostState::default(),
            &selected,
        );
        assert!(matches!(report.client, Some(RuleOutcome::Failed(_))));
        assert_eq!(foreign.count(" change "), 0);
        assert!(
            foreign.scoped.borrow().is_empty(),
            "new scoped routes were rolled back"
        );
        assert_eq!(foreign.count("delete -net 0.0.0.0/1 -interface utun9"), 0);
    }

    #[test]
    fn restart_cleans_scoped_routes_by_journal_and_kernel_marker_even_on_a_new_utun() {
        let fake = Fake::new();
        let dir = tempfile::tempdir().unwrap();
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        let state = HostState::with_state_dir(dir.path());
        assert_eq!(
            apply_plan(&run, &state, &plan(false, true)).client,
            Some(RuleOutcome::Applied)
        );
        assert_eq!(fake.scoped.borrow().len(), 2);
        // An administrator replaces one of the two routes before we restart.
        for ((_, half), listing) in fake.scoped.borrow_mut().iter_mut() {
            if half == HALVES[0] {
                *listing = listing.replace("PROTO2", "STATIC");
            }
        }
        drop(state);
        clear_all(&run, &HostState::with_state_dir(dir.path()), "utun9");
        assert_eq!(fake.scoped.borrow().len(), 1);
        assert!(
            fake.scoped
                .borrow()
                .contains_key(&("en0".into(), HALVES[0].into()))
        );
        assert!(!dir.path().join("macos-exit-routes").exists());
    }

    #[test]
    fn cleanup_preserves_an_ipv6_reject_installed_by_another_owner() {
        let fake = Fake::new();
        fake.v6.borrow_mut().insert("::/1".into(), 0);
        let dir = tempfile::tempdir().unwrap();
        let state = HostState::with_state_dir(dir.path());
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        assert_eq!(
            apply_plan(&run, &state, &plan(false, true)).client,
            Some(RuleOutcome::Applied)
        );
        assert_eq!(fake.v6.borrow().len(), 2);
        clear_all(&run, &HostState::with_state_dir(dir.path()), "utun9");
        assert_eq!(
            fake.v6.borrow().keys().cloned().collect::<Vec<_>>(),
            ["::/1"]
        );
    }

    #[test]
    fn refreshing_a_changed_gateway_updates_pf_and_replaces_only_our_previous_scope() {
        let mut fake = Fake::new();
        let state = HostState::default();
        let plan = plan(false, true);
        assert_eq!(
            apply_plan(&|t, a, s| fake.run(t, a, s), &state, &plan).client,
            Some(RuleOutcome::Applied)
        );
        fake.default_route = Some(
            DEFAULT_ROUTE
                .replace("en0", "en1")
                .replace("192.168.1.1", "10.0.0.1"),
        );
        assert_eq!(
            refresh_client(&|t, a, s| fake.run(t, a, s), &state, &plan),
            Some(RuleOutcome::Applied)
        );
        assert_eq!(fake.scoped.borrow().len(), 2);
        assert!(
            fake.scoped
                .borrow()
                .keys()
                .all(|(interface, _)| interface == "en1")
        );
        assert!(
            fake.stdins
                .borrow()
                .last()
                .unwrap()
                .contains("route-to (en1 10.0.0.1)")
        );
    }

    #[test]
    fn serving_without_an_upstream_moves_nat_when_the_physical_interface_changes() {
        let mut fake = Fake::new();
        let state = HostState::default();
        let plan = plan(true, false);
        let first = apply_plan(&|t, a, s| fake.run(t, a, s), &state, &plan);
        assert_eq!(first.offer[0].1, RuleOutcome::Applied);
        fake.default_route = Some(DEFAULT_ROUTE.replace("en0", "en7"));
        let moved = refresh_offer(&|t, a, s| fake.run(t, a, s), &state, &plan).unwrap();
        assert_eq!(moved.offer[0].1, RuleOutcome::Applied);
        assert!(fake.stdins.borrow().last().unwrap().contains("nat on en7"));
        assert_eq!(moved.client, None);
        assert_eq!(fake.count(" add "), 0);
    }

    #[test]
    fn no_routes_are_added_when_the_rules_did_not_load() {
        let mut fake = Fake::new();
        fake.pf_load_fails = true;
        fake.forwarding.set("0\n");
        let token = HostState::default();
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
        assert_eq!(fake.count("Sysctl -w"), 0);
        assert_eq!(fake.count("OfferHelper"), 0);
    }

    #[test]
    fn a_failing_route_is_a_failure_and_leaves_nothing_behind() {
        let mut fake = Fake::new();
        fake.route_add_fails = true;
        let token = HostState::default();
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
        let token = HostState::default();
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
        let token = HostState::default();
        let report = apply_plan(&|t, a, s| fake.run(t, a, s), &token, &plan(true, false));
        let RuleOutcome::Failed(why) = &report.offer[0].1 else {
            panic!("{report:?}");
        };
        assert!(why.contains("already goes through"), "{why}");
    }

    #[test]
    fn pf_is_enabled_once_and_released_once_on_clear() {
        let fake = Fake::new();
        let token = HostState::default();
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        apply_plan(&run, &token, &plan(true, false));
        apply_plan(&run, &token, &plan(true, true));
        assert_eq!(fake.count("Pfctl -E"), 1, "{:?}", fake.calls());

        clear_all(&run, &token, "utun5");
        assert_eq!(fake.count("Pfctl -X 4242"), 1);
        assert_eq!(fake.stdins.borrow().last().map(String::as_str), Some(""));
        assert!(
            fake.position("delete -net 0.0.0.0/1 -interface utun5")
                .is_some()
        );
        assert_eq!(*token.token.lock().unwrap(), None);
        // A second clear has nothing to release and still succeeds.
        clear_all(&run, &token, "utun5");
        assert_eq!(fake.count("Pfctl -X"), 1);
    }

    #[test]
    fn dropping_the_client_removes_its_routes() {
        let fake = Fake::new();
        let token = HostState::default();
        let run = |t, a: &[String], s: Option<&str>| fake.run(t, a, s);
        assert_eq!(
            apply_plan(&run, &token, &plan(false, true)).client,
            Some(RuleOutcome::Applied)
        );
        let adds = fake.count(" add ");
        apply_plan(&run, &token, &plan(true, false));
        assert!(fake.position("delete -net 0.0.0.0/1").is_some());
        assert_eq!(fake.count(" add "), adds);
    }
}

//! Local underlay candidates, shared by the UDP carriers.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// Discovers local network interface IPs to announce to peers, excluding loopback, overlay interfaces, and virtual bridges.
pub fn local_ip_candidates() -> Vec<IpAddr> {
    local_ip_candidates_excluding(None)
}

pub(crate) fn local_ip_candidates_excluding(
    excluded_interface: Option<&str>,
) -> Vec<std::net::IpAddr> {
    let mut candidates = Vec::new();
    for iface in netdev::get_interfaces() {
        if excluded_interface.is_some_and(|name| {
            iface.name.eq_ignore_ascii_case(name)
                || iface
                    .friendly_name
                    .as_deref()
                    .is_some_and(|friendly| friendly.eq_ignore_ascii_case(name))
        }) || !is_candidate_interface(&iface)
        {
            continue;
        }
        for ip in &iface.ipv4 {
            let addr = ip.addr();
            if is_candidate_ipv4(addr) {
                let priority = ip_priority(&iface, IpAddr::V4(addr));
                candidates.push((priority, IpAddr::V4(addr)));
            }
        }
    }
    // Sort descending by priority so the most viable physical / WAN / LAN IP is candidate #0
    candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut seen = std::collections::HashSet::new();
    let mut ips = Vec::new();
    for (_, ip) in candidates {
        if seen.insert(ip) {
            ips.push(ip);
        }
    }
    ips
}

pub(crate) fn is_candidate_interface(iface: &netdev::Interface) -> bool {
    if !iface.is_up() || iface.is_loopback() {
        return false;
    }

    let name = iface.name.to_lowercase();
    let friendly = iface
        .friendly_name
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let desc = iface
        .description
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();

    // Skip Tsunagi / Wintun overlay interfaces
    if name.starts_with("tsun")
        || name.contains("tsunagi")
        || name.contains("wintun")
        || friendly.starts_with("tsun")
        || friendly.contains("tsunagi")
        || friendly.contains("wintun")
        || desc.contains("wintun")
        || desc.contains("tsunagi")
    {
        return false;
    }

    // Skip container interfaces and virtual bridges purely internal to container engines
    if name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("cni")
        || name.starts_with("flannel")
        || name.starts_with("cali")
        || name.starts_with("kube")
        || name.starts_with("dummy")
        || name.starts_with("lxc")
        || name.starts_with("podman")
        || friendly.contains("wsl")
    {
        return false;
    }

    true
}

/// Reorders candidate addresses so that candidates on the same local subnet as one of our
/// active network interfaces appear first.
pub fn prioritize_local_subnet(candidates: &mut [SocketAddr]) {
    let local_subnets: Vec<(Ipv4Addr, u8)> = netdev::get_interfaces()
        .into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .flat_map(|iface| {
            iface
                .ipv4
                .into_iter()
                .map(|net| (net.addr(), net.prefix_len()))
        })
        .collect();

    candidates.sort_by_key(|addr| {
        let is_local = match addr.ip() {
            IpAddr::V4(v4) => local_subnets
                .iter()
                .any(|(local_ip, prefix_len)| matches_subnet(*local_ip, *prefix_len, v4)),
            IpAddr::V6(_) => false,
        };
        if is_local { 0 } else { 1 }
    });
}

fn matches_subnet(local_ip: Ipv4Addr, prefix_len: u8, target_ip: Ipv4Addr) -> bool {
    if prefix_len == 0 {
        return false;
    }
    let mask = if prefix_len >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    (u32::from(local_ip) & mask) == (u32::from(target_ip) & mask)
}

pub(crate) fn is_candidate_ipv4(addr: std::net::Ipv4Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() || addr.is_broadcast() {
        return false;
    }
    if addr.is_documentation() {
        return false;
    }
    true
}

pub(crate) fn ip_priority(iface: &netdev::Interface, ip: IpAddr) -> u32 {
    let has_gateway = iface.gateway.is_some();
    let base = if has_gateway { 100 } else { 0 };
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Tailscale: 100.64.0.0/10
            let is_tailscale = octets[0] == 100 && (octets[1] & 0xc0) == 64;
            let is_private = v4.is_private();
            if !is_private && !is_tailscale {
                // Public / globally routable IP
                base + 50
            } else if has_gateway && is_private {
                // Primary LAN IP with gateway (e.g. 192.168.1.117)
                base + 40
            } else if is_tailscale {
                // Tailscale / CGNAT
                base + 30
            } else {
                // Other private / virtual
                base + 10
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_global = (segments[0] & 0xe000) == 0x2000;
            if is_global { base + 45 } else { base + 20 }
        }
    }
}

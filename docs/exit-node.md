# Exit nodes

A member can offer itself as an **exit node** in a network. Other members can
then send their default IPv4 internet traffic through it. Linux, macOS and
Windows can offer or use an exit node. Android can use one.

## Using it

The offering side, per network, off by default:

```sh
tsng network exit-node <network> on      # or off
```

Rules are installed even when the kernel does not forward yet, and `status`
says so. Turning forwarding on is left to you, on purpose:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```

The using side:

```sh
tsng exit-node                  # who offers one
tsng exit-node <name|id>        # choose the device's internet exit
tsng exit-node -n work gateway  # choose gateway in work if the name is ambiguous
tsng exit-node off
```

The tray does the same: a checkbox on the network tile to offer, and an icon on
each device in the devices window that offers one, with a confirmation.
The network card shows the selected peer even when folded. The up arrow counts
IP bytes sent through the exit and the down arrow counts reply bytes delivered
to this device. Traffic addressed to the peer within the mesh is counted only
in the devices window. The exit totals start over on a new selection or restart.

An agent uses **one exit node across all active networks**. Choosing another
replaces the previous selection and survives restart. Internet packets use
the local address in the selected exit's network. Each active mesh keeps
its own subnet route, including routes to the exit peer's overlay address,
other peers and virtual services. An unused address inside an active mesh
subnet is dropped locally. Offering an exit remains a per-network choice.

## How it works

- An offering agent says so in its control-plane `Announce` (`exit_node`), and
  only once its rules are in place. Members see which peers offer one.
- **Server:** `iptables` masquerades the overlay range of that network out of
  any other interface and allows forwarding for it. Rules carry the tag
  `tsunagi-exit:<interface>:<range>` and are removed when the offer ends, the
  network stops, and when the agent exits. Only networks that offer have
  rules, so the others' traffic is not forwarded.
- **Client:** policy routing, with no change to the main table. Table `29811`
  holds `default dev <interface> src <local address in the exit network>` once
  that address is assigned. Rules `5205 fwmark 0x40000000/0x40000000
  lookup main` and `5206 uidrange <agent uid> lookup main` keep the agent's
  sockets and their replies outside the tunnel, before Tailscale's rules.
  `5290 lookup main suppress_prefixlength 0` preserves LAN and other specific
  routes, and `5300 lookup 29811` directs other traffic through the exit.
  The exit table is `29811` (`0x7473`).
- **Linux reverse-path filtering:** only the agent's dedicated UID is marked
  in mangle `OUTPUT`. Its own bit, `0x40000000`, is saved to conntrack and
  restored in `PREROUTING` before the host firewall checks reply routing.
  Other mark bits, including Tailscale's `0xff0000` mask, are preserved. The
  rules are tagged `tsunagi-exit-underlay:<interface>` and never accept packets
  around the host firewall. IPv4 and IPv6 protection is installed before exit
  routes; routes are removed before protection, including rollback on failure.
  Locally owned TCP listeners and bound UDP sockets also protect the first
  incoming packet, before any outgoing packet has created a connection mark.
  Socket addresses and ports
  come from local kernel socket tables and match an actual socket; remote
  announcements never supply these firewall arguments.
  The socket set is refreshed before private pair negotiation is sent and on
  discovery ticks, so fresh AWG ports are included. An unchanged set causes no
  firewall writes; a socket-refresh failure leaves active exit routes in place.
  Linux needs both `iptables` and `ip6tables` when IPv6 is present.
- **Kernel strict `rp_filter`:** if an interface uses strict mode (`1`), the
  kernel must include marks in reverse lookups: set
  `net.ipv4.conf.all.src_valid_mark=1`, or enable it on those interfaces.
  The agent checks this before installing exit routes and reports an actionable
  error if marks would be ignored. It never disables `rp_filter` or changes
  host sysctls. Netfilter strict reverse checks also need their mark-aware
  form, such as `rpfilter --validmark`, which NixOS already uses.
- The router sends ordinary IPv4 unicast outside all active mesh ranges to
  the selected exit. It accepts replies with external source addresses from
  that peer only when they target this device's address in the exit network.
- **IPv6 is blocked while you use one.** There is no IPv6 through an exit node,
  and letting it go the ordinary way would leak it. The same three rules exist
  for IPv6 with an `unreachable default` in the table, so applications get an
  immediate "network unreachable" and fall back to IPv4. LAN, ULA and other
  specific IPv6 routes keep working, and so does the agent's own IPv6. A host
  with no IPv6 has nothing to block and is left alone.

## macOS

macOS has no `iptables` and no per-user policy routing, so the same behaviour
is built from `pf` and `route`. The agent runs as root there.

- **Offering:** a `pf` anchor `com.apple/tsunagi-exit-<interface>` (the stock
  `/etc/pf.conf` already evaluates `com.apple/*`) holds
  `nat on <egress> from <range> to any -> (<egress>)` and a `pass in` rule.
  `pf` is enabled if it was off, and that reference is released when the rules
  go. Forwarding is only read: `sudo sysctl -w net.inet.ip.forwarding=1`, which
  macOS forgets at reboot. The egress is the default route's interface **at the
  time the rules are applied**; after it changes (Wi-Fi to Ethernet) switch the
  offer off and on.
- When **using** an exit, ordinary IPv4 internet connections take the two
  split-default routes through the utun, with the local address of the selected
  network. More specific routes continue to reach their own networks.
- Sockets already using the physical address need matching routes scoped to
  the uplink. Without them, macOS can reject a send before the packet reaches
  PF. For new TCP and UDP sockets, PF sends the agent's traffic out the uplink
  and preserves its source port. Replies to these tagged connections return
  through loopback after reverse NAT so macOS can deliver them to a socket
  whose local address belongs to the utun. This exemption matches the
  daemon's user ID, so it also applies to other processes running as root.
  IPv6 internet traffic is blocked with rejecting `::/1` and `8000::/1` routes.
- To inspect an active exit, run `tsng exit-node` and
  `sudo pfctl -a com.apple/tsunagi-exit-utunN -vvsr`, using the daemon's utun
  number. The physical interface and the utun should both see transport packets.

## Windows

- **Offering:** each offered range gets a WinNAT object
  `tsunagi-exit:<interface>:<range>` (`New-NetNat`), removed with the offer, the
  network and the agent. Forwarding is read for the overlay interface and never
  changed; Windows forwards per interface, so enable it on the ones involved
  (`Get-NetIPInterface | Set-NetIPInterface -Forwarding Enabled`, administrator
  PowerShell). Some Windows versions allow one NAT per host; a second range then
  reports its own failure.
- **Using:** Windows has no per-user routing, so the agent's own traffic is kept
  off the tunnel *by destination*. `0.0.0.0/1` and `128.0.0.0/1` go through the
  overlay interface; a `/32` route with metric 7373 (the marker for "ours")
  through the physical default gateway is added for every address the agent
  talks to directly, including verified connection paths and current relay
  servers. Existing LAN and other more specific routes keep their next hop.
  A newly authenticated connection supplies its direct paths immediately.
  After a disconnect, the agent keeps its last verified paths for up to two
  minutes to allow reconnection. It checks the physical gateway and relay
  DNS every 30 seconds while the exit is active. Recent DNS answers remain
  usable for up to two minutes after rotation or a failed lookup.
  Physical bypass routes exclude every active mesh subnet. Wintun can choose
  any local alias for the default route. For
  TCP, UDP and ICMP echo, the agent uses the exit network's address on the
  tunnel and restores replies to the address the Windows socket used.
  IPv6 is blackholed with `::/1` and `8000::/1` on the overlay interface,
  so applications fall back to IPv4 after a delay rather than at once.
  Everything is in the active store: a reboot clears it.
- Not verified on a live host when this was written. To inspect:
  `Get-NetRoute -PolicyStore ActiveStore | ? { $_.RouteMetric -eq 7373 -or $_.InterfaceAlias -like 'tsun*' }`.

## What it does not do

- **The agent must run as a system service** (its own user). The uid exemption
  would otherwise cover everything you run. A per-user agent refuses to use an
  exit node and says why.
- **If the exit node disappears the rules stay** and traffic is dropped until
  it returns or you run `tsng exit-node off`. This is deliberate: falling
  back to the direct path would leak traffic nobody agreed to send in the
  clear. The agent logs it once, `status` and the tray say so loudly.
- **IPv6-only destinations are unreachable** meanwhile; carrying IPv6 through
  the exit node is not implemented. DNS is untouched.
- Kernel forwarding is only read, never changed.

## Trust

Anyone who knows the network's secret can pick your exit node if you offer
one, and you carry what they send: it leaves from your address and is yours to
answer for. The exit node sees every destination and, for plain traffic, its
contents. Choosing an exit node means trusting its owner completely. Offer one
only in networks whose members you trust, and only from a machine you are
willing to have that traffic come from.

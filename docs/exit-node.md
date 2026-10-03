# Exit nodes

A member can offer itself as an **exit node** in a network. Other members can
then send *all* their internet traffic through it, the way a commercial VPN
or Tailscale's exit nodes work. Linux only for now.

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
tsng exit-node <name|id>        # send everything through it
tsng exit-node off
```

The tray does the same: a checkbox on the network tile to offer, and an icon on
each device in the devices window that offers one, with a confirmation.

One device has one default route, so it uses **one** exit node at a time;
choosing another replaces the first. Offering is per network, so a device can
be an exit node in one network and not in another.

## How it works

- An offering agent says so in its control-plane `Announce` (`exit_node`), and
  only once its rules are in place. Members see which peers offer one.
- **Server:** `iptables` masquerades the overlay range of that network out of
  any other interface and allows forwarding for it. Rules carry the tag
  `tsunagi-exit:<interface>:<range>` and are removed when the offer ends, the
  network stops, and when the agent exits. Only networks that offer have
  rules, so the others' traffic is not forwarded.
- **Client:** policy routing, with no change to the main table. Table `28787`
  holds `default dev <interface>`, and three rules sit after Tailscale's:
  `5280 uidrange <agent uid> lookup main` (the agent's own connections never
  go through the tunnel, which would be a loop), `5290 lookup main
  suppress_prefixlength 0` (LAN and other specific routes keep working) and
  `5300 lookup 28787`.
- Packets for addresses outside every overlay range are sent to the exit node
  by the router; the exit node's replies are accepted from any source. A member
  that is not your exit node cannot do that.
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
- **Using:** `0.0.0.0/1` and `128.0.0.0/1` routes through the overlay interface,
  and a `pf` `route-to` rule that sends the agent's own traffic (matched by its
  user id, root) back out the physical interface, with translation to that
  interface's address. Anything else you run as root also bypasses the tunnel.
  IPv6 is blocked with rejecting `::/1` and `8000::/1` routes.
- Not verified on a live host when this was written: run `tsng exit-node` and
  check `sudo pfctl -a com.apple/tsunagi-exit-utunN -s rules -s nat`.

## Windows

Offering only. Each offered range gets a WinNAT object
`tsunagi-exit:<interface>:<range>` (`New-NetNat`), removed with the offer, the
network and the agent. Forwarding is read for the overlay interface and never
changed; Windows forwards per interface, so enable it on the ones involved
(`Get-NetIPInterface | Set-NetIPInterface -Forwarding Enabled`, administrator
PowerShell). Some Windows versions allow one NAT per host; a second range then
reports its own failure.

Using one is **not available**: Windows has no per-user routing, so the agent's
own traffic cannot be kept out of a default route through the overlay and would
loop. `tsng exit-node <name>` reports that and installs nothing. This was
written without a Windows host to run it on.

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

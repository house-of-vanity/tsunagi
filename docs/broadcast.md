# LAN discovery broadcasts

Broadcast participation is a **local setting of each network**, enabled by
default. Different networks on the same agent can have different settings;
each member advertises whether it accepts broadcasts over its authenticated
control session. It is not a network-wide vote or signed shared configuration.

```sh
tsng join -n games --no-broadcast
tsng join -n games --broadcast
tsng network broadcast games off
tsng network broadcast games on
tsng network broadcast games
```

Joining without either flag preserves the saved choice. The `network broadcast`
command can change a running network immediately or configure it while the
agent is stopped. It accepts the exact network name, full id or a unique id
prefix; ambiguous selectors list candidates without changing anything.
`status` reports the local setting. There is no global `up`
override: starting the agent preserves every network's independent policy.

## Delivery

At local TUN ingress, the IP router recognizes IPv4 UDP addressed to the limited
broadcast `255.255.255.255` or the configured overlay subnet's directed broadcast
(for example `10.13.37.255` for `/24`). These address forms follow
[RFC 1122 section 3.3.6](https://www.rfc-editor.org/rfc/rfc1122#section-3.3.6).
There is no port allowlist: discovery requests and server announcements on
game-specific UDP ports use the same mechanism. IPv4/UDP lengths are checked
before fanout, including handling IP fragments. IPv6 multicast, mDNS, DHCP
bridging, Ethernet/IPX and physical LAN capture are outside this feature.

The local source address selects exactly one broadcast domain. A limited
broadcast is never copied into all networks merely because they share a TUN.
A directed broadcast must belong to that source's network. Unspecified sources
and physical LAN sources have no authorized domain yet. Recipients are live,
authenticated, opted-in members with signed overlay address ownership. The
immutable recipient list is rebuilt with address/policy changes, not per packet.

The origin creates **one encrypted unicast copy per eligible peer** and hands it
to the existing shortest-path router. Each can travel through several transport
links. Transit handles opaque ciphertext with the existing hop limit and does
not create another fanout. The original IP source, destination, TTL, UDP ports,
checksum and payload remain unchanged. Reply packets use ordinary unicast.
There is no broadcast retransmission timer or application-payload deduplication:
games may legitimately repeat the same discovery query. WireGuard replay checks
reject duplicated encrypted packets delivered by the transport.

At the destination, the usual authenticated-source ownership check still runs.
Broadcast admission also checks the receiving network's setting, the sender's
announced participation, the destination domain and UDP framing. Disabling it
takes effect locally even while a remote sender still has an older announcement.
Received broadcasts terminate in the local TUN and never enter the fanout path.
An ordinary decrypted packet must target this host's address in that network;
the TUN is not a transit gateway to another overlay or physical subnet.

Opt-out disables originating and accepting broadcasts on that host/network.
It does not disable opaque unicast transit for other members: intermediate
routers cannot inspect another pair's encrypted IP payload.

## Host behavior and verification

A game's discovery packet only reaches Tsunagi if the operating system sends it
through the Tsunagi interface, and its reply only reaches the game if the host
firewall admits it. While a network has broadcast on, the agent installs
exactly two things for the interface it owns, and removes them when broadcast
is turned off, the network is left or stopped, or the agent exits:

- **Route** `255.255.255.255/32` through the overlay interface, with the
  overlay address as its source (Linux: netlink, `ip route add 255.255.255.255/32
  dev tsun0 src <overlay-ip>`; Windows: `New-NetRoute`, metric 1, active store).
  Limited broadcasts from every program then go to the overlay and not to the
  physical LAN while this is installed; this is the price of the feature.
- **Firewall allowance** for inbound **UDP only**, from the overlay range only,
  on that interface only (Linux: an `iptables -I INPUT` rule tagged
  `tsunagi:<interface>`; Windows: a Defender rule of that name). Replies to a
  broadcast come from another address than the request went to, so a stateful
  firewall never matches them to it. TCP services such as SSH stay unexposed.

Both are tagged, idempotent and reversible, and are never derived from a remote
announcement. A rule left by a crashed run is replaced on the next apply. If
`iptables` is missing (for example a host with only `nft`) or the process is not
privileged, the route is still installed and `status` prints a
`broadcast rules` line saying which half is missing and why. To undo it all,
turn broadcast off for the network: `tsng network broadcast <network> off`.

**One interface, several networks.** The host has one `255.255.255.255` route
per interface, so only one overlay address can be its source. The lowest network
id among broadcast-enabled networks with an address is used; `status` says when
that is not the network being shown. Directed broadcasts (`10.13.37.255`) follow
the ordinary connected route and are not affected.

**What it cannot fix.** A game that binds its socket to a physical address or
device, or sends to the physical subnet's broadcast address, still bypasses the
TUN. The Windows implementation could not be run while it was written; its
scripts are unit-tested only.

The suite tests real agents, authenticated iroh links and WireGuard encryption
with memory TUNs: limited/directed UDP discovery, multihop fanout, single-copy
delivery, opt-out, unicast replies, malformed input, source validation and
network isolation. Host rules are tested through a mock host and a scripted
`iptables`; the default suite changes no OS setting. It does not launch CS 1.6 or
Warcraft III.

## Future exported LANs

`overlay::broadcast` owns domain selection and recipient policy separately from
IP parsing, encryption and encrypted transit. A future LAN adapter should feed
an explicitly authorized ingress domain into this layer, and export routes
through the corresponding source/destination admission policy. It must not
relax address checks globally or reinterpret all `.255` addresses as broadcasts.
Multiple gateways to the same LAN will need origin identifiers and bounded
duplicate suppression at LAN ingress/egress before physical rebroadcast is
enabled. No subnet export or host forwarding configuration is added here.

## Compatibility

Control ALPN is `tsunagi/ctrl/3` because `Announce` now carries participation.
The encrypted transit envelope and data ALPN `tsunagi/data/4` stay unchanged.
Local control protocol 14 rejects commands from mismatched running binaries
with a restart message instead of decoding a different request shape.
Upgrade all members and restart the agent before using the new CLI.

SQLite schema 4 adds `networks.broadcast` with default `1`. Existing network
names, secrets, identity keys and signed records are retained. The old binary
does not understand schema 4; the migration is not a downgrade mechanism.

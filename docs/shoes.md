# Embedded Shoes transports

Both profiles carry the usual length-prefixed, encrypted mesh datagrams over a
direct TCP stream. Each listener has a preferred port, 9443 for `vless-xhttp`
and 9444 for `ss2022`. If a default is occupied, the agent announces an
available port. An explicitly configured port must bind successfully.

The wire implementations adapt the stream-one request format, HTTP/2 stream
flow control, VLESS TCP handshake and Shadowsocks TCP record format from
[Shoes v0.3.8](https://github.com/cfal/shoes/tree/7680938b96a245a21d9e481ad009205b956e4436).
The protocol crates include the upstream MIT license. Both run inside the agent.

For each new TCP handshake the dialler generates an independent 32-byte
identifier, 32 bytes of secret material and a method selector. It sends the offer
to the destination member on the encrypted control connection for that network.
The receiver acknowledges the identifier before data authentication starts.
Only the two peers see the offer. The receiver accepts one successful claim
within 12 seconds. A replacement, a disabled transport or the end of membership
invalidates pending credentials. The TCP ports and device identities are stable
across these attempts. No per-attempt secret enters SQLite or status output.

* **VLESS + XHTTP** uses a single bidirectional HTTP/2 POST with the XHTTP
  stream-one path and standard Referer padding. The path and VLESS UUIDv4
  change per attempt. TLS 1.3 authenticates the server using the Ed25519 SPKI
  of the expected mesh member. The client uses the peer's IP for the request
  authority, so this profile can run without a domain, public PKI or ingress.
* **Shadowsocks 2022** selects AES-128-GCM or AES-256-GCM independently of the
  key and salt. The TCP request carries a random salt and padding. The receiver
  authenticates the fixed and variable headers, the service selector and the
  time window. The response authenticates the request salt. The first payload
  byte acknowledges the mesh service. Subsequent data uses standard encrypted
  length and payload records. [SIP022](https://shadowsocks.org/doc/sip022.html)

The destination encoded inside either protocol is the mesh service selector
`127.0.0.1:1`. Each endpoint terminates that service in memory and hands the
resulting link to the mesh. The inner WireGuard tunnel authenticates the source
and destination of the overlay traffic.

The elected peer tries advertised TCP listeners first. Candidates can include
verified direct control-path IPs and configured bootstrap IPs paired with the
peer's advertised TCP port. Peers that advertise `link-reverse` v1 can request
one reverse attempt after the forward attempt fails. The first successful
direction carries traffic both ways. If both fail the mesh applies its usual
carrier selection and relay routing. Ports forwarded through a router must
reach the announced TCP listener. Network filtering and NAT determine which
paths can actually be established.

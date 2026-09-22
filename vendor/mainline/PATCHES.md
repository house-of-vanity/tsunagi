# Mainline 8.0.0: Windows receive timeout correction

This directory contains the published `mainline` 8.0.0 sources, manifest and
MIT license. The workspace selects this copy through `[patch.crates-io]`.

- Upstream: https://github.com/pubky/mainline
- Published source commit: `b0cabe684f310004c6dcfe8099b91f0d239b11e3`
- Crates.io archive SHA-256:
  `d32eaee3dcba6e0bbbefe8bd896a8bd6039d5e74b199c0fe248e9feb547c2a26`
- The upstream manifest is retained, including its development dependencies;
  the crate is excluded from the application workspace.

The only source change is in `src/rpc/socket.rs`: `KrpcSocket::recv_from`
treats `ErrorKind::TimedOut` like `WouldBlock`. Its 50 ms socket read timeout
is a normal idle tick, not a failed DHT operation. Windows reports this as
WSAETIMEDOUT (10060), producing approximately 16 warnings per second with
the unmodified crate. Other receive errors still emit the original warning.
Request deadlines, DHT routing, publication and lookup behavior are unchanged.

Rust documents the platform difference here:
https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.set_read_timeout

Regression coverage is part of the regular workspace suite:

```sh
cargo test --locked -p tsunagi --test mainline_socket
```

It drives the actual DHT actor through idle receive ticks on loopback, checks
that no socket warnings were emitted, then exchanges a real KRPC ping. The
existing Mainline Testnet tests also cover publication, lookup and recovery.
No public DHT, privileged interface or changes to host settings are needed.

When upstream releases this correction, upgrade the dependency and remove
this directory, the patch entry and its workspace exclusion. Keep the
regression test. Do not patch Cargo's global registry cache.

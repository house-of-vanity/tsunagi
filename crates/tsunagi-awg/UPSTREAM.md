# Amnezia packet engine

`src/masking.rs` is adapted from `src/core/amnezia.rs` in
https://github.com/RunaRoo/AmneziaWG-RS at
`51579a7d6e8882d1d8d6d00822f09e18a9423b73`, under Apache-2.0.
The upstream license is retained in `LICENSE-AmneziaWG-RS`.

The adaptation replaces configuration-file loading with bounded typed pair
profiles, updates RNG calls to rand 0.10, removes an unnecessary unwrap, and
does not embed upstream's Node, global executors, OS interface operations or
detached tasks. Noise/WireGuard is supplied by boringtun, already used by
Tsunagi. Each pair owns one socket and one cancellable packet-engine task.

This is Tsunagi AWG wire version 1, not a claim of compatibility with external
Amnezia servers. The masking engine substitutes message headers outside the
standard WireGuard state machine and restores them before Noise validation.
There are no remote file paths, shell hooks, or persisted pair profiles.

The adapted masking source remains Apache-2.0. Newly written Tsunagi code
follows the repository's WTFPL. This package declares both licenses in Cargo
metadata; the workspace license alone does not describe its copied source.

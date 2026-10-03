//! Deterministic network space identity.
//!
//! A *network space* is fully determined by a [`NetworkName`] and a
//! [`NetworkSecret`]. Two agents that were given the same pair derive the same
//! [`NetworkId`], [`DiscoveryKey`] and handshake authentication key, with no
//! coordination, no creator, no timestamp and no leader election.
//!
//! # Derivation scheme (`tsunagi-network-id-v1`)
//!
//! All inputs are encoded with an unambiguous length-prefixed encoding, written
//! here as `LP(x) = u32_be(x.len()) || x`. String concatenation is never used.
//!
//! ```text
//! salt = SHA-256( LP("tsunagi-network-id-v1") || LP(name_utf8) )
//! prk  = HKDF-SHA256-Extract(salt, ikm = secret_bytes)
//! info(label)   = LP("tsunagi-network-id-v1") || LP(label)
//! network_id    = HKDF-Expand(prk, info("network-id"),    32)
//! discovery_key = HKDF-Expand(prk, info("discovery-key"), 32)
//! auth_key      = HKDF-Expand(prk, info("handshake-auth"), 32)
//! ```
//!
//! HKDF's `info` parameter is what separates the three derived values
//! (RFC 5869 §3.2). Learning `discovery_key` — which is published to a
//! discovery backend and is therefore semi-public — does not reveal `auth_key`,
//! so the discovery key must never be used as a password or bearer token.
//!
//! The scheme label is versioned and frozen. Upgrading this crate or bumping
//! the control protocol version must not change an existing [`NetworkId`].

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Frozen label identifying the network identity derivation scheme.
///
/// Changing this string creates a different, incompatible network space for the
/// same name and secret. It must never be changed casually.
pub const IDENTITY_SCHEME: &str = "tsunagi-network-id-v1";

/// Maximum length of a network name in UTF-8 bytes.
pub const MAX_NETWORK_NAME_LEN: usize = 64;

/// Minimum length of a network secret in bytes.
///
/// The proof-of-concept targets high-entropy shared secrets. See
/// [`NetworkSecret::generate`].
pub const MIN_NETWORK_SECRET_LEN: usize = 16;

/// Maximum length of a network secret in bytes.
pub const MAX_NETWORK_SECRET_LEN: usize = 1024;

/// Human-readable prefix of the canonical secret text encoding.
pub const SECRET_TEXT_PREFIX: &str = "tsn1";

/// Appends `LP(bytes) = u32_be(len) || bytes` to `out`.
///
/// Panics are impossible here: the caller-provided slices are already bounded by
/// [`MAX_NETWORK_NAME_LEN`] / [`MAX_NETWORK_SECRET_LEN`], and the cast is
/// saturating for anything larger.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The name half of a network space.
///
/// Rules, deliberately strict and never silently applied:
///
/// * 1..=[`MAX_NETWORK_NAME_LEN`] bytes of UTF-8.
/// * No ASCII control characters.
/// * No leading or trailing ASCII whitespace — such a name is **rejected**,
///   not trimmed.
/// * Used verbatim. No case folding and no Unicode normalisation is performed,
///   so `Home` and `home` are different network spaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// Validates and wraps a network name.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::InvalidNetworkName("must not be empty"));
        }
        if name.len() > MAX_NETWORK_NAME_LEN {
            return Err(Error::InvalidNetworkName(
                "must not exceed 64 bytes of UTF-8",
            ));
        }
        if name.chars().any(|c| c.is_control()) {
            return Err(Error::InvalidNetworkName(
                "must not contain control characters",
            ));
        }
        let trimmed = name.trim_matches(|c: char| c.is_ascii_whitespace());
        if trimmed.len() != name.len() {
            return Err(Error::InvalidNetworkName(
                "must not have leading or trailing ASCII whitespace",
            ));
        }
        Ok(Self(name))
    }

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NetworkName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for NetworkName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// The shared secret half of a network space.
///
/// This is the single shared secret the end user configures; "password" and
/// "secret" refer to the same value. The bytes are used **verbatim**: never
/// trimmed, case-folded, normalised or truncated.
///
/// The value is zeroized on drop and redacted from [`Debug`].
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkSecret(Zeroizing<Vec<u8>>);

impl NetworkSecret {
    /// Wraps raw secret bytes.
    ///
    /// Requires at least [`MIN_NETWORK_SECRET_LEN`] bytes. This crate makes no
    /// security promises for short, low-entropy human passphrases: there is no
    /// PAKE here, so an offline guessing attack against a weak secret is cheap
    /// for anyone who can reach the handshake.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.len() < MIN_NETWORK_SECRET_LEN {
            return Err(Error::InvalidNetworkSecret(
                "must be at least 16 bytes; use NetworkSecret::generate()",
            ));
        }
        if bytes.len() > MAX_NETWORK_SECRET_LEN {
            return Err(Error::InvalidNetworkSecret("must not exceed 1024 bytes"));
        }
        Ok(Self(bytes))
    }

    /// Generates a fresh 32-byte random secret.
    ///
    /// This is the recommended way to create a network secret.
    pub fn generate() -> Self {
        let mut buf = vec![0u8; 32];
        rand::fill(&mut buf[..]);
        Self(Zeroizing::new(buf))
    }

    /// Parses the canonical text form produced by [`NetworkSecret::encode`].
    ///
    /// The format is `tsn1` followed by lowercase unpadded RFC 4648 base32.
    /// Parsing is strict: no whitespace, no case mixing in the payload.
    pub fn decode(text: &str) -> Result<Self> {
        let payload = text
            .strip_prefix(SECRET_TEXT_PREFIX)
            .ok_or(Error::InvalidNetworkSecret(
                "canonical secrets start with `tsn1`",
            ))?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(payload.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::InvalidNetworkSecret("not valid base32"))?;
        Self::from_bytes(bytes)
    }

    /// Encodes the secret in its canonical text form.
    ///
    /// The returned string is zeroized on drop. Never log it.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut encoded = data_encoding::BASE32_NOPAD.encode(&self.0);
        encoded.make_ascii_lowercase();
        let out = Zeroizing::new(format!("{SECRET_TEXT_PREFIX}{encoded}"));
        encoded.zeroize();
        out
    }

    /// Exposes the raw secret bytes.
    ///
    /// Callers must not log, serialise or copy these bytes into diagnostics.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for NetworkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkSecret(<redacted>)")
    }
}

/// Encodes 32 bytes as lowercase unpadded base32.
fn b32(bytes: &[u8; 32]) -> String {
    let mut s = data_encoding::BASE32_NOPAD.encode(bytes);
    s.make_ascii_lowercase();
    s
}

/// Decodes lowercase unpadded base32 into 32 bytes.
fn unb32(kind: &'static str, s: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::InvalidEncoding {
            kind,
            reason: "not valid base32",
        })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidEncoding {
        kind,
        reason: "expected 32 bytes",
    })
}

/// Public, non-secret identifier of a network space.
///
/// Safe to log, publish and put into status output. It does not authorise
/// anything on its own: an attacker who knows a `NetworkId` still cannot pass
/// the handshake without the secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    /// Returns the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Builds a network id from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a short prefix useful for logs.
    pub fn fmt_short(&self) -> String {
        b32(&self.0).chars().take(10).collect()
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b32(&self.0))
    }
}

impl std::fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkId({})", self.fmt_short())
    }
}

impl std::str::FromStr for NetworkId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        unb32("network id", s).map(Self)
    }
}

/// Lookup key used to find candidates for a network in a discovery backend.
///
/// Derived from the secret, so it is not published in the clear the way a
/// [`NetworkId`] is. It is nevertheless **not** a credential: a discovery
/// backend, or anyone observing it, learns nothing that helps pass the
/// handshake.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscoveryKey([u8; 32]);

impl DiscoveryKey {
    /// Returns the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Builds a discovery key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for DiscoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b32(&self.0))
    }
}

impl std::fmt::Debug for DiscoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiscoveryKey({}…)",
            b32(&self.0).chars().take(10).collect::<String>()
        )
    }
}

/// The deterministic, immutable description of a network space.
///
/// There is no competing genesis: this value contains no creator identity, no
/// creation time and no owner signature, so two agents started independently
/// with the same parameters produce byte-identical descriptors. The secret is
/// never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDescriptor {
    /// Frozen derivation scheme label, see [`IDENTITY_SCHEME`].
    pub scheme: &'static str,
    /// The network name.
    pub name: NetworkName,
    /// The derived public network identifier.
    pub network_id: NetworkId,
}

impl NetworkDescriptor {
    /// Canonical, unambiguous byte encoding of the descriptor.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_lp(&mut out, self.scheme.as_bytes());
        push_lp(&mut out, self.name.as_str().as_bytes());
        push_lp(&mut out, &self.network_id.0);
        out
    }
}

/// All key material derived from a [`NetworkName`] and [`NetworkSecret`].
///
/// The authentication key is zeroized on drop and never leaves this crate.
#[derive(Clone)]
pub struct NetworkKeys {
    network_id: NetworkId,
    discovery_key: DiscoveryKey,
    auth_key: Zeroizing<[u8; 32]>,
    // Separate from the semi-public DiscoveryKey. Existing derivations stay frozen.
    dht_write_key: Zeroizing<[u8; 32]>,
    name: NetworkName,
}

impl NetworkKeys {
    /// Derives all network key material.
    ///
    /// This is a pure function of `(name, secret)`. It does not depend on the
    /// device key, the hostname, the wall clock or the order in which agents
    /// start.
    pub fn derive(name: &NetworkName, secret: &NetworkSecret) -> Self {
        let mut salt_input = Vec::new();
        push_lp(&mut salt_input, IDENTITY_SCHEME.as_bytes());
        push_lp(&mut salt_input, name.as_str().as_bytes());
        let salt = Sha256::digest(&salt_input);

        let hk = Hkdf::<Sha256>::new(Some(&salt), secret.expose());

        let expand = |label: &str| -> [u8; 32] {
            let mut info = Vec::new();
            push_lp(&mut info, IDENTITY_SCHEME.as_bytes());
            push_lp(&mut info, label.as_bytes());
            let mut okm = [0u8; 32];
            // 32 bytes is far below HKDF-SHA256's 255*32 limit, so this cannot fail.
            match hk.expand(&info, &mut okm) {
                Ok(()) => okm,
                Err(_) => unreachable!("HKDF-SHA256 expand of 32 bytes cannot fail"),
            }
        };

        Self {
            network_id: NetworkId(expand("network-id")),
            discovery_key: DiscoveryKey(expand("discovery-key")),
            auth_key: Zeroizing::new(expand("handshake-auth")),
            dht_write_key: Zeroizing::new(expand("mainline-rendezvous-write-v1")),
            name: name.clone(),
        }
    }

    /// The public network identifier.
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// The discovery lookup key.
    pub fn discovery_key(&self) -> DiscoveryKey {
        self.discovery_key
    }

    /// The network name.
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// The immutable descriptor of this network space.
    pub fn descriptor(&self) -> NetworkDescriptor {
        NetworkDescriptor {
            scheme: IDENTITY_SCHEME,
            name: self.name.clone(),
            network_id: self.network_id,
        }
    }

    /// The handshake authentication key. Crate-internal on purpose.
    pub(crate) fn auth_key(&self) -> &[u8; 32] {
        &self.auth_key
    }

    /// Secret signing material for network rendezvous; never exported or logged.
    pub(crate) fn dht_write_key(&self) -> &[u8; 32] {
        &self.dht_write_key
    }
}

impl std::fmt::Debug for NetworkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkKeys")
            .field("name", &self.name)
            .field("network_id", &self.network_id)
            .field("discovery_key", &self.discovery_key)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

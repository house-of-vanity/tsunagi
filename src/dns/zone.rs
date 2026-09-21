//! What the overlay answers to, as a DNS zone.
//!
//! Nothing here touches a socket or the operating system, and it does not
//! depend on a DNS wire library either: it takes a roster and a question and
//! says what the answer is. That is what makes the interesting parts — which
//! names exist, what "does not exist" means as against "exists with nothing
//! of that type", and what is outside the zone entirely — testable on their
//! own.
//!
//! # Where the names come from
//!
//! From signed state, which is why a member that is switched off still
//! resolves. Its claim outlived the session, so the name and the address are
//! both still there to answer with. Nothing is invented for a member that
//! claimed neither.
//!
//! Only IPv4 is served. The IPv6 overlay address is derived from a
//! WireGuard key that travels in live announcements and is not in signed
//! state, so it cannot be answered for a member that is away — and answering
//! for some members and not others depending on whether they happen to be
//! online is worse than not answering at all.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Longest a DNS name may be, in the presentation form used here.
const MAX_NAME_LEN: usize = 253;
/// Longest one label may be.
const MAX_LABEL_LEN: usize = 63;

/// Why a zone name cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZoneError {
    /// The name was empty, or became empty once normalised.
    #[error("a zone name must have at least one label")]
    Empty,
    /// One label was unusable.
    #[error("`{label}` is not a usable DNS label: {reason}")]
    Label {
        /// The offending label.
        label: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The whole name is too long.
    #[error("a zone name must be at most {MAX_NAME_LEN} characters")]
    TooLong,
}

/// A validated, canonical zone name.
///
/// Held without a trailing dot and lower-cased, so comparison is a plain
/// string comparison rather than a special case at every use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneName(String);

impl ZoneName {
    /// Validates and normalises a zone name.
    pub fn new(raw: &str) -> Result<Self, ZoneError> {
        let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(ZoneError::Empty);
        }
        if trimmed.len() > MAX_NAME_LEN {
            return Err(ZoneError::TooLong);
        }
        for label in trimmed.split('.') {
            let reason = if label.is_empty() {
                Some("it is empty")
            } else if label.len() > MAX_LABEL_LEN {
                Some("it is longer than 63 characters")
            } else if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                Some("only letters, digits, `-` and `_` are allowed")
            } else if label.starts_with('-') || label.ends_with('-') {
                Some("a label may not start or end with `-`")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(ZoneError::Label {
                    label: label.to_string(),
                    reason,
                });
            }
        }
        Ok(Self(trimmed))
    }

    /// The name, without a trailing dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The last label, which is what would collide with a real top-level
    /// domain.
    pub fn top_label(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    /// What is worrying about this zone name, if anything.
    ///
    /// A warning and never a refusal: the name is the user's to choose, and
    /// a private zone that shadows a public one is a decision, not a
    /// mistake. Saying nothing would let it be an accident.
    pub fn collision(&self) -> Option<String> {
        let top = self.top_label();
        // Reserved for exactly this use and never delegated, so nothing to
        // say. See RFC 6761 and RFC 8375.
        const RESERVED: &[&str] = &[
            "internal",
            "home",
            "test",
            "example",
            "invalid",
            "localhost",
        ];
        if RESERVED.contains(&top) {
            return None;
        }
        if top == "local" {
            return Some(
                "`.local` belongs to multicast DNS: on a host running Avahi or \
                 systemd-resolved's mDNS, names under it are resolved by that and \
                 not by this agent"
                    .to_string(),
            );
        }
        if tld::exist_case_insensitive(top) {
            return Some(format!(
                "`.{top}` is a real top-level domain, so every public name under it \
                 becomes unreachable from this host while the overlay is up"
            ));
        }
        // Not delegated today is not a promise about tomorrow.
        (!self.0.contains('.')).then(|| {
            format!(
                "`.{top}` is not a delegated top-level domain today, but it could \
                 become one; `.internal` is reserved for private use and never will"
            )
        })
    }

    /// Whether `name` is this zone or sits under it.
    ///
    /// Compared label-wise, so `evilzone` does not count as being under
    /// `zone`.
    pub fn covers(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name == self.0
            || name
                .strip_suffix(&self.0)
                .is_some_and(|rest| rest.ends_with('.'))
    }

    /// The part of `name` below this zone, if it is under it.
    fn relative(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name == self.0 {
            return Some(String::new());
        }
        let rest = name.strip_suffix(&self.0)?;
        let rest = rest.strip_suffix('.')?;
        (!rest.is_empty()).then(|| rest.to_string())
    }
}

/// The kinds of question this zone knows how to answer.
///
/// Its own enum rather than the wire library's, so the decision of what to
/// answer does not depend on how a packet is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// An IPv4 address.
    A,
    /// A name for an address.
    Ptr,
    /// The zone's start of authority.
    Soa,
    /// The zone's name servers.
    Ns,
    /// Anything else, including AAAA.
    Other,
}

/// What the zone has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Addresses for the name asked about.
    Addresses(Vec<Ipv4Addr>),
    /// A name for the address asked about.
    Name(String),
    /// The zone's start of authority.
    Soa,
    /// The name exists here but has nothing of the type asked for.
    ///
    /// Distinct from [`Answer::NoSuchName`] because the two are different
    /// answers on the wire: this one is a success with no records, and a
    /// resolver must not take it as proof the name is absent. Getting them
    /// the wrong way round teaches a resolver to cache the wrong thing.
    NoData,
    /// No such name in this zone.
    NoSuchName,
    /// Not a name this zone is responsible for.
    NotOurs,
}

/// The names and addresses of one network, ready to answer questions.
#[derive(Debug, Clone)]
pub struct Zone {
    origin: ZoneName,
    /// Name relative to the origin, to the addresses it answers to.
    hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    /// Address to the name that holds it.
    names: BTreeMap<Ipv4Addr, String>,
    /// Changes whenever the contents do.
    serial: u32,
}

impl Zone {
    /// Builds a zone from the members that have both a name and an address.
    ///
    /// A member with one but not the other contributes nothing: a name with
    /// no address cannot be answered, and an address with no name has nothing
    /// to be asked about.
    pub fn new(origin: ZoneName, members: impl IntoIterator<Item = (String, Ipv4Addr)>) -> Self {
        let mut hosts: BTreeMap<String, Vec<Ipv4Addr>> = BTreeMap::new();
        let mut names: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
        for (hostname, address) in members {
            let hostname = hostname.trim_matches('.').to_ascii_lowercase();
            if hostname.is_empty() {
                continue;
            }
            let addresses = hosts.entry(hostname.clone()).or_default();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
            // First name wins, and the map is ordered, so the reverse answer
            // is the same on every replica rather than depending on the order
            // records happened to arrive in.
            names.entry(address).or_insert(hostname);
        }
        for addresses in hosts.values_mut() {
            addresses.sort();
        }

        let serial = content_serial(&hosts);
        Self {
            origin,
            hosts,
            names,
            serial,
        }
    }

    /// The zone's origin.
    pub fn origin(&self) -> &ZoneName {
        &self.origin
    }

    /// A number that changes whenever the contents do.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// How many names it answers for.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether it answers for nothing.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Every name it answers for, with its addresses.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &[Ipv4Addr])> {
        self.hosts
            .iter()
            .map(|(name, addresses)| (name.as_str(), addresses.as_slice()))
    }

    /// The reverse zones this zone is authoritative for.
    ///
    /// Only when the range lands on an octet boundary. Claiming a reverse
    /// zone larger than the range would shadow reverse lookups for addresses
    /// that are nothing to do with us, which is worse than not answering.
    pub fn reverse_origin(base: Ipv4Addr, prefix_len: u8) -> Option<String> {
        let octets = base.octets();
        match prefix_len {
            8 => Some(format!("{}.in-addr.arpa", octets[0])),
            16 => Some(format!("{}.{}.in-addr.arpa", octets[1], octets[0])),
            24 => Some(format!(
                "{}.{}.{}.in-addr.arpa",
                octets[2], octets[1], octets[0]
            )),
            _ => None,
        }
    }

    /// Answers one question.
    pub fn lookup(&self, qname: &str, query: Query) -> Answer {
        if let Some(address) = reverse_address(qname) {
            return match self.names.get(&address) {
                Some(name) if query == Query::Ptr => {
                    Answer::Name(format!("{name}.{}", self.origin.as_str()))
                }
                Some(_) => Answer::NoData,
                None => Answer::NoSuchName,
            };
        }

        let Some(relative) = self.origin.relative(qname) else {
            return Answer::NotOurs;
        };

        // The apex: the zone itself exists whether or not anybody is in it.
        if relative.is_empty() {
            return match query {
                Query::Soa => Answer::Soa,
                Query::Ns => Answer::NoData,
                _ => Answer::NoData,
            };
        }

        match self.hosts.get(&relative) {
            Some(addresses) if query == Query::A => Answer::Addresses(addresses.clone()),
            // The name is here, it just has no AAAA and never will while
            // only IPv4 is served. Saying "no such name" instead would tell
            // a resolver to stop asking for the A record too.
            Some(_) => Answer::NoData,
            None => Answer::NoSuchName,
        }
    }
}

/// The address a reverse name asks about, if it is one.
fn reverse_address(qname: &str) -> Option<Ipv4Addr> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let mut octets = [0u8; 4];
    let mut seen = 0;
    for (index, part) in rest.split('.').enumerate() {
        if index >= 4 {
            return None;
        }
        octets[3 - index] = part.parse().ok()?;
        seen += 1;
    }
    (seen == 4).then(|| Ipv4Addr::from(octets))
}

/// A serial that changes with the contents and not otherwise.
///
/// Derived rather than counted, so two agents holding the same roster agree,
/// and a restart does not go backwards.
fn content_serial(hosts: &BTreeMap<String, Vec<Ipv4Addr>>) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (name, addresses) in hosts {
        name.hash(&mut hasher);
        for address in addresses {
            address.octets().hash(&mut hasher);
        }
    }
    // Never zero: a zero serial is legal but reads like "unset" in a log.
    (hasher.finish() as u32).max(1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn zone() -> Zone {
        Zone::new(
            ZoneName::new("lab").unwrap(),
            [
                ("music".to_string(), Ipv4Addr::new(10, 13, 37, 237)),
                ("ai".to_string(), Ipv4Addr::new(10, 13, 37, 69)),
            ],
        )
    }

    #[test]
    fn a_zone_name_is_normalised_and_checked() {
        assert_eq!(ZoneName::new("LAB.").unwrap().as_str(), "lab");
        assert_eq!(
            ZoneName::new(" lab.internal ").unwrap().as_str(),
            "lab.internal"
        );
        assert_eq!(
            ZoneName::new("lab.internal").unwrap().top_label(),
            "internal"
        );

        assert_eq!(ZoneName::new("").unwrap_err(), ZoneError::Empty);
        assert_eq!(ZoneName::new(".").unwrap_err(), ZoneError::Empty);
        assert!(matches!(
            ZoneName::new("a..b").unwrap_err(),
            ZoneError::Label { .. }
        ));
        assert!(matches!(
            ZoneName::new("-lab").unwrap_err(),
            ZoneError::Label { .. }
        ));
        assert!(matches!(
            ZoneName::new("la b").unwrap_err(),
            ZoneError::Label { .. }
        ));
        assert!(matches!(
            ZoneName::new(&"x".repeat(64)).unwrap_err(),
            ZoneError::Label { .. }
        ));
    }

    #[test]
    fn a_zone_name_that_shadows_a_public_one_is_flagged_but_allowed() {
        // Flagged, never refused: shadowing is the user's decision to make.
        let ru = ZoneName::new("ru").unwrap();
        let warning = ru.collision().expect("a real TLD is worth mentioning");
        assert!(warning.contains("real top-level domain"), "{warning}");

        assert!(ZoneName::new("com").unwrap().collision().is_some());
        assert!(ZoneName::new("lab.com").unwrap().collision().is_some());

        // Reserved for private use, so nothing to say.
        for quiet in ["internal", "lab.internal", "home", "test", "invalid"] {
            assert_eq!(ZoneName::new(quiet).unwrap().collision(), None, "{quiet}");
        }

        // `.local` is not a delegated TLD, but it is not free either.
        let local = ZoneName::new("local").unwrap().collision().unwrap();
        assert!(local.contains("multicast DNS"), "{local}");

        // An undelegated single label is a maybe, not a yes.
        let lab = ZoneName::new("lab").unwrap().collision().unwrap();
        assert!(lab.contains("could"), "{lab}");
        // A multi-label name under something undelegated is not worth a word.
        assert_eq!(ZoneName::new("a.lab").unwrap().collision(), None);
    }

    #[test]
    fn a_neighbouring_name_is_not_inside_the_zone() {
        // `evillab` ends with `lab`, and a suffix comparison that forgot the
        // label boundary would hand it to us.
        let origin = ZoneName::new("lab").unwrap();
        assert!(origin.covers("lab"));
        assert!(origin.covers("music.lab."));
        assert!(origin.covers("a.b.lab"));
        assert!(!origin.covers("evillab"));
        assert!(!origin.covers("lab.example.com"));
        assert!(!origin.covers("example.com"));
    }

    #[test]
    fn a_member_resolves_by_name() {
        let zone = zone();
        assert_eq!(
            zone.lookup("music.lab", Query::A),
            Answer::Addresses(vec![Ipv4Addr::new(10, 13, 37, 237)])
        );
        // Case and a trailing dot are the same question.
        assert_eq!(
            zone.lookup("MUSIC.LAB.", Query::A),
            Answer::Addresses(vec![Ipv4Addr::new(10, 13, 37, 237)])
        );
    }

    #[test]
    fn a_name_with_no_record_of_that_type_is_not_a_missing_name() {
        // AAAA for a member that exists must be NODATA, not NXDOMAIN: an
        // NXDOMAIN would tell the resolver the name is absent and stop it
        // asking for the A record.
        let zone = zone();
        assert_eq!(zone.lookup("music.lab", Query::Other), Answer::NoData);
        assert_eq!(zone.lookup("nobody.lab", Query::A), Answer::NoSuchName);
    }

    #[test]
    fn questions_outside_the_zone_are_refused_rather_than_denied() {
        // Denying them would be a lie: this server knows nothing about them.
        let zone = zone();
        assert_eq!(zone.lookup("example.com", Query::A), Answer::NotOurs);
        assert_eq!(zone.lookup("evillab", Query::A), Answer::NotOurs);
    }

    #[test]
    fn the_apex_exists_even_with_nobody_in_the_network() {
        let empty = Zone::new(ZoneName::new("lab").unwrap(), []);
        assert!(empty.is_empty());
        assert_eq!(empty.lookup("lab", Query::Soa), Answer::Soa);
        assert_eq!(empty.lookup("lab", Query::A), Answer::NoData);
        assert_eq!(empty.lookup("music.lab", Query::A), Answer::NoSuchName);
    }

    #[test]
    fn an_address_resolves_back_to_its_name() {
        let zone = zone();
        assert_eq!(
            zone.lookup("237.37.13.10.in-addr.arpa", Query::Ptr),
            Answer::Name("music.lab".into())
        );
        assert_eq!(
            zone.lookup("9.37.13.10.in-addr.arpa", Query::Ptr),
            Answer::NoSuchName
        );
        // A reverse name asked for the wrong type is still a name we know.
        assert_eq!(
            zone.lookup("237.37.13.10.in-addr.arpa", Query::A),
            Answer::NoData
        );
    }

    #[test]
    fn a_reverse_zone_is_claimed_only_when_it_is_exactly_ours() {
        // Claiming a reverse zone wider than the range would shadow lookups
        // for addresses that have nothing to do with this network.
        assert_eq!(
            Zone::reverse_origin(Ipv4Addr::new(10, 13, 37, 0), 24).as_deref(),
            Some("37.13.10.in-addr.arpa")
        );
        assert_eq!(
            Zone::reverse_origin(Ipv4Addr::new(10, 13, 0, 0), 16).as_deref(),
            Some("13.10.in-addr.arpa")
        );
        assert_eq!(Zone::reverse_origin(Ipv4Addr::new(10, 13, 37, 0), 25), None);
        assert_eq!(Zone::reverse_origin(Ipv4Addr::new(100, 64, 0, 0), 10), None);
    }

    #[test]
    fn members_with_nothing_to_say_are_left_out() {
        let zone = Zone::new(
            ZoneName::new("lab").unwrap(),
            [(String::new(), Ipv4Addr::new(10, 0, 0, 1))],
        );
        assert!(zone.is_empty());
    }

    #[test]
    fn two_members_sharing_a_name_both_answer_and_the_order_is_stable() {
        // The state layer resolves name ownership; if two records still
        // reach here, answering with both beats picking one at random.
        let build = |flip: bool| {
            let members = if flip {
                vec![
                    ("music".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
                    ("music".to_string(), Ipv4Addr::new(10, 0, 0, 1)),
                ]
            } else {
                vec![
                    ("music".to_string(), Ipv4Addr::new(10, 0, 0, 1)),
                    ("music".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
                ]
            };
            Zone::new(ZoneName::new("lab").unwrap(), members)
        };
        assert_eq!(
            build(false).lookup("music.lab", Query::A),
            build(true).lookup("music.lab", Query::A)
        );
        assert_eq!(build(false).serial(), build(true).serial());
    }

    #[test]
    fn the_serial_follows_the_contents() {
        let a = zone();
        let b = zone();
        assert_eq!(a.serial(), b.serial(), "the same roster, the same serial");

        let changed = Zone::new(
            ZoneName::new("lab").unwrap(),
            [("music".to_string(), Ipv4Addr::new(10, 13, 37, 238))],
        );
        assert_ne!(a.serial(), changed.serial());
    }
}

//! Answering DNS questions about the overlay, over UDP and TCP.
//!
//! Authoritative for one zone and nothing else. There is no recursion, no
//! forwarding and no cache: a question this agent cannot answer from the
//! signed roster is refused rather than passed anywhere, so pointing a
//! resolver at this server can never make it a path to the outside.
//!
//! The decision of what to answer lives in [`super::zone`]; this module is
//! only the wire format and the sockets. [`respond`] sits between them and
//! takes bytes to bytes, so everything the server does to a packet is
//! testable without opening a socket.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use simple_dns::rdata::{A, PTR, RData, SOA};
use simple_dns::{Name, PacketFlag, QCLASS, QTYPE, RCODE, ResourceRecord, TYPE};

use super::zone::{Answer, Query, Zone};

/// How long an answer may be cached.
///
/// Short, because the roster changes when members come and go and a stale
/// answer is worse than another question.
pub const TTL: u32 = 30;

/// The largest question this server will read.
///
/// A DNS message is 512 bytes without EDNS and 4096 with it; anything past
/// that is not a question worth answering.
pub const MAX_MESSAGE_LEN: usize = 4096;

/// The largest answer sent over UDP without the client offering EDNS.
const CLASSIC_UDP_LIMIT: usize = 512;

/// How long a TCP client may take over one question.
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How many TCP questions may be in flight at once.
const MAX_TCP_CONNECTIONS: usize = 32;

/// The zone the server answers from, swapped as the roster changes.
///
/// Shared rather than copied into the server so that a roster change is one
/// write, not a restart: rebinding the socket would drop questions in flight
/// for no reason.
#[derive(Debug, Clone)]
pub struct SharedZone(Arc<RwLock<Arc<Zone>>>);

impl SharedZone {
    /// Wraps a zone.
    pub fn new(zone: Zone) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(zone))))
    }

    /// Replaces it.
    pub fn set(&self, zone: Zone) {
        match self.0.write() {
            Ok(mut guard) => *guard = Arc::new(zone),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(zone),
        }
    }

    /// The zone as it is now.
    pub fn get(&self) -> Arc<Zone> {
        match self.0.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

/// Builds the answer to one question.
///
/// `None` means say nothing at all: the message was not a question this
/// server should reply to, and replying anyway would make this a useful
/// amplifier for somebody spoofing a source address.
pub fn respond(zone: &Zone, query: &[u8]) -> Option<Vec<u8>> {
    let packet = simple_dns::Packet::parse(query).ok()?;
    if packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }

    let mut reply = simple_dns::Packet::new_reply(packet.id());
    // Recursion is not available here and the flag says so honestly; the
    // desired bit is echoed because a resolver compares it.
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }

    if packet.opcode() != simple_dns::OPCODE::StandardQuery {
        *reply.rcode_mut() = RCODE::NotImplemented;
        return reply.build_bytes_vec().ok();
    }

    // Exactly one question. Zero is nothing to answer; more than one has no
    // agreed meaning and every real server rejects it.
    let [question] = packet.questions.as_slice() else {
        *reply.rcode_mut() = RCODE::FormatError;
        return reply.build_bytes_vec().ok();
    };
    if !matches!(question.qclass, QCLASS::CLASS(simple_dns::CLASS::IN)) {
        *reply.rcode_mut() = RCODE::Refused;
        return reply.build_bytes_vec().ok();
    }

    let qname = question.qname.to_string();
    let answer = zone.lookup(&qname, query_kind(question.qtype));
    reply.questions.push(question.clone());

    let name = Name::new(&qname).ok()?;
    match answer {
        Answer::NotOurs => *reply.rcode_mut() = RCODE::Refused,
        Answer::Addresses(addresses) => {
            reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            for address in addresses {
                reply.answers.push(ResourceRecord::new(
                    name.clone(),
                    simple_dns::CLASS::IN,
                    TTL,
                    RData::A(A::from(address)),
                ));
            }
        }
        Answer::Name(target) => {
            reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            let target = Name::new(&target).ok()?.into_owned();
            reply.answers.push(ResourceRecord::new(
                name.clone(),
                simple_dns::CLASS::IN,
                TTL,
                RData::PTR(PTR(target)),
            ));
        }
        Answer::Soa => {
            reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            reply.answers.push(soa_record(zone)?);
        }
        Answer::NoData => {
            reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            // The authority section carries the SOA so a resolver knows how
            // long it may remember that there is nothing here.
            reply.name_servers.push(soa_record(zone)?);
        }
        Answer::NoSuchName => {
            reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            *reply.rcode_mut() = RCODE::NameError;
            reply.name_servers.push(soa_record(zone)?);
        }
    }

    reply.build_bytes_vec_compressed().ok()
}

/// The zone's start of authority.
fn soa_record(zone: &Zone) -> Option<ResourceRecord<'static>> {
    let origin = Name::new(zone.origin().as_str()).ok()?.into_owned();
    Some(ResourceRecord::new(
        origin.clone(),
        simple_dns::CLASS::IN,
        TTL,
        RData::SOA(SOA {
            mname: origin.clone(),
            // There is no mailbox behind this zone and inventing one would
            // be a fiction; the origin itself is the honest answer.
            rname: origin,
            serial: zone.serial(),
            refresh: TTL as i32,
            retry: TTL as i32,
            expire: 86_400,
            minimum: TTL,
        }),
    ))
}

fn query_kind(qtype: QTYPE) -> Query {
    match qtype {
        QTYPE::TYPE(TYPE::A) => Query::A,
        QTYPE::TYPE(TYPE::PTR) => Query::Ptr,
        QTYPE::TYPE(TYPE::SOA) => Query::Soa,
        QTYPE::TYPE(TYPE::NS) => Query::Ns,
        // ANY is answered as an address question rather than by dumping the
        // zone: an ANY that returns everything is an amplification gift.
        QTYPE::ANY => Query::A,
        _ => Query::Other,
    }
}

/// Whether the client offered EDNS, and so how large an answer it will take.
fn udp_limit(query: &[u8]) -> usize {
    simple_dns::Packet::parse(query)
        .ok()
        .and_then(|packet| packet.opt().map(|opt| opt.udp_packet_size as usize))
        .unwrap_or(CLASSIC_UDP_LIMIT as u16 as usize)
        .clamp(CLASSIC_UDP_LIMIT, MAX_MESSAGE_LEN)
}

/// Cuts an answer down to what the client said it would take.
///
/// The records are dropped and the truncated bit set, which tells a resolver
/// to ask again over TCP. Sending a reply it cannot reassemble would just
/// look like packet loss.
fn truncate_for_udp(query: &[u8], reply: Vec<u8>) -> Vec<u8> {
    let limit = udp_limit(query);
    if reply.len() <= limit {
        return reply;
    }
    let Ok(parsed) = simple_dns::Packet::parse(&reply) else {
        return reply;
    };
    let mut short = simple_dns::Packet::new_reply(parsed.id());
    short.set_flags(PacketFlag::TRUNCATION | PacketFlag::AUTHORITATIVE_ANSWER);
    *short.rcode_mut() = parsed.rcode();
    for question in &parsed.questions {
        short.questions.push(question.clone());
    }
    short.build_bytes_vec().unwrap_or(reply)
}

/// A running DNS server.
#[derive(Debug)]
pub struct DnsServer {
    local_addr: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl DnsServer {
    /// Binds and starts answering.
    ///
    /// Both transports on the same address and port, as a resolver expects:
    /// it falls back to TCP when an answer does not fit, and a server that
    /// only listened on UDP would leave it with nowhere to go.
    pub async fn bind(addr: SocketAddr, zone: SharedZone) -> std::io::Result<Self> {
        let udp = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = udp.local_addr()?;
        let tcp = tokio::net::TcpListener::bind(local_addr).await?;

        let udp_zone = zone.clone();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_MESSAGE_LEN];
            loop {
                let (read, from) = match udp.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::debug!(%err, "dns udp receive failed");
                        continue;
                    }
                };
                let query = &buffer[..read];
                let Some(reply) = respond(&udp_zone.get(), query) else {
                    continue;
                };
                let reply = truncate_for_udp(query, reply);
                if let Err(err) = udp.send_to(&reply, from).await {
                    tracing::debug!(%err, "dns udp reply failed");
                }
            }
        });

        let tcp_zone = zone.clone();
        let tcp_task = tokio::spawn(async move {
            let permits = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));
            loop {
                let (stream, _) = match tcp.accept().await {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::debug!(%err, "dns tcp accept failed");
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    return;
                };
                let zone = tcp_zone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Bounded, so a client that connects and says nothing
                    // cannot hold a slot open.
                    let _ = tokio::time::timeout(TCP_TIMEOUT, serve_tcp(stream, zone)).await;
                });
            }
        });

        Ok(Self {
            local_addr,
            tasks: vec![udp_task, tcp_task],
        })
    }

    /// The address it is answering on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn serve_tcp(mut stream: tokio::net::TcpStream, zone: SharedZone) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        // Checked before the buffer is allocated, as everywhere else that
        // reads a length off a wire.
        let len = u16::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_MESSAGE_LEN {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;

        let Some(reply) = respond(&zone.get(), &query) else {
            return Ok(());
        };
        let Ok(len) = u16::try_from(reply.len()) else {
            return Ok(());
        };
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::dns::zone::ZoneName;
    use std::net::Ipv4Addr;

    fn zone() -> Zone {
        Zone::new(
            ZoneName::new("lab").unwrap(),
            [
                ("music".to_string(), Ipv4Addr::new(10, 13, 37, 237)),
                ("ai".to_string(), Ipv4Addr::new(10, 13, 37, 69)),
            ],
        )
    }

    fn ask(name: &str, qtype: TYPE) -> Vec<u8> {
        let mut packet = simple_dns::Packet::new_query(0x1234);
        packet.questions.push(simple_dns::Question::new(
            Name::new(name).unwrap(),
            qtype.into(),
            QCLASS::CLASS(simple_dns::CLASS::IN),
            false,
        ));
        packet.build_bytes_vec().unwrap()
    }

    /// The bytes of a reply. Parsed by each caller, because a parsed packet
    /// borrows from them.
    fn answer(query: &[u8]) -> Vec<u8> {
        respond(&zone(), query).expect("a reply")
    }

    #[test]
    fn a_member_is_answered_authoritatively() {
        let bytes = answer(&ask("music.lab", TYPE::A));
        let reply = simple_dns::Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert!(reply.has_flags(PacketFlag::RESPONSE));
        assert!(reply.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        assert!(!reply.has_flags(PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.questions.len(), 1, "the question is echoed");
        match &reply.answers[0].rdata {
            RData::A(a) => assert_eq!(Ipv4Addr::from(a.address), Ipv4Addr::new(10, 13, 37, 237)),
            other => panic!("expected an A record, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_name_is_denied_with_a_soa_to_cache_the_denial() {
        let bytes = answer(&ask("nobody.lab", TYPE::A));
        let reply = simple_dns::Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NameError);
        assert!(reply.answers.is_empty());
        assert_eq!(
            reply.name_servers.len(),
            1,
            "a SOA bounds the negative cache"
        );
    }

    #[test]
    fn a_name_that_exists_without_that_record_is_not_denied() {
        // NODATA, not NXDOMAIN: denying the name would stop a resolver
        // asking for the A record it could have had.
        let bytes = answer(&ask("music.lab", TYPE::AAAA));
        let reply = simple_dns::Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert!(reply.answers.is_empty());
        assert_eq!(reply.name_servers.len(), 1);
    }

    #[test]
    fn anything_outside_the_zone_is_refused_and_never_forwarded() {
        for name in ["example.com", "evillab", "google.com"] {
            let bytes = answer(&ask(name, TYPE::A));
            let reply = simple_dns::Packet::parse(&bytes).unwrap();
            assert_eq!(reply.rcode(), RCODE::Refused, "{name}");
            assert!(reply.answers.is_empty());
        }
    }

    #[test]
    fn an_address_is_answered_backwards() {
        let bytes = answer(&ask("237.37.13.10.in-addr.arpa", TYPE::PTR));
        let reply = simple_dns::Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NoError);
        match &reply.answers[0].rdata {
            RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "music.lab"),
            other => panic!("expected a PTR record, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_is_never_sent_to_something_that_was_not_a_question() {
        // Answering a response would make this a reflector for anyone who
        // can spoof a source address.
        let mut packet = simple_dns::Packet::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        assert!(respond(&zone(), &packet.build_bytes_vec().unwrap()).is_none());
        assert!(respond(&zone(), b"").is_none());
        assert!(respond(&zone(), b"not a dns packet at all").is_none());
    }

    #[test]
    fn a_question_with_no_question_in_it_is_a_format_error() {
        let packet = simple_dns::Packet::new_query(7);
        let bytes = respond(&zone(), &packet.build_bytes_vec().unwrap()).unwrap();
        let reply = simple_dns::Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::FormatError);
    }

    #[test]
    fn a_class_other_than_internet_is_refused() {
        let mut packet = simple_dns::Packet::new_query(9);
        packet.questions.push(simple_dns::Question::new(
            Name::new("music.lab").unwrap(),
            TYPE::A.into(),
            QCLASS::CLASS(simple_dns::CLASS::CH),
            false,
        ));
        let bytes = respond(&zone(), &packet.build_bytes_vec().unwrap()).unwrap();
        assert_eq!(
            simple_dns::Packet::parse(&bytes).unwrap().rcode(),
            RCODE::Refused
        );
    }

    #[test]
    fn an_answer_too_large_for_udp_is_truncated_rather_than_dropped() {
        // A resolver that gets a truncated reply asks again over TCP; one
        // that gets nothing back just waits.
        let many: Vec<(String, Ipv4Addr)> = (0..200)
            .map(|i| ("host".to_string(), Ipv4Addr::new(10, 13, 37, i as u8)))
            .collect();
        let wide = Zone::new(ZoneName::new("lab").unwrap(), many);
        let query = ask("host.lab", TYPE::A);
        let full = respond(&wide, &query).unwrap();
        assert!(
            full.len() > CLASSIC_UDP_LIMIT,
            "the test needs a big answer"
        );

        let short = truncate_for_udp(&query, full);
        assert!(short.len() <= CLASSIC_UDP_LIMIT);
        let parsed = simple_dns::Packet::parse(&short).unwrap();
        assert!(parsed.has_flags(PacketFlag::TRUNCATION));
        assert_eq!(parsed.questions.len(), 1);
    }

    #[tokio::test]
    async fn the_server_answers_over_udp_and_tcp_on_one_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let shared = SharedZone::new(zone());
        let server = DnsServer::bind("127.0.0.1:0".parse().unwrap(), shared.clone())
            .await
            .unwrap();
        let addr = server.local_addr();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&ask("music.lab", TYPE::A), addr)
            .await
            .unwrap();
        let mut buffer = vec![0u8; MAX_MESSAGE_LEN];
        let read = client.recv(&mut buffer).await.unwrap();
        let reply = simple_dns::Packet::parse(&buffer[..read]).unwrap();
        assert_eq!(reply.answers.len(), 1);

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let query = ask("ai.lab", TYPE::A);
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes(header) as usize];
        stream.read_exact(&mut body).await.unwrap();
        let reply = simple_dns::Packet::parse(&body).unwrap();
        assert_eq!(reply.answers.len(), 1);
    }

    #[tokio::test]
    async fn the_same_zone_is_answered_over_ipv6_as_over_ipv4() {
        // A question arrives over whichever family the resolver chooses, so
        // a listener is opened from each list in the plan and both have to
        // answer the same thing. Answering one family only leaves the other
        // timing out, which looks like a broken overlay.
        let shared = SharedZone::new(zone());
        let plan = crate::dns::listen_plan(None, 0);
        let mut answered = 0;

        for family in plan.families() {
            let candidate = family[0];
            let server = match DnsServer::bind(candidate, shared.clone()).await {
                Ok(server) => server,
                // A host with IPv6 switched off in the kernel cannot bind
                // `::1`, and the agent copes with that by design; so does
                // this. The other family still has to work.
                Err(err) if candidate.is_ipv6() => {
                    eprintln!("no IPv6 loopback on this host ({err}); skipping that family");
                    continue;
                }
                Err(err) => panic!("cannot listen on {candidate}: {err}"),
            };
            let addr = server.local_addr();
            assert_eq!(addr.is_ipv6(), candidate.is_ipv6());

            let client = tokio::net::UdpSocket::bind(if addr.is_ipv6() {
                "[::1]:0"
            } else {
                "127.0.0.1:0"
            })
            .await
            .unwrap();
            client
                .send_to(&ask("music.lab", TYPE::A), addr)
                .await
                .unwrap();
            let mut buffer = vec![0u8; MAX_MESSAGE_LEN];
            let read = client.recv(&mut buffer).await.unwrap();
            let reply = simple_dns::Packet::parse(&buffer[..read]).unwrap();
            assert_eq!(reply.rcode(), RCODE::NoError, "over {addr}");
            match &reply.answers[0].rdata {
                // The same IPv4 answer either way: the family a question
                // travelled over says nothing about what the answer is.
                RData::A(a) => {
                    assert_eq!(Ipv4Addr::from(a.address), Ipv4Addr::new(10, 13, 37, 237))
                }
                other => panic!("expected an A record over {addr}, got {other:?}"),
            }
            answered += 1;
        }

        assert!(answered > 0, "at least one family must have answered");
    }

    #[tokio::test]
    async fn replacing_the_zone_changes_what_the_running_server_answers() {
        let shared = SharedZone::new(Zone::new(ZoneName::new("lab").unwrap(), []));
        let server = DnsServer::bind("127.0.0.1:0".parse().unwrap(), shared.clone())
            .await
            .unwrap();
        let addr = server.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = vec![0u8; MAX_MESSAGE_LEN];

        client
            .send_to(&ask("music.lab", TYPE::A), addr)
            .await
            .unwrap();
        let read = client.recv(&mut buffer).await.unwrap();
        assert_eq!(
            simple_dns::Packet::parse(&buffer[..read]).unwrap().rcode(),
            RCODE::NameError
        );

        // A member joins: no rebind, no dropped socket.
        shared.set(zone());
        client
            .send_to(&ask("music.lab", TYPE::A), addr)
            .await
            .unwrap();
        let read = client.recv(&mut buffer).await.unwrap();
        let reply = simple_dns::Packet::parse(&buffer[..read]).unwrap();
        assert_eq!(reply.rcode(), RCODE::NoError);
        assert_eq!(reply.answers.len(), 1);
    }
}

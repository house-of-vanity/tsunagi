//! Peer-only Shoes Shadowsocks 2022 TCP profile, adapted from cfal/shoes v0.3.8
//! shadowsocks/{blake3_key,shadowsocks_stream,shadowsocks_tcp_handler}.rs (MIT).
mod records;
use iroh::EndpointId;
use rand::Rng;
use records::Records;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tsunagi::BoxFuture;
use tsunagi_shoes::{Profile, Profiles, ShoesWire, Stream, Ticket, driven};

/// Fixed identity of the external carrier.
pub const PROTOCOL: &str = "ss2022";
/// Initial compatible wire format.
pub const WIRE_VERSION: u16 = 1;
/// Preferred physical port.
pub const PORT: u16 = 9444;
/// Both SIP022 AES-GCM methods are available.
pub struct Shadowsocks2022;

// A service selector inside the encrypted request. No OS connection is opened.
const TARGET: [u8; 7] = [1, 127, 0, 0, 1, 0, 1];
const MAX_PADDING: usize = 900;
const TAG: usize = 16;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Shadowsocks record")
}
fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
fn key_len(profile: &Profile) -> usize {
    // Independent of the secret; the private offer tells both endpoints which method to use.
    if profile.variant { 32 } else { 16 }
}
fn fixed(kind: u8, request_salt: &[u8], len: usize) -> io::Result<Vec<u8>> {
    let mut header = vec![kind];
    header.extend_from_slice(&now()?.to_be_bytes());
    header.extend_from_slice(request_salt);
    header.extend_from_slice(&u16::try_from(len).map_err(|_| invalid())?.to_be_bytes());
    Ok(header)
}
fn parse_fixed(header: &[u8], kind: u8, salt: &[u8], time: u64) -> io::Result<usize> {
    if header.len() != 11 + salt.len() || header[0] != kind || &header[9..9 + salt.len()] != salt {
        return Err(invalid());
    }
    let timestamp = u64::from_be_bytes(header[1..9].try_into().map_err(|_| invalid())?);
    if timestamp.abs_diff(time) > 30 {
        return Err(invalid());
    }
    let n = 9 + salt.len();
    Ok(u16::from_be_bytes([header[n], header[n + 1]]) as usize)
}
fn record_stream(tcp: TcpStream, mut seal: Records, mut open: Records, early: Vec<u8>) -> Stream {
    let (stream, bridge) = tokio::io::duplex(64 * 1024);
    driven(stream, async move {
        let (mut net_in, mut net_out) = tcp.into_split();
        let (mut app_in, mut app_out) = tokio::io::split(bridge);
        let upload = async {
            let mut buf = vec![0; 16 * 1024];
            loop {
                let n = app_in.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, io::Error>(());
                }
                let mut frame = seal.seal(&(n as u16).to_be_bytes())?;
                frame.extend(seal.seal(&buf[..n])?);
                net_out.write_all(&frame).await?;
            }
        };
        let download = async {
            app_out.write_all(&early).await?;
            loop {
                let len = open.read(&mut net_in, 2).await?;
                let n = u16::from_be_bytes([len[0], len[1]]) as usize;
                if n == 0 {
                    return Err::<(), _>(invalid());
                }
                app_out.write_all(&open.read(&mut net_in, n).await?).await?;
            }
        };
        tokio::select! { _ = upload => {}, _ = download => {} }
    })
}

impl ShoesWire for Shadowsocks2022 {
    fn name(&self) -> &'static str {
        PROTOCOL
    }
    fn version(&self) -> u16 {
        WIRE_VERSION
    }
    fn connect<'a>(
        &'a self,
        mut tcp: TcpStream,
        _: EndpointId,
        p: &'a Profile,
    ) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let n = key_len(p);
            let salt = &p.tag[..n];
            let mut seal = Records::new(&p.secret[..n], salt)?;
            let pad: u16 = rand::random_range(1..=MAX_PADDING as u16);
            let mut body = TARGET.to_vec();
            body.extend_from_slice(&pad.to_be_bytes());
            body.resize(body.len() + usize::from(pad), 0);
            rand::rng().fill_bytes(&mut body[9..]);
            let mut first = salt.to_vec();
            first.extend(seal.seal(&fixed(0, &[], body.len())?)?);
            first.extend(seal.seal(&body)?);
            tcp.write_all(&first).await?;
            let mut response = vec![0; n + 11 + n + TAG];
            if tcp.read(&mut response).await? != response.len() {
                return Err(invalid());
            }
            let mut open = Records::new(&p.secret[..n], &response[..n])?;
            let header = open.open(response[n..].to_vec())?;
            let size = parse_fixed(&header, 1, salt, now()?)?;
            if size == 0 {
                return Err(invalid());
            }
            let initial = open.read(&mut tcp, size).await?;
            let early = initial.strip_prefix(&[0]).ok_or_else(invalid)?;
            Ok(record_stream(tcp, seal, open, early.to_vec()))
        })
    }
    fn accept<'a>(
        &'a self,
        mut tcp: TcpStream,
        profiles: &'a Profiles,
    ) -> BoxFuture<'a, io::Result<(Ticket, Stream)>> {
        Box::pin(async move {
            // Use a consistent reset on rejected or truncated first records (SIP022 §3.1.4).
            tcp.set_zero_linger()?;
            // SIP022 reads the salt and complete fixed header in one socket read.
            let mut prefix = [0u8; 32 + 11 + TAG];
            let used = tcp.read(&mut prefix).await?;
            if used < 16 + 11 + TAG {
                return Err(invalid());
            }
            let ticket = profiles.lookup(&prefix[..16])?;
            let p = &ticket.profile;
            let n = key_len(p);
            let end = n + 11 + TAG;
            if used < end || prefix[..n] != p.tag[..n] {
                return Err(invalid());
            }
            let salt = &prefix[..n];
            let key = &p.secret[..n];
            let mut open = Records::new(key, salt)?;
            let header = open.open(prefix[n..end].to_vec())?;
            let size = parse_fixed(&header, 0, &[], now()?)?;
            if size < 9 {
                return Err(invalid());
            }
            let mut body = vec![0; size + TAG];
            let buffered = used - end;
            body[..buffered].copy_from_slice(&prefix[end..used]);
            tcp.read_exact(&mut body[buffered..]).await?;
            let body = open.open(body)?;
            let early = parse_target(&body)?;
            profiles.claim(&ticket)?;
            // Tokio deprecates positive linger times because they block on close.
            // Clearing the rejection-only reset restores the normal nonblocking close.
            #[allow(deprecated)]
            tcp.set_linger(None)?;
            let response_salt: [u8; 32] = rand::random();
            let mut seal = Records::new(key, &response_salt[..n])?;
            let mut response = response_salt[..n].to_vec();
            response.extend(seal.seal(&fixed(1, salt, 1)?)?);
            response.extend(seal.seal(&[0])?);
            tcp.write_all(&response).await?;
            Ok((ticket, record_stream(tcp, seal, open, early.to_vec())))
        })
    }
}
fn parse_target(body: &[u8]) -> io::Result<&[u8]> {
    if body.len() < 9 || body[..7] != TARGET {
        return Err(invalid());
    }
    let pad = u16::from_be_bytes([body[7], body[8]]) as usize;
    if pad > MAX_PADDING || body.len() == 9 {
        return Err(invalid());
    }
    body.get(9 + pad..).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn reject_clock_skew_reflection_wrong_salt_and_wrong_service() {
        let header = fixed(1, &[8; 16], 512).unwrap();
        let time = now().unwrap();
        assert_eq!(parse_fixed(&header, 1, &[8; 16], time).unwrap(), 512);
        assert!(parse_fixed(&header, 0, &[8; 16], time).is_err());
        assert!(parse_fixed(&header, 1, &[7; 16], time).is_err());
        assert!(parse_fixed(&header, 1, &[8; 16], time + 31).is_err());
        let mut body = TARGET.to_vec();
        body.extend([0, 0]);
        assert!(parse_target(&body).is_err());
        body.extend([9]);
        assert_eq!(parse_target(&body).unwrap(), &[9]);
        body[8] = 2;
        assert!(parse_target(&body).is_err());
        body[8] = 1;
        body[4] = 2;
        assert!(parse_target(&body).is_err());
    }
}

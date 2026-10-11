//! Optional, bounded server-reflexive discovery on the pair's own UDP socket.
//! A STUN answer is a candidate only; WireGuard authentication verifies a path.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub(crate) async fn mapped(socket: &UdpSocket, server: &str) -> Option<SocketAddr> {
    tokio::time::timeout(Duration::from_millis(1200), async {
        let address = tokio::net::lookup_host(server)
            .await
            .ok()?
            .find(SocketAddr::is_ipv4)?;
        let transaction: [u8; 12] = rand::random();
        let mut request = [0; 20];
        request[..2].copy_from_slice(&[0, 1]);
        request[4..8].copy_from_slice(&COOKIE);
        request[8..].copy_from_slice(&transaction);
        socket.send_to(&request, address).await.ok()?;
        let mut bytes = [0; 1024];
        loop {
            let (len, source) = socket.recv_from(&mut bytes).await.ok()?;
            if source == address
                && let Some(mapped) = parse(&bytes[..len], &transaction)
            {
                return Some(mapped);
            }
        }
    })
    .await
    .ok()
    .flatten()
}
fn parse(bytes: &[u8], transaction: &[u8; 12]) -> Option<SocketAddr> {
    if bytes.len() < 20
        || bytes[..2] != [1, 1]
        || bytes[4..8] != COOKIE
        || &bytes[8..20] != transaction
    {
        return None;
    }
    let declared = u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize;
    if !declared.is_multiple_of(4) || declared != bytes.len() - 20 {
        return None;
    }
    let mut at = 20;
    while at + 4 <= bytes.len() {
        let kind = u16::from_be_bytes(bytes[at..at + 2].try_into().ok()?);
        let len = u16::from_be_bytes(bytes[at + 2..at + 4].try_into().ok()?) as usize;
        at += 4;
        let attribute = bytes.get(at..at.checked_add(len)?)?;
        if kind == 0x0020 && attribute.len() == 8 && attribute[0..2] == [0, 1] {
            let port = u16::from_be_bytes([attribute[2] ^ COOKIE[0], attribute[3] ^ COOKIE[1]]);
            let ip = Ipv4Addr::new(
                attribute[4] ^ COOKIE[0],
                attribute[5] ^ COOKIE[1],
                attribute[6] ^ COOKIE[2],
                attribute[7] ^ COOKIE[3],
            );
            if port == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return None;
            }
            return Some(SocketAddr::new(IpAddr::V4(ip), port));
        }
        at = at.checked_add((len + 3) & !3)?;
    }
    None
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[tokio::test]
    async fn mapping_uses_the_actual_socket_and_rejects_unrelated_or_truncated_answers() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = server.local_addr().unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let expected = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0; 128];
            let (len, source) = server.recv_from(&mut request).await.unwrap();
            assert_eq!(len, 20);
            assert_eq!(source, expected);
            let tx: [u8; 12] = request[8..20].try_into().unwrap();
            let mut reply = request[..20].to_vec();
            reply[..4].copy_from_slice(&[1, 1, 0, 12]);
            reply.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
            let port = source.port().to_be_bytes();
            reply.extend_from_slice(&[port[0] ^ COOKIE[0], port[1] ^ COOKIE[1]]);
            for (i, b) in Ipv4Addr::LOCALHOST.octets().into_iter().enumerate() {
                reply.push(b ^ COOKIE[i]);
            }
            assert!(parse(&reply, &[0; 12]).is_none());
            for len in 0..reply.len() {
                assert!(parse(&reply[..len], &tx).is_none());
            }
            server.send_to(&reply, source).await.unwrap();
        });
        assert_eq!(mapped(&socket, &address.to_string()).await, Some(expected));
        task.await.unwrap();
    }
}

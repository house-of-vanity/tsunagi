//! Shoes' XHTTP stream-one and VLESS TCP profile over HTTP/2 and pinned TLS 1.3.
//! Wire formats adapted from cfal/shoes v0.3.8 (MIT), xhttp/wire.rs and vless/.
mod h2_stream;
use bytes::Bytes;
use h2_stream::H2MultiStream;
use iroh::EndpointId;
use rustls::pki_types::ServerName;
use std::{io, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tsunagi::{BoxFuture, identity::DeviceIdentity};
use tsunagi_shoes::{Profile, Profiles, ShoesWire, Stream, Ticket, driven};
use tsunagi_tcp_tls::cert::{generate_self_signed_cert, make_client_config, make_server_config};
use zeroize::Zeroizing;

/// Catalog identifier, independent of Tsunagi's software version.
pub const PROTOCOL: &str = "vless-xhttp";
/// Initial compatible wire format.
pub const WIRE_VERSION: u16 = 1;
/// Preferred physical port.
pub const PORT: u16 = 9443;

const TARGET: [u8; 9] = [0, 1, 0, 1, 1, 127, 0, 0, 1]; // no addons, TCP, port 1, IPv4
const HEADER_LIMIT: u32 = 8192;

/// One HTTP/2 endpoint identified by its persistent mesh public key.
pub struct VlessXhttp {
    tls: tokio_rustls::TlsAcceptor,
}
impl VlessXhttp {
    /// Construct a server without DNS, public certificates or web ingress.
    pub fn new(
        identity: &DeviceIdentity,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (cert, key) = generate_self_signed_cert(&identity.secret_bytes(), "localhost")?;
        let mut tls = make_server_config(cert, key)?;
        Arc::make_mut(&mut tls).alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self { tls: tls.into() })
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid VLESS/XHTTP handshake")
}
fn header(p: &Profile) -> Zeroizing<[u8; 26]> {
    let mut bytes = Zeroizing::new([0; 26]);
    bytes[1..17].copy_from_slice(&p.secret[..16]);
    // RFC 9562 UUIDv4 version and variant.
    bytes[7] = (bytes[7] & 0x0f) | 0x40;
    bytes[9] = (bytes[9] & 0x3f) | 0x80;
    bytes[17..].copy_from_slice(&TARGET);
    bytes
}
fn request(p: &Profile, authority: std::net::SocketAddr) -> io::Result<http::Request<()>> {
    let path = format!("/{}/", hex::encode(p.tag));
    let uri = format!("https://{authority}{path}");
    let padding = "X".repeat(rand::random_range(100..=1000));
    http::Request::post(&uri)
        .header("referer", format!("{uri}?x_padding={padding}"))
        .header("content-type", "application/grpc")
        .body(())
        .map_err(io::Error::other)
}
fn request_tag<T>(req: &http::Request<T>) -> io::Result<[u8; 32]> {
    if req.method() != http::Method::POST || req.uri().scheme_str() != Some("https") {
        return Err(invalid());
    }
    let path = req
        .uri()
        .path()
        .strip_prefix('/')
        .and_then(|p| p.strip_suffix('/'))
        .ok_or_else(invalid)?;
    let referer: http::Uri = req
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid)?;
    let padding = referer
        .query()
        .and_then(|q| q.strip_prefix("x_padding="))
        .ok_or_else(invalid)?;
    if !(100..=1000).contains(&padding.len()) || path.len() != 64 {
        return Err(invalid());
    }
    let mut tag = [0; 32];
    hex::decode_to_slice(path, &mut tag).map_err(|_| invalid())?;
    Ok(tag)
}

impl ShoesWire for VlessXhttp {
    fn name(&self) -> &'static str {
        PROTOCOL
    }
    fn version(&self) -> u16 {
        WIRE_VERSION
    }
    fn connect<'a>(
        &'a self,
        tcp: TcpStream,
        peer: EndpointId,
        profile: &'a Profile,
    ) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut config = make_client_config(peer).map_err(io::Error::other)?;
            Arc::make_mut(&mut config).alpn_protocols = vec![b"h2".to_vec()];
            let address = tcp.peer_addr()?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(ServerName::IpAddress(address.ip().into()), tcp)
                .await?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(invalid());
            }
            let (sender, mut connection) = h2::client::Builder::new()
                .max_header_list_size(HEADER_LIMIT)
                .enable_push(false)
                .handshake::<_, Bytes>(tls)
                .await
                .map_err(io::Error::other)?;
            let open = async {
                let mut sender = sender.ready().await.map_err(io::Error::other)?;
                let (response, mut send) = sender
                    .send_request(request(profile, address)?, false)
                    .map_err(io::Error::other)?;
                send.send_data(Bytes::copy_from_slice(&header(profile)[..]), false)
                    .map_err(io::Error::other)?;
                let response = response.await.map_err(io::Error::other)?;
                if response.status() != http::StatusCode::OK {
                    return Err(invalid());
                }
                Ok(H2MultiStream::new(send, response.into_body()))
            };
            let stream = tokio::select! { _ = &mut connection => return Err(invalid()), result = open => result? };
            let mut stream = driven(stream, async move {
                let _ = connection.await;
            });
            let mut response = [0; 2];
            stream.read_exact(&mut response).await?;
            if response != [0, 0] {
                return Err(invalid());
            }
            Ok(stream)
        })
    }
    fn accept<'a>(
        &'a self,
        tcp: TcpStream,
        profiles: &'a Profiles,
    ) -> BoxFuture<'a, io::Result<(Ticket, Stream)>> {
        Box::pin(async move {
            let tls = self.tls.accept(tcp).await?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(invalid());
            }
            let mut conn = h2::server::Builder::new()
                .max_header_list_size(HEADER_LIMIT)
                .max_concurrent_streams(1)
                .handshake::<_, Bytes>(tls)
                .await
                .map_err(io::Error::other)?;
            let (req, mut respond) = conn
                .accept()
                .await
                .ok_or_else(invalid)?
                .map_err(io::Error::other)?;
            let ticket = profiles.lookup(&request_tag(&req)?)?;
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .header("cache-control", "no-store")
                .body(())
                .map_err(io::Error::other)?;
            let send = respond
                .send_response(response, false)
                .map_err(io::Error::other)?;
            let mut stream = driven(H2MultiStream::new(send, req.into_body()), async move {
                while let Some(Ok((_, mut response))) = conn.accept().await {
                    response.send_reset(h2::Reason::REFUSED_STREAM);
                }
            });
            let mut received = Zeroizing::new([0u8; 26]);
            stream.read_exact(&mut received[..]).await?;
            if !bool::from(received[..].ct_eq(&header(&ticket.profile)[..])) {
                return Err(invalid());
            }
            profiles.claim(&ticket)?;
            stream.write_all(&[0, 0]).await?;
            Ok((ticket, stream))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn stream_one_and_vless_use_the_standard_post_path_uuid_and_tcp_destination() {
        let p = Profile {
            tag: [0xda; 32],
            secret: [0xaa; 32],
            variant: false,
        };
        let req = request(&p, "127.0.0.1:9443".parse().unwrap()).unwrap();
        assert_eq!(req.headers()["content-type"], "application/grpc");
        assert_eq!(request_tag(&req).unwrap(), p.tag);
        assert_eq!(
            hex::encode(&header(&p)[..]),
            "00aaaaaaaaaaaa4aaaaaaaaaaaaaaaaaaa00010001017f000001"
        );
    }
    #[test]
    fn bad_methods_and_paths_are_rejected_before_allocating_a_stream() {
        let p = Profile {
            tag: [7; 32],
            secret: [4; 32],
            variant: true,
        };
        let mut req = request(&p, "127.0.0.1:9443".parse().unwrap()).unwrap();
        *req.method_mut() = http::Method::GET;
        assert!(request_tag(&req).is_err());
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_static("https://peer.invalid/missing/");
        assert!(request_tag(&req).is_err());
    }
}

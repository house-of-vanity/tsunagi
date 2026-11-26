//! Optional interoperability against an independently built upstream Shoes server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{
    fs,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tsunagi::identity::DeviceIdentity;
use tsunagi_shoes::{Profile, ShoesWire};
use tsunagi_tcp_tls::cert::generate_self_signed_cert;

struct Reference(Child);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        data_encoding::BASE64.encode(bytes)
    )
}
#[tokio::test]
#[ignore = "set TSUNAGI_SHOES_BIN to the upstream Shoes executable (v0.3.8)"]
async fn upstream_server_accepts_stream_one_and_both_ss2022_methods() {
    let bin = std::env::var_os("TSUNAGI_SHOES_BIN").expect("upstream Shoes path");
    let dir = tempfile::tempdir().unwrap();
    let endpoint = DeviceIdentity::generate();
    let (cert, key) = generate_self_signed_cert(&endpoint.secret_bytes(), "localhost").unwrap();
    fs::write(
        dir.path().join("cert.pem"),
        pem("CERTIFICATE", cert.as_ref()),
    )
    .unwrap();
    fs::write(
        dir.path().join("key.pem"),
        pem("PRIVATE KEY", key.secret_der()),
    )
    .unwrap();
    for (is_vless, use_256) in [(true, false), (false, false), (false, true)] {
        let profile = Profile {
            tag: [0x34; 32],
            secret: [0x53; 32],
            variant: use_256,
        };
        let (wire, protocol): (Box<dyn ShoesWire>, String) = if is_vless {
            let path = hex::encode(profile.tag);
            (
                Box::new(tsunagi_vless_xhttp::VlessXhttp::new(&endpoint).unwrap()),
                format!(
                    "type: tls\n    default_target:\n      cert: cert.pem\n      key: key.pem\n      alpn_protocols: [h2]\n      protocol:\n        type: xhttp\n        path: /{path}/\n        mode: stream-one\n        protocol:\n          type: vless\n          user_id: 53535353-5353-4353-9353-535353535353"
                ),
            )
        } else {
            let size = if use_256 { 32 } else { 16 };
            let key = data_encoding::BASE64.encode(&profile.secret[..size]);
            (
                Box::new(tsunagi_ss2022::Shadowsocks2022),
                format!(
                    "type: shadowsocks\n    cipher: 2022-blake3-aes-{}-gcm\n    password: '{key}'",
                    size * 8
                ),
            )
        };
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend.local_addr().unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        fs::write(dir.path().join("reference.yaml"), format!("- address: {address}\n  protocol:\n    {protocol}\n  rules:\n    - mask: 127.0.0.1:1\n      action: allow\n      override_address: {backend_address}\n      client_chain: direct\n")).unwrap();
        drop(reservation);
        let mut server = Reference(
            Command::new(&bin)
                .current_dir(dir.path())
                .args(["-t", "1", "--no-reload", "reference.yaml"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(15), async {
            let tcp = loop {
                assert!(
                    server.0.try_wait().unwrap().is_none(),
                    "reference server exited at startup"
                );
                if let Ok(tcp) = TcpStream::connect(address).await {
                    break tcp;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            };
            let payload = vec![0x8c; 96 * 1024];
            let exchange = async {
                let mut stream = wire
                    .connect(tcp, endpoint.endpoint_id(), &profile)
                    .await
                    .unwrap();
                if !is_vless {
                    let mut first = [0; 4];
                    stream.read_exact(&mut first).await.unwrap();
                    assert_eq!(&first, b"mesh");
                }
                stream.write_all(&payload).await.unwrap();
                let mut returned = vec![0; payload.len()];
                stream.read_exact(&mut returned).await.unwrap();
                assert_eq!(payload, returned);
            };
            let service = async {
                let (mut socket, _) = backend.accept().await.unwrap();
                if !is_vless {
                    socket.write_all(b"\0mesh").await.unwrap();
                }
                let mut bytes = vec![0; payload.len()];
                socket.read_exact(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
            };
            tokio::join!(service, exchange);
        })
        .await
        .expect("reference wire exchange timed out");
    }
}

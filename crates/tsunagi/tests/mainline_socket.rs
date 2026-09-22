//! The real Mainline UDP receive loop must be quiet while idle on Windows too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tracing_subscriber::layer::SubscriberExt;

struct SocketWarnings(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SocketWarnings {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "mainline::rpc::socket"
            && *event.metadata().level() <= tracing::Level::WARN
        {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[tokio::test]
async fn an_idle_dht_socket_stays_quiet_and_still_answers_packets() {
    // Mainline owns an OS thread, so a thread-local subscriber cannot see its
    // events. This integration-test binary has just this test and installs
    // its own subscriber; it cannot affect the application or other binaries.
    let warnings = Arc::new(AtomicUsize::new(0));
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(SocketWarnings(Arc::clone(&warnings))),
    )
    .unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        let dht = mainline::Dht::builder()
            .no_bootstrap()
            .server_mode()
            .bind_address(Ipv4Addr::LOCALHOST)
            .port(0)
            .build()
            .unwrap()
            .as_async();

        let address = dht.info().await.local_addr();
        // Each info response comes from the actor after another receive-loop
        // iteration. With no peers or packets, these exercise real socket
        // read timeouts, without an arbitrary sleep or public bootstrap.
        for _ in 0..8 {
            assert_eq!(dht.info().await.local_addr(), address);
        }
        assert_eq!(warnings.load(Ordering::Relaxed), 0, "idle receive warnings");

        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let ping = b"d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t4:ping1:y1:qe";
        client.send_to(ping, address).await.unwrap();
        let mut response = [0u8; 2048];
        let (len, from) = client.recv_from(&mut response).await.unwrap();
        assert_eq!(from, std::net::SocketAddr::V4(address));
        let response = &response[..len];
        assert!(response.windows(9).any(|field| field == b"1:t4:ping"));
        assert!(response.windows(6).any(|field| field == b"1:y1:r"));
        assert_eq!(warnings.load(Ordering::Relaxed), 0);
    })
    .await
    .expect("the DHT receive loop keeps making progress");
}

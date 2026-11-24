//! Peer for the Android instrumentation test. Only the test APK packages it.
#![cfg(target_os = "android")]

use jni::{JNIEnv, objects::JObject};
use std::{
    fs::File,
    io,
    net::Ipv4Addr,
    os::fd::{FromRawFd, OwnedFd},
    process::Command,
    time::Duration,
};
use tsunagi::overlay::{Cidr, TunDevice, TunFactory, TunRequest};
use tsunagi_android::{dns::Resolver, tun::AndroidTun};

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_VpnSourceTest_checkSockets(
    mut env: JNIEnv,
    _: JObject,
    fd: i32,
    count: i32,
) {
    // SAFETY: the instrumentation test transfers a duplicate with detachFd().
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|rt| rt.block_on(check(file, count)));
    if let Err(error) = result {
        let _ = env.throw_new("java/lang/AssertionError", error.to_string());
    }
}

async fn check(file: File, count: i32) -> io::Result<()> {
    let factory = AndroidTun::new(
        Resolver::new(|_| None),
        move |_| file.try_clone(),
        |_, _| Ok(()),
    );
    let locals = [
        Ipv4Addr::new(198, 18, 234, 1),
        Ipv4Addr::new(198, 19, 234, 1),
    ];
    let mut req = TunRequest::bare("vpn", 1280);
    for &local in locals.iter().take(count as usize) {
        req.addresses
            .push(Cidr::new(local.into(), 24).map_err(io::Error::other)?);
    }
    let tun = factory.create(req).await.map_err(io::Error::other)?;
    for &local in locals.iter().take(count as usize) {
        let mut octets = local.octets();
        octets[3] = 2;
        let remote = Ipv4Addr::from(octets);
        let exchange = async {
            udp(tun.as_ref(), local, remote).await?;
            ping(tun.as_ref(), local, remote).await
        };
        tokio::time::timeout(Duration::from_secs(8), exchange)
            .await
            .map_err(|_| io::Error::other(format!("echo timed out on network {local}")))??;
    }
    Ok(())
}

async fn echo(
    tun: &dyn TunDevice,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    protocol: u8,
) -> io::Result<()> {
    use smoltcp::wire::{Icmpv4Message, Icmpv4Packet};
    loop {
        let mut pkt = tun
            .recv()
            .await
            .ok_or_else(|| io::Error::other("VPN closed"))?
            .to_vec();
        if pkt.len() < 28 || pkt[0] != 0x45 || pkt[9] != protocol || pkt[16..20] != remote.octets()
        {
            continue;
        }
        if protocol == 17 {
            if pkt[22..24] != 45678u16.to_be_bytes() || &pkt[28..] != b"mesh probe" {
                continue;
            }
            // Swapping ports preserves the UDP checksum.
            pkt[20..24].rotate_left(2);
        } else {
            let mut icmp = Icmpv4Packet::new_checked(&mut pkt[20..]).map_err(io::Error::other)?;
            if icmp.msg_type() != Icmpv4Message::EchoRequest {
                continue;
            }
            icmp.set_msg_type(Icmpv4Message::EchoReply);
            icmp.fill_checksum();
        }
        if pkt[12..16] != local.octets() {
            return Err(io::Error::other(format!(
                "peer {remote} saw source {:?}, expected {local}",
                &pkt[12..16]
            )));
        }
        // Swapping addresses preserves the IPv4 checksum and the pseudo-header sum.
        pkt[12..20].rotate_left(4);
        return tun.send(pkt.into()).await.map_err(io::Error::other);
    }
}

async fn udp(tun: &dyn TunDevice, local: Ipv4Addr, remote: Ipv4Addr) -> io::Result<()> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect((remote, 45678)).await?;
    socket.send(b"mesh probe").await?;
    echo(tun, local, remote, 17).await?;
    let mut reply = [0; 64];
    let n = socket.recv(&mut reply).await?;
    if &reply[..n] != b"mesh probe" {
        return Err(io::Error::other("UDP echo payload changed"));
    }
    Ok(())
}

async fn ping(tun: &dyn TunDevice, local: Ipv4Addr, remote: Ipv4Addr) -> io::Result<()> {
    let command = async {
        let output = tokio::task::spawn_blocking(move || {
            Command::new("/system/bin/ping")
                .args(["-n", "-c", "1", "-w", "4"])
                .arg(remote.to_string())
                .output()
        })
        .await??;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ping {remote} failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    };
    tokio::try_join!(command, echo(tun, local, remote, 1))?;
    Ok(())
}

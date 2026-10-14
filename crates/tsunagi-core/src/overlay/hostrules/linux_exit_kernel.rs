//! Privileged routing regression, isolated from the host in named namespaces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::Duration;

use super::linux::run_firewall;
use super::linux_exit_mark::{clear, install, local_sockets, refresh};
use crate::overlay::NetlinkProvisioner;

const TEST: &str = "overlay::hostrules::linux_exit_kernel::strict_firewall_preserves_underlay_and_application_exit_routing";
const ROLE: &str = "TSUNAGI_EXIT_KERNEL_TEST_ROLE";

fn ip(arguments: &[&str]) -> String {
    let result = Command::new("ip").args(arguments).output().unwrap();
    assert!(
        result.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).into_owned()
}

struct Namespace(String);
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}
struct Echo(Child);
impl Drop for Echo {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn probes() {
    let should_pass = std::env::var("TSUNAGI_EXIT_KERNEL_EXPECT").unwrap() == "pass";
    for address in ["198.51.100.2:42000", "[2001:db8:2::2]:42000"] {
        let address: SocketAddr = address.parse().unwrap();
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket.send_to(b"rpf", address).unwrap();
        let mut packet = [0u8; 3];
        assert_eq!(
            socket.recv(&mut packet).is_ok(),
            should_pass,
            "UDP {address}"
        );
        if should_pass {
            assert_eq!(&packet, b"rpf");
        }
        let connected = TcpStream::connect_timeout(&address, Duration::from_secs(1));
        assert_eq!(connected.is_ok(), should_pass, "TCP {address}");
        if let Ok(mut stream) = connected {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream.write_all(b"rpf").unwrap();
            stream.read_exact(&mut packet).unwrap();
            assert_eq!(&packet, b"rpf");
        }
    }
}

fn run_probes(expect: &str) {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", TEST, "--nocapture"])
        .env(ROLE, "probe")
        .env("TSUNAGI_EXIT_KERNEL_EXPECT", expect)
        .uid(990)
        .gid(990)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn passive_listener() {
    let listeners: Vec<_> = ["192.0.2.1:42010", "[2001:db8:1::1]:42010"]
        .into_iter()
        .map(|address| TcpListener::bind(address).unwrap())
        .collect();
    println!("PASSIVE_READY");
    let tasks: Vec<_> = listeners
        .into_iter()
        .map(|listener| {
            std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = [0; 3];
                socket.read_exact(&mut bytes).unwrap();
                socket.write_all(&bytes).unwrap();
            })
        })
        .collect();
    for task in tasks {
        task.join().unwrap();
    }
}

fn udp_listener() {
    let sockets: Vec<_> = ["192.0.2.1:42011", "[2001:db8:1::1]:42011"]
        .into_iter()
        .map(|a| UdpSocket::bind(a).unwrap())
        .collect();
    println!("PASSIVE_READY");
    let tasks: Vec<_> = sockets
        .into_iter()
        .map(|socket| {
            std::thread::spawn(move || {
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = [0; 3];
                let (len, peer) = socket.recv_from(&mut bytes).unwrap();
                socket.send_to(&bytes[..len], peer).unwrap();
            })
        })
        .collect();
    for task in tasks {
        task.join().unwrap();
    }
}

fn spawn_listener(role: &str) -> Echo {
    let process = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", TEST, "--nocapture"])
        .env(ROLE, role)
        .uid(990)
        .gid(990)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Echo(process);
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "listener exited before readiness"
        );
        if line.contains("PASSIVE_READY") {
            // Keep the reader open for libtest's final status after the socket
            // worker finishes; closing it here makes success a broken pipe.
            child.0.stdout = Some(output.into_inner());
            return child;
        }
    }
}

fn client() {
    for setting in ["rp_filter", "src_valid_mark"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/all/{setting}"), b"1").unwrap();
    }
    std::fs::write("/proc/sys/net/ipv4/conf/rpf-c/rp_filter", b"1").unwrap();
    for family in [false, true] {
        let args: Vec<_> = [
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-m",
            "rpfilter",
            "--invert",
            "--validmark",
            "-j",
            "DROP",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let result = run_firewall(family, &args);
        assert!(
            matches!(result, super::linux::Ran::Exited { success: true, .. }),
            "{result:?}"
        );
    }
    let provisioner = NetlinkProvisioner::new().unwrap();
    let route = provisioner.host_rules().route;
    // Model Tailscale's earlier lookup, without running another VPN daemon.
    ip(&["-4", "rule", "add", "priority", "5270", "table", "52"]);
    ip(&[
        "-4", "route", "add", "default", "dev", "tsun0", "table", "52",
    ]);
    ip(&["-6", "rule", "add", "priority", "5270", "table", "52"]);
    ip(&[
        "-6",
        "route",
        "add",
        "unreachable",
        "default",
        "table",
        "52",
    ]);
    // A foreign VPN must leave neighbour discovery and connected LAN paths
    // usable; otherwise the fixture itself cannot resolve its uplink neighbour.
    for prefix in ["fe80::/64", "2001:db8:1::/64"] {
        ip(&["-6", "route", "add", "throw", prefix, "table", "52"]);
    }
    let mut passive = spawn_listener("listener");
    route.set_exit_client("tsun0", 990).unwrap();
    // uid bypass alone cannot protect reverse lookups, reproducing the bug.
    run_probes("blocked");
    install(&run_firewall, "tsun0", 990, true).unwrap();
    run_probes("pass");
    // Pair transports may bind fresh UDP ports after exit activation.
    let mut dynamic_udp = spawn_listener("udp-listener");
    refresh(
        &run_firewall,
        "tsun0",
        true,
        &local_sockets(990, true).unwrap(),
    )
    .unwrap();
    let server = std::env::var("TSUNAGI_EXIT_KERNEL_SERVER").unwrap();
    let incoming = Command::new("ip").args(["netns", "exec", &server, "python3", "-c", r#"import socket
for family,source,target in [(socket.AF_INET,'198.51.100.2','192.0.2.1'),(socket.AF_INET6,'2001:db8:2::2','2001:db8:1::1')]:
    for kind,port in [(socket.SOCK_STREAM,42010),(socket.SOCK_DGRAM,42011)]:
        s=socket.socket(family,kind); s.settimeout(2); s.bind((source,0)); s.connect((target,port)); s.sendall(b'rpf'); assert s.recv(3)==b'rpf'; s.close()
"#]).output().unwrap();
    assert!(
        incoming.status.success(),
        "first inbound TCP/UDP must be protected: {}",
        String::from_utf8_lossy(&incoming.stderr)
    );
    assert!(passive.0.wait().unwrap().success());
    assert!(dynamic_udp.0.wait().unwrap().success());
    // Repeated apply remains usable, and does not redirect application sockets.
    install(&run_firewall, "tsun0", 990, true).unwrap();
    run_probes("pass");
    assert!(ip(&["-4", "route", "get", "198.51.100.2", "uid", "991"]).contains("dev tsun0"));
    let blocked = Command::new("ip")
        .args(["-6", "route", "get", "2001:db8:2::2", "uid", "991"])
        .output()
        .unwrap();
    assert!(
        !blocked.status.success(),
        "application IPv6 must stay blocked"
    );
    route.clear_exit_client().unwrap();
    clear(&run_firewall, "tsun0", true).unwrap();
    for family in ["-4", "-6"] {
        assert!(
            ip(&[family, "rule", "show"]).contains("5270:"),
            "foreign routing rules survive cleanup"
        );
        ip(&[family, "rule", "del", "priority", "5270"]);
    }
    assert!(ip(&["-4", "route", "get", "198.51.100.2", "uid", "991"]).contains("dev rpf-c"));
    assert!(ip(&["-6", "route", "get", "2001:db8:2::2", "uid", "991"]).contains("dev rpf-c"));
    for family in [false, true] {
        let result = run_firewall(family, &["-t".into(), "mangle".into(), "-S".into()]);
        if let super::linux::Ran::Exited { stdout, .. } = result {
            assert!(!stdout.contains("tsunagi-exit-underlay:"));
            assert!(!stdout.contains("tsunagi-exit-sockets:"));
            assert!(
                stdout.contains("rpfilter"),
                "strict host filtering is retained"
            );
        }
    }
}

#[test]
#[ignore = "needs root, iproute2, iptables/ip6tables and Python; changes only temporary namespaces"]
fn strict_firewall_preserves_underlay_and_application_exit_routing() {
    match std::env::var(ROLE).as_deref() {
        Ok("probe") => {
            probes();
            return;
        }
        Ok("client") => {
            client();
            return;
        }
        Ok("listener") => {
            passive_listener();
            return;
        }
        Ok("udp-listener") => {
            udp_listener();
            return;
        }
        _ => {}
    }
    let suffix = std::process::id();
    let client_name = format!("tsng-rpf-c-{suffix}");
    let server_name = format!("tsng-rpf-s-{suffix}");
    ip(&["netns", "add", &client_name]);
    let _client = Namespace(client_name.clone());
    ip(&["netns", "add", &server_name]);
    let _server = Namespace(server_name.clone());
    ip(&[
        "link",
        "add",
        "rpf-c",
        "netns",
        &client_name,
        "type",
        "veth",
        "peer",
        "name",
        "rpf-s",
        "netns",
        &server_name,
    ]);
    for (namespace, interface, v4, v6) in [
        (&client_name, "rpf-c", "192.0.2.1/24", "2001:db8:1::1/64"),
        (&server_name, "rpf-s", "192.0.2.2/24", "2001:db8:1::2/64"),
    ] {
        ip(&["-n", namespace, "link", "set", "lo", "up"]);
        ip(&["-n", namespace, "addr", "add", v4, "dev", interface]);
        ip(&[
            "-n", namespace, "-6", "addr", "add", v6, "dev", interface, "nodad",
        ]);
        ip(&["-n", namespace, "link", "set", interface, "up"]);
    }
    ip(&[
        "-n",
        &server_name,
        "addr",
        "add",
        "198.51.100.2/32",
        "dev",
        "lo",
    ]);
    ip(&[
        "-n",
        &server_name,
        "-6",
        "addr",
        "add",
        "2001:db8:2::2/128",
        "dev",
        "lo",
        "nodad",
    ]);
    ip(&[
        "-n",
        &client_name,
        "route",
        "add",
        "default",
        "via",
        "192.0.2.2",
    ]);
    ip(&[
        "-n",
        &client_name,
        "-6",
        "route",
        "add",
        "default",
        "via",
        "2001:db8:1::2",
    ]);
    ip(&["-n", &client_name, "link", "add", "tsun0", "type", "dummy"]);
    ip(&[
        "-n",
        &client_name,
        "addr",
        "add",
        "10.13.37.1/24",
        "dev",
        "tsun0",
    ]);
    ip(&["-n", &client_name, "link", "set", "tsun0", "up"]);
    let echo_code = r#"import socket,selectors,sys
selector=selectors.DefaultSelector()
for family in [socket.AF_INET,socket.AF_INET6]:
    for kind in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
        sock=socket.socket(family,kind)
        if family==socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        sock.bind(('198.51.100.2' if family==socket.AF_INET else '2001:db8:2::2',42000))
        if kind==socket.SOCK_STREAM: sock.listen()
        selector.register(sock,selectors.EVENT_READ,kind)
print('ready',flush=True)
while True:
    for key,_ in selector.select():
        if key.data==socket.SOCK_DGRAM:
            data,address=key.fileobj.recvfrom(128); key.fileobj.sendto(data,address)
        else:
            conn,_=key.fileobj.accept(); conn.settimeout(2)
            try: conn.sendall(conn.recv(128))
            finally: conn.close()
"#;
    let child = Command::new("ip")
        .args([
            "netns",
            "exec",
            &server_name,
            "python3",
            "-u",
            "-c",
            echo_code,
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut echo = Echo(child);
    let mut ready = String::new();
    BufReader::new(echo.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");
    let result = Command::new("ip")
        .args(["netns", "exec", &client_name])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", TEST, "--nocapture"])
        .env(ROLE, "client")
        .env("TSUNAGI_EXIT_KERNEL_SERVER", &server_name)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
